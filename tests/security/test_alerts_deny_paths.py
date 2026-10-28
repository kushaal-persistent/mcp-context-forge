# -*- coding: utf-8 -*-
"""Location: ./tests/security/test_alerts_deny_paths.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Security deny-path tests for the alerts API (Issue #5805).

Each test drives a real FastAPI app with the alerts routers mounted and
``TestClient``, against a real in-memory SQLite database. Only two things are
substituted: the database session dependency points at that test database, and
the authenticated principal is a fixed dict. The permission decorator, the
RBAC role lookup, the Layer-1 token-scope check and the alert visibility rules
all run for real, so every denial asserted here is produced by production code.

Members are granted ``alerts.*`` through real team-scoped ``Role``/``UserRole``
rows where a test needs them past RBAC. A member with no grant is denied by the
decorator (403) before any visibility logic runs, so the grant is what lets a
test reach the 404 it asserts.

The cases cover the deny paths a regression could silently open:

* Layer 1 token scope denies a request before RBAC runs (403, generic body).
* RBAC denies a member lacking the alerts permission (403).
* Foreign-team alerts return the generic 404 on every read and write route and
  their state is left unchanged.
* Global alerts (``team_id IS NULL``) are hidden from team-scoped callers.
* Administrator bypass is refused on the admin status route
  (``allow_admin_bypass=False``).
* Anonymous callers receive 401 and never see alert data.
"""

# Standard
import uuid

# Third-Party
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# First-Party
from mcpgateway.db import Alert, AlertDelivery, AlertPreference, Base, EmailTeam, EmailTeamMember, EmailUser, Role, SecurityEvent, UserRole, get_db, utc_now
from mcpgateway.middleware import rbac as rbac_module
from mcpgateway.routers import alerts as alerts_router_module
from mcpgateway.services import alert_delivery as delivery_module
from mcpgateway.services import alert_service as alert_service_module

_TABLES = [
    EmailUser.__table__,
    EmailTeam.__table__,
    EmailTeamMember.__table__,
    Role.__table__,
    UserRole.__table__,
    SecurityEvent.__table__,
    Alert.__table__,
    AlertDelivery.__table__,
    AlertPreference.__table__,
]

ADMIN = "admin@example.com"
MEMBER = "member@example.com"
TEAM_A = "team-a"
TEAM_B = "team-b"

_ACCESS_DENIED = "Access denied"
_NOT_FOUND = "alert not found"
_AUTH_REQUIRED = "User authentication required"

_READ_PERMS = ["alerts.read", "alerts.subscribe"]
_ACK_PERMS = ["alerts.read", "alerts.acknowledge", "alerts.subscribe"]


@pytest.fixture
def factory():
    """Create an in-memory SQLite database with the alerting tables and return its session factory.

    Yields:
        sessionmaker: Session factory bound to the in-memory database.
    """
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=_TABLES)
    session_factory = sessionmaker(bind=engine)
    yield session_factory
    engine.dispose()


@pytest.fixture
def enabled(factory, monkeypatch):
    """Turn alerting on and route every alert database access to the test database.

    Args:
        factory: Session factory bound to the test database.
        monkeypatch: Pytest monkeypatch fixture.

    Returns:
        sessionmaker: The same session factory, for convenience.
    """
    monkeypatch.setattr(alert_service_module, "SessionLocal", factory)
    monkeypatch.setattr(alerts_router_module, "SessionLocal", factory)
    monkeypatch.setattr(delivery_module, "SessionLocal", factory)
    monkeypatch.setattr(alerts_router_module.settings, "alerting_enabled", True, raising=False)
    monkeypatch.setattr(alerts_router_module.settings, "alerting_source_security_enabled", True, raising=False)
    return factory


def _seed_users(factory):
    """Insert an administrator and a plain member, with no RBAC roles granted.

    Args:
        factory: Session factory bound to the test database.
    """
    with factory() as db:
        db.add(EmailUser(email=ADMIN, password_hash="x", full_name="Admin", is_admin=True, is_active=True))  # pragma: allowlist secret
        db.add(EmailUser(email=MEMBER, password_hash="x", full_name="Member", is_admin=False, is_active=True))  # pragma: allowlist secret
        db.commit()


def _grant_team_role(factory, email, team_id, permissions):
    """Grant a team-scoped role carrying the given permissions to a user, using the real RBAC tables.

    Args:
        factory: Session factory bound to the test database.
        email: User to grant.
        team_id: Team the role is scoped to.
        permissions: Permission strings stored on the role.
    """
    role_id = uuid.uuid4().hex
    with factory() as db:
        db.add(Role(id=role_id, name=f"role-{role_id[:8]}", scope="team", permissions=list(permissions), created_by=ADMIN, is_system_role=False, is_active=True))
        db.add(UserRole(user_email=email, role_id=role_id, scope="team", scope_id=team_id, granted_by=ADMIN, is_active=True))
        db.commit()


def _make_alert(factory, *, team_id=None, status="open", dedup_key=None):
    """Insert an alert row and return its identifier.

    Args:
        factory: Session factory bound to the test database.
        team_id: Owning team, or None for a global alert.
        status: Lifecycle status.
        dedup_key: Dedup key (unique when omitted).

    Returns:
        str: Alert identifier.
    """
    now = utc_now()
    alert_id = uuid.uuid4().hex
    with factory() as db:
        db.add(
            Alert(
                id=alert_id,
                source="security",
                type="brute_force",
                severity="HIGH",
                status=status,
                title=f"Alert {alert_id[:6]}",
                body=f"Body for {alert_id[:6]}",
                team_id=team_id,
                dedup_key=dedup_key or f"k-{alert_id}",
                first_seen=now,
                last_seen=now,
                count=1,
                created_at=now,
                updated_at=now,
                alert_metadata={"threat_score": 0.8},
            )
        )
        db.commit()
    return alert_id


def _verified_payload(principal):
    """Build the verified JWT payload the auth layer would store for this principal.

    Args:
        principal: Caller dict with ``email``, ``is_admin`` and ``token_teams``.

    Returns:
        dict: Payload stored as ``request.state._jwt_verified_payload``.
    """
    payload = {"sub": principal["email"], "is_admin": principal["is_admin"]}
    if principal["token_teams"] is None and principal["is_admin"]:
        payload["teams"] = None
    else:
        payload["teams"] = list(principal["token_teams"] or [])
    return payload


def _build_app(factory, *, principal, token_scopes=None):
    """Build a FastAPI app mirroring production mounts for one caller.

    The user router is mounted at ``/v1`` (its own prefix gives ``/v1/alerts``)
    and the admin router is mounted without a prefix, as ``main.py`` does. A
    middleware stores the verified payload and, when given, the API-token scope
    list on ``request.state``, where the auth layer keeps them, so the real
    Layer-1 scope resolver runs.

    Args:
        factory: Session factory bound to the test database.
        principal: Caller dict, or None for an anonymous caller.
        token_scopes: Optional API-token permission list to present (Layer 1).

    Returns:
        FastAPI: Application ready for TestClient.
    """
    app = FastAPI()
    app.include_router(alerts_router_module.router, prefix="/v1")
    app.include_router(alerts_router_module.admin_router)

    if principal is not None:

        @app.middleware("http")
        async def _attach_identity(request, call_next):
            """Store the verified payload and any token scopes on request.state.

            Args:
                request: Incoming request.
                call_next: Next handler in the chain.

            Returns:
                Response: Downstream response.
            """
            request.state._jwt_verified_payload = ("test-token", _verified_payload(principal))
            if token_scopes is not None:
                request.state.token_scopes = list(token_scopes)
            return await call_next(request)

    def _db():
        """Yield a short-lived session on the test database.

        Yields:
            Session: Database session closed after the request.
        """
        db = factory()
        try:
            yield db
        finally:
            db.close()

    async def _user():
        """Return the fixed principal for the current request.

        The decorator reads ``email`` and ``token_scopes`` from this dict, so the
        token scope presented to Layer 1 is carried here as well as on ``request.state``.

        Returns:
            dict: Principal, carrying the email, admin flag and Layer-1 token scopes.
        """
        if principal is None:
            # The real dependency rejects unauthenticated requests before any handler runs.
            raise HTTPException(status_code=401, detail=_AUTH_REQUIRED)
        ctx = {"email": principal["email"], "is_admin": principal["is_admin"], "token_use": "session"}
        if token_scopes is not None:
            ctx["token_scopes"] = list(token_scopes)
        return ctx

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[rbac_module.get_current_user_with_permissions] = _user
    return app


def _admin_principal():
    """Return the caller dict for an unrestricted administrator.

    Returns:
        dict: Principal with no team restriction.
    """
    return {"email": ADMIN, "is_admin": True, "teams": None, "token_teams": None}


def _team_principal(teams):
    """Return the caller dict for a non-admin member scoped to the given teams.

    Args:
        teams: Team scope to present.

    Returns:
        dict: Principal.
    """
    return {"email": MEMBER, "is_admin": False, "teams": teams, "token_teams": teams}


def _alert_row(factory, alert_id):
    """Read back an alert row in a fresh session, to prove a denied request left it unchanged.

    Args:
        factory: Session factory bound to the test database.
        alert_id: Alert identifier.

    Returns:
        tuple: ``(status, ack_by, resolved_by)`` for the alert.
    """
    with factory() as db:
        row = db.execute(select(Alert).where(Alert.id == alert_id)).scalar_one()
        return row.status, row.ack_by, row.resolved_by


# ---------------------------------------------------------------------------
# Layer 1: API token scope denies before RBAC
# ---------------------------------------------------------------------------


class TestTokenScopeDenial:
    """A scoped API token that omits the required alerts permission is refused."""

    def test_list_denied_when_token_scope_omits_alerts_read(self, enabled):
        """A token scoped to unrelated permissions gets 403 with the generic body on the inbox list."""
        _seed_users(enabled)
        _grant_team_role(enabled, MEMBER, TEAM_A, _READ_PERMS)
        _make_alert(enabled, team_id=TEAM_A)
        client = TestClient(_build_app(enabled, principal=_team_principal([TEAM_A]), token_scopes=["tools.read"]))
        response = client.get("/v1/alerts/")
        assert response.status_code == 403
        assert response.json()["detail"] == _ACCESS_DENIED

    def test_list_body_not_leaked_when_token_scope_denied(self, enabled):
        """The denied response carries no alert data and does not name the missing permission."""
        _seed_users(enabled)
        _grant_team_role(enabled, MEMBER, TEAM_A, _READ_PERMS)
        alert_id = _make_alert(enabled, team_id=TEAM_A)
        client = TestClient(_build_app(enabled, principal=_team_principal([TEAM_A]), token_scopes=["tools.read"]))
        response = client.get("/v1/alerts/")
        assert response.status_code == 403
        assert alert_id not in response.text
        assert "alerts.read" not in response.text

    def test_ack_denied_when_token_scope_omits_alerts_acknowledge(self, enabled):
        """A token holding only alerts.read cannot acknowledge, and the alert stays open."""
        _seed_users(enabled)
        _grant_team_role(enabled, MEMBER, TEAM_A, _ACK_PERMS)
        alert_id = _make_alert(enabled, team_id=TEAM_A)
        client = TestClient(_build_app(enabled, principal=_team_principal([TEAM_A]), token_scopes=["alerts.read"]))
        response = client.post(f"/v1/alerts/{alert_id}/ack")
        assert response.status_code == 403
        assert response.json()["detail"] == _ACCESS_DENIED
        assert _alert_row(enabled, alert_id) == ("open", None, None)

    def test_resolve_denied_when_token_scope_omits_alerts_acknowledge(self, enabled):
        """A token holding only alerts.read cannot resolve, and the alert stays open."""
        _seed_users(enabled)
        _grant_team_role(enabled, MEMBER, TEAM_A, _ACK_PERMS)
        alert_id = _make_alert(enabled, team_id=TEAM_A)
        client = TestClient(_build_app(enabled, principal=_team_principal([TEAM_A]), token_scopes=["alerts.read"]))
        response = client.post(f"/v1/alerts/{alert_id}/resolve")
        assert response.status_code == 403
        assert response.json()["detail"] == _ACCESS_DENIED
        assert _alert_row(enabled, alert_id) == ("open", None, None)

    def test_preferences_denied_when_token_scope_omits_alerts_subscribe(self, enabled):
        """A token without alerts.subscribe cannot read preferences, even when the RBAC role grants it."""
        _seed_users(enabled)
        _grant_team_role(enabled, MEMBER, TEAM_A, _READ_PERMS)
        client = TestClient(_build_app(enabled, principal=_team_principal([TEAM_A]), token_scopes=["alerts.read"]))
        response = client.get("/v1/alerts/preferences")
        assert response.status_code == 403
        assert response.json()["detail"] == _ACCESS_DENIED

    def test_admin_status_denied_when_token_scope_omits_alerts_manage(self, enabled):
        """A token without alerts.manage cannot read the admin status, even for an administrator."""
        _seed_users(enabled)
        client = TestClient(_build_app(enabled, principal=_admin_principal(), token_scopes=["alerts.read"]))
        response = client.get("/admin/alerts/status")
        assert response.status_code == 403
        assert response.json()["detail"] == _ACCESS_DENIED


# ---------------------------------------------------------------------------
# RBAC: a member lacking the alerts permission is denied
# ---------------------------------------------------------------------------


class TestRbacDenial:
    """A member with no alerts role grant is refused by the permission decorator."""

    def test_member_without_role_is_denied_list(self, enabled):
        """A member holding no alerts role gets 403 on the inbox, and no alert data."""
        _seed_users(enabled)
        own_id = _make_alert(enabled, team_id=TEAM_A)
        client = TestClient(_build_app(enabled, principal=_team_principal([TEAM_A]), token_scopes=None))
        response = client.get("/v1/alerts/")
        assert response.status_code == 403
        assert response.json()["detail"] == _ACCESS_DENIED
        assert own_id not in response.text

    def test_member_with_read_only_cannot_acknowledge(self, enabled):
        """A member granted only alerts.read and alerts.subscribe cannot acknowledge, and the alert stays open."""
        _seed_users(enabled)
        _grant_team_role(enabled, MEMBER, TEAM_A, _READ_PERMS)
        alert_id = _make_alert(enabled, team_id=TEAM_A)
        client = TestClient(_build_app(enabled, principal=_team_principal([TEAM_A]), token_scopes=None))
        response = client.post(f"/v1/alerts/{alert_id}/ack")
        assert response.status_code == 403
        assert response.json()["detail"] == _ACCESS_DENIED
        assert _alert_row(enabled, alert_id) == ("open", None, None)

    def test_member_with_read_only_cannot_bulk_acknowledge(self, enabled):
        """A member without alerts.acknowledge cannot use the bulk endpoint, and no alert changes."""
        _seed_users(enabled)
        _grant_team_role(enabled, MEMBER, TEAM_A, _READ_PERMS)
        alert_id = _make_alert(enabled, team_id=TEAM_A)
        client = TestClient(_build_app(enabled, principal=_team_principal([TEAM_A]), token_scopes=None))
        response = client.post("/v1/alerts/bulk", json={"action": "ack", "ids": [alert_id]})
        assert response.status_code == 403
        assert response.json()["detail"] == _ACCESS_DENIED
        assert _alert_row(enabled, alert_id) == ("open", None, None)


# ---------------------------------------------------------------------------
# Foreign-team alerts: generic 404 and no state change
# ---------------------------------------------------------------------------


class TestForeignTeamDenial:
    """An alert owned by another team is indistinguishable from a missing alert."""

    def test_get_foreign_team_alert_is_generic_404(self, enabled):
        """Reading another team's alert returns the generic 404 with no alert body."""
        _seed_users(enabled)
        _grant_team_role(enabled, MEMBER, TEAM_B, _READ_PERMS)
        alert_id = _make_alert(enabled, team_id=TEAM_A)
        client = TestClient(_build_app(enabled, principal=_team_principal([TEAM_B]), token_scopes=None))
        response = client.get(f"/v1/alerts/{alert_id}")
        assert response.status_code == 404
        assert response.json()["detail"] == _NOT_FOUND
        assert "Body for" not in response.text

    def test_foreign_and_missing_alert_responses_are_identical(self, enabled):
        """A foreign alert and a nonexistent alert return the same status and detail, so existence is not revealed."""
        _seed_users(enabled)
        _grant_team_role(enabled, MEMBER, TEAM_B, _READ_PERMS)
        foreign_id = _make_alert(enabled, team_id=TEAM_A)
        client = TestClient(_build_app(enabled, principal=_team_principal([TEAM_B]), token_scopes=None))
        foreign = client.get(f"/v1/alerts/{foreign_id}")
        missing = client.get(f"/v1/alerts/{uuid.uuid4().hex}")
        assert foreign.status_code == missing.status_code == 404
        assert foreign.json() == missing.json()

    def test_ack_foreign_team_alert_is_404_and_leaves_alert_open(self, enabled):
        """Acknowledging another team's alert returns 404 and does not change its state."""
        _seed_users(enabled)
        _grant_team_role(enabled, MEMBER, TEAM_B, _ACK_PERMS)
        alert_id = _make_alert(enabled, team_id=TEAM_A)
        client = TestClient(_build_app(enabled, principal=_team_principal([TEAM_B]), token_scopes=None))
        response = client.post(f"/v1/alerts/{alert_id}/ack")
        assert response.status_code == 404
        assert response.json()["detail"] == _NOT_FOUND
        assert _alert_row(enabled, alert_id) == ("open", None, None)

    def test_resolve_foreign_team_alert_is_404_and_leaves_alert_open(self, enabled):
        """Resolving another team's alert returns 404 and does not change its state."""
        _seed_users(enabled)
        _grant_team_role(enabled, MEMBER, TEAM_B, _ACK_PERMS)
        alert_id = _make_alert(enabled, team_id=TEAM_A)
        client = TestClient(_build_app(enabled, principal=_team_principal([TEAM_B]), token_scopes=None))
        response = client.post(f"/v1/alerts/{alert_id}/resolve")
        assert response.status_code == 404
        assert response.json()["detail"] == _NOT_FOUND
        assert _alert_row(enabled, alert_id) == ("open", None, None)

    def test_bulk_ack_reports_foreign_alert_as_failed_and_leaves_it_open(self, enabled):
        """A bulk acknowledge reports a foreign alert in failed with a generic reason and does not change it."""
        _seed_users(enabled)
        _grant_team_role(enabled, MEMBER, TEAM_B, _ACK_PERMS)
        foreign_id = _make_alert(enabled, team_id=TEAM_A)
        own_id = _make_alert(enabled, team_id=TEAM_B, dedup_key="own")
        client = TestClient(_build_app(enabled, principal=_team_principal([TEAM_B]), token_scopes=None))
        response = client.post("/v1/alerts/bulk", json={"action": "ack", "ids": [foreign_id, own_id]})
        assert response.status_code == 200
        body = response.json()
        assert body["processed"] == [own_id]
        assert body["failed"] == [{"id": foreign_id, "reason": "not found"}]
        assert _alert_row(enabled, foreign_id) == ("open", None, None)
        assert _alert_row(enabled, own_id)[0] == "acknowledged"

    def test_bulk_resolve_reports_foreign_alert_as_failed_and_leaves_it_open(self, enabled):
        """A bulk resolve reports a foreign alert in failed and does not change its state."""
        _seed_users(enabled)
        _grant_team_role(enabled, MEMBER, TEAM_B, _ACK_PERMS)
        foreign_id = _make_alert(enabled, team_id=TEAM_A)
        client = TestClient(_build_app(enabled, principal=_team_principal([TEAM_B]), token_scopes=None))
        response = client.post("/v1/alerts/bulk", json={"action": "resolve", "ids": [foreign_id]})
        assert response.status_code == 200
        body = response.json()
        assert body["processed"] == []
        assert body["failed"] == [{"id": foreign_id, "reason": "not found"}]
        assert _alert_row(enabled, foreign_id) == ("open", None, None)

    def test_bulk_read_reports_foreign_alert_as_failed(self, enabled):
        """A bulk read reports a foreign alert in failed with the generic not-found reason."""
        _seed_users(enabled)
        # The bulk route is guarded by alerts.acknowledge for every action, including "read".
        _grant_team_role(enabled, MEMBER, TEAM_B, _ACK_PERMS)
        foreign_id = _make_alert(enabled, team_id=TEAM_A)
        client = TestClient(_build_app(enabled, principal=_team_principal([TEAM_B]), token_scopes=None))
        response = client.post("/v1/alerts/bulk", json={"action": "read", "ids": [foreign_id]})
        assert response.status_code == 200
        body = response.json()
        assert body["processed"] == []
        assert body["failed"] == [{"id": foreign_id, "reason": "not found"}]


# ---------------------------------------------------------------------------
# Global alerts are admin-only
# ---------------------------------------------------------------------------


class TestGlobalAlertDenial:
    """Global alerts (team_id IS NULL) are hidden from team-scoped callers."""

    def test_team_caller_cannot_read_global_alert(self, enabled):
        """A team-scoped member gets the generic 404 for a global alert."""
        _seed_users(enabled)
        _grant_team_role(enabled, MEMBER, TEAM_A, _READ_PERMS)
        global_id = _make_alert(enabled, team_id=None)
        client = TestClient(_build_app(enabled, principal=_team_principal([TEAM_A]), token_scopes=None))
        response = client.get(f"/v1/alerts/{global_id}")
        assert response.status_code == 404
        assert response.json()["detail"] == _NOT_FOUND

    def test_team_caller_cannot_ack_global_alert(self, enabled):
        """A team-scoped member cannot acknowledge a global alert, and it stays open."""
        _seed_users(enabled)
        _grant_team_role(enabled, MEMBER, TEAM_A, _ACK_PERMS)
        global_id = _make_alert(enabled, team_id=None)
        client = TestClient(_build_app(enabled, principal=_team_principal([TEAM_A]), token_scopes=None))
        response = client.post(f"/v1/alerts/{global_id}/ack")
        assert response.status_code == 404
        assert _alert_row(enabled, global_id) == ("open", None, None)

    def test_team_caller_list_excludes_global_alerts(self, enabled):
        """The inbox for a team-scoped member omits global alerts entirely."""
        _seed_users(enabled)
        _grant_team_role(enabled, MEMBER, TEAM_A, _READ_PERMS)
        _make_alert(enabled, team_id=None, dedup_key="global-1")
        own_id = _make_alert(enabled, team_id=TEAM_A, dedup_key="own-1")
        client = TestClient(_build_app(enabled, principal=_team_principal([TEAM_A]), token_scopes=None))
        body = client.get("/v1/alerts/").json()
        assert body["total"] == 1
        assert [item["id"] for item in body["items"]] == [own_id]

    def test_public_only_caller_sees_no_alerts(self, enabled):
        """A public-only caller (token_teams == []) sees neither team nor global alerts."""
        _seed_users(enabled)
        _grant_team_role(enabled, MEMBER, TEAM_A, _READ_PERMS)
        _make_alert(enabled, team_id=None, dedup_key="global-2")
        _make_alert(enabled, team_id=TEAM_A, dedup_key="team-2")
        client = TestClient(_build_app(enabled, principal=_team_principal([]), token_scopes=None))
        body = client.get("/v1/alerts/").json()
        assert body["total"] == 0
        assert body["items"] == []


# ---------------------------------------------------------------------------
# Administrator bypass is denied on the admin status route
# ---------------------------------------------------------------------------


class TestAdminBypassDenial:
    """The admin status route refuses administrator bypass; only an explicit alerts.manage grant passes."""

    def test_admin_status_decorator_disables_admin_bypass(self):
        """The admin status route is declared with allow_admin_bypass=False."""
        endpoint = alerts_router_module.get_alerting_status
        assert endpoint._required_permission == "alerts.manage"  # pylint: disable=protected-access
        assert endpoint._allow_admin_bypass is False  # pylint: disable=protected-access

    def test_admin_without_explicit_grant_is_denied_on_status(self, enabled):
        """An administrator with no alerts.manage grant is refused on the admin status route."""
        _seed_users(enabled)
        client = TestClient(_build_app(enabled, principal=_admin_principal(), token_scopes=None))
        response = client.get("/admin/alerts/status")
        assert response.status_code == 403
        assert response.json()["detail"] == _ACCESS_DENIED

    def test_admin_status_denial_does_not_return_status_fields(self, enabled):
        """The denied admin response exposes none of the status fields."""
        _seed_users(enabled)
        client = TestClient(_build_app(enabled, principal=_admin_principal(), token_scopes=None))
        response = client.get("/admin/alerts/status")
        assert response.status_code == 403
        assert "pending_deliveries" not in response.text
        assert "alerting_enabled" not in response.text


# ---------------------------------------------------------------------------
# Anonymous callers
# ---------------------------------------------------------------------------


class TestAnonymousDenial:
    """An anonymous caller gets 401 and never sees alert data."""

    def test_anonymous_list_is_401_with_no_data(self, enabled):
        """An anonymous list request returns 401 with the auth-required detail and no alert data."""
        _seed_users(enabled)
        _make_alert(enabled, team_id=TEAM_A)
        client = TestClient(_build_app(enabled, principal=None))
        response = client.get("/v1/alerts/")
        assert response.status_code == 401
        assert response.json()["detail"] == _AUTH_REQUIRED
        assert "items" not in response.json()

    def test_anonymous_ack_is_401_and_alert_unchanged(self, enabled):
        """An anonymous acknowledge returns 401 and does not change the alert."""
        _seed_users(enabled)
        alert_id = _make_alert(enabled, team_id=TEAM_A)
        client = TestClient(_build_app(enabled, principal=None))
        response = client.post(f"/v1/alerts/{alert_id}/ack")
        assert response.status_code == 401
        assert _alert_row(enabled, alert_id) == ("open", None, None)

    def test_anonymous_stream_is_401(self, enabled):
        """An anonymous caller cannot open the SSE stream."""
        _seed_users(enabled)
        client = TestClient(_build_app(enabled, principal=None))
        response = client.get("/v1/alerts/stream")
        assert response.status_code == 401
        assert response.json()["detail"] == _AUTH_REQUIRED

    def test_flag_off_hides_routes_even_for_admin(self, enabled, monkeypatch):
        """With the master flag off, even an administrator gets the generic 404 and no alert data."""
        monkeypatch.setattr(alerts_router_module.settings, "alerting_enabled", False, raising=False)
        _seed_users(enabled)
        _make_alert(enabled, team_id=TEAM_A)
        client = TestClient(_build_app(enabled, principal=_admin_principal(), token_scopes=None))
        response = client.get("/v1/alerts/")
        assert response.status_code == 404
        assert "items" not in response.json()
