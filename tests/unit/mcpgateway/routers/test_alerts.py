# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/routers/test_alerts.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Tests for the alerts API routers (Issue #5805).

Requests go through a real FastAPI app with the alerts routers mounted and
``TestClient``. Alert data lives in a real in-memory SQLite database. Only two
things are substituted: the database session dependency points at that test
database, and the authenticated principal is a fixed dict. The team scope
resolver runs against that dict through ``get_scoped_resource_access_context``.
The permission decorator's contract (declared permission and admin-bypass flag)
is asserted from the attributes it records on each wrapper.
"""

# Standard
from datetime import timedelta
import json
import uuid

# Third-Party
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import pytest

# First-Party
from mcpgateway.db import Alert, AlertDelivery, AlertPreference, Base, EmailTeamMember, EmailUser, Role, SecurityEvent, UserRole, get_db, utc_now
from mcpgateway.middleware import rbac as rbac_module
from mcpgateway.routers import alerts as alerts_router_module
from mcpgateway.services import alert_delivery as delivery_module
from mcpgateway.services import alert_service as alert_service_module

_TABLES = [
    EmailUser.__table__,
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


@pytest.fixture
def factory():
    """Create an in-memory SQLite database with the alerting tables and return its session factory."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=_TABLES)
    session_factory = sessionmaker(bind=engine)
    yield session_factory
    engine.dispose()


@pytest.fixture
def enabled(factory, monkeypatch):
    """Turn alerting on and route every alert database access to the test database."""
    monkeypatch.setattr(alert_service_module, "SessionLocal", factory)
    monkeypatch.setattr(alerts_router_module, "SessionLocal", factory)
    monkeypatch.setattr(delivery_module, "SessionLocal", factory)
    monkeypatch.setattr(alerts_router_module.settings, "alerting_enabled", True, raising=False)
    monkeypatch.setattr(alerts_router_module.settings, "alerting_source_security_enabled", True, raising=False)
    return factory


def _seed_users(factory):
    """Insert an administrator and a plain member.

    Args:
        factory: Session factory bound to the test database.
    """
    with factory() as db:
        db.add(EmailUser(email=ADMIN, password_hash="x", full_name="Admin", is_admin=True, is_active=True))  # pragma: allowlist secret
        db.add(EmailUser(email=MEMBER, password_hash="x", full_name="Member", is_admin=False, is_active=True))  # pragma: allowlist secret
        db.commit()


def _make_alert(factory, *, team_id=None, severity="HIGH", status="open", dedup_key=None, age_seconds=0):
    """Insert an alert row and return its identifier.

    Args:
        factory: Session factory bound to the test database.
        team_id: Owning team, or None for a global alert.
        severity: Alert severity.
        status: Lifecycle status.
        dedup_key: Dedup key (unique when omitted).
        age_seconds: How far in the past ``created_at`` is placed.

    Returns:
        str: Alert identifier.
    """
    now = utc_now() - timedelta(seconds=age_seconds)
    alert_id = uuid.uuid4().hex
    with factory() as db:
        db.add(
            Alert(
                id=alert_id,
                source="security",
                type="brute_force",
                severity=severity,
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


def _deliver(factory, alert_id, user_email, *, state="sent", age_seconds=0):
    """Insert an in-app delivery row for a user and return its identifier.

    Args:
        factory: Session factory bound to the test database.
        alert_id: Alert identifier.
        user_email: Recipient.
        state: Delivery state.
        age_seconds: How far in the past ``created_at`` is placed.

    Returns:
        str: Delivery identifier.
    """
    delivery_id = uuid.uuid4().hex
    created = utc_now() - timedelta(seconds=age_seconds)
    with factory() as db:
        db.add(
            AlertDelivery(
                id=delivery_id,
                alert_id=alert_id,
                user_email=user_email,
                channel="in_app",
                state=state,
                attempts=0,
                next_attempt_at=created,
                created_at=created,
            )
        )
        db.commit()
    return delivery_id


def _verified_payload(principal):
    """Build the verified JWT payload the auth layer would store for this principal.

    The payload follows the ``normalize_token_teams`` contract: an administrator with
    no team restriction carries ``teams: null`` and ``is_admin: true``; a member carries
    the explicit team list; a missing list means public-only.

    Args:
        principal: Caller dict with ``email``, ``is_admin`` and ``token_teams``.

    Returns:
        dict: Payload to store as ``request.state._jwt_verified_payload``.
    """
    payload = {"sub": principal["email"], "is_admin": principal["is_admin"]}
    if principal["token_teams"] is None and principal["is_admin"]:
        payload["teams"] = None
    else:
        payload["teams"] = list(principal["token_teams"] or [])
    return payload


def _build_app(factory, *, principal, mount_admin=True):
    """Build a FastAPI app mirroring production mounts, with identity set through the verified-JWT path.

    The user router is mounted at ``/v1`` (its own prefix is ``/alerts``, giving
    ``/v1/alerts``). The admin router is mounted without a prefix of its own, as
    ``main.py`` does. A middleware stores the verified payload on ``request.state``
    exactly where the auth layer does, so the real Layer-1 scope resolver runs.

    Args:
        factory: Session factory bound to the test database.
        principal: Caller dict (``email``, ``is_admin``, ``token_teams``), or None for an anonymous caller.
        mount_admin: Whether to mount the admin router.

    Returns:
        FastAPI: Application ready for TestClient.
    """
    app = FastAPI()
    app.include_router(alerts_router_module.router, prefix="/v1")
    if mount_admin:
        app.include_router(alerts_router_module.admin_router)

    if principal is not None:

        @app.middleware("http")
        async def _attach_verified_payload(request, call_next):
            """Store the verified payload on request.state, as the auth middleware does.

            Args:
                request: Incoming request.
                call_next: Next handler in the chain.

            Returns:
                Response: Downstream response.
            """
            request.state._jwt_verified_payload = ("test-token", _verified_payload(principal))
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

        Returns:
            dict: Principal, with the email the scope resolver reads.
        """
        if principal is None:
            return {"email": None}
        return {"email": principal["email"], "is_admin": principal["is_admin"]}

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[rbac_module.get_current_user_with_permissions] = _user
    return app


def _admin_principal():
    """Return the caller dict for an unrestricted administrator.

    Returns:
        dict: Principal with no team restriction.
    """
    return {"email": ADMIN, "is_admin": True, "teams": None, "token_teams": None}


def _member_principal(teams):
    """Return the caller dict for a non-admin member scoped to the given teams.

    Args:
        teams: Team scope to present, or None for unrestricted.

    Returns:
        dict: Principal.
    """
    return {"email": MEMBER, "is_admin": False, "teams": teams, "token_teams": teams}


# ---------------------------------------------------------------------------
# Flag-off and mounting
# ---------------------------------------------------------------------------


class TestFlagOffAndMounts:
    """With the master flag off no alerting route serves data."""

    def test_list_returns_404_when_flag_off(self, factory, monkeypatch):
        """With alerting disabled, GET /v1/alerts/ returns 404 and no alert data."""
        monkeypatch.setattr(alerts_router_module.settings, "alerting_enabled", False, raising=False)
        _seed_users(factory)
        _make_alert(factory)
        client = TestClient(_build_app(factory, principal=_admin_principal()))
        response = client.get("/v1/alerts/")
        assert response.status_code == 404
        assert "items" not in response.json()

    def test_admin_status_returns_404_when_flag_off(self, factory, monkeypatch):
        """With alerting disabled, GET /admin/alerts/status is not served."""
        monkeypatch.setattr(alerts_router_module.settings, "alerting_enabled", False, raising=False)
        _seed_users(factory)
        client = TestClient(_build_app(factory, principal=_admin_principal()))
        assert client.get("/admin/alerts/status").status_code == 404

    def test_unknown_alert_path_is_not_served(self, factory, enabled):
        """A path outside the mounted prefix is not routed, so no alert handler runs."""
        _seed_users(factory)
        client = TestClient(_build_app(factory, principal=_admin_principal()))
        assert client.get("/alerts/").status_code == 404


# ---------------------------------------------------------------------------
# Permission declarations (read from the decorator's recorded attributes)
# ---------------------------------------------------------------------------


def _route_endpoint(app_router, path, method):
    """Return the endpoint function registered for a path and method.

    Args:
        app_router: APIRouter to search.
        path: Route path as registered on the router.
        method: HTTP method.

    Returns:
        Callable: Endpoint function.
    """
    full_path = f"{app_router.prefix}{path}"
    for route in app_router.routes:
        if getattr(route, "path", None) == full_path and method in getattr(route, "methods", set()):
            return route.endpoint
    raise AssertionError(f"no route {method} {path}")


class TestPermissionDeclarations:
    """Each route declares the permission the blueprint assigns it."""

    @pytest.mark.parametrize(
        ("path", "method", "permission"),
        [
            ("", "GET", "alerts.read"),
            ("/stream", "GET", "alerts.read"),
            ("/preferences", "GET", "alerts.subscribe"),
            ("/preferences", "PUT", "alerts.subscribe"),
            ("/bulk", "POST", "alerts.acknowledge"),
            ("/{alert_id}", "GET", "alerts.read"),
            ("/{alert_id}/ack", "POST", "alerts.acknowledge"),
            ("/{alert_id}/resolve", "POST", "alerts.acknowledge"),
        ],
    )
    def test_user_route_declares_expected_permission(self, path, method, permission):
        """Each user route records the permission named in the blueprint."""
        endpoint = _route_endpoint(alerts_router_module.router, path, method)
        assert endpoint._required_permission == permission  # pylint: disable=protected-access

    def test_admin_status_denies_admin_bypass(self):
        """The admin status route requires alerts.manage and does not let administrators bypass it."""
        endpoint = _route_endpoint(alerts_router_module.admin_router, "/status", "GET")
        assert endpoint._required_permission == "alerts.manage"  # pylint: disable=protected-access
        assert endpoint._allow_admin_bypass is False  # pylint: disable=protected-access

    def test_user_read_routes_allow_admin_bypass(self):
        """Read routes keep the default admin bypass, as the blueprint permits for read."""
        endpoint = _route_endpoint(alerts_router_module.router, "", "GET")
        assert endpoint._allow_admin_bypass is True  # pylint: disable=protected-access


# ---------------------------------------------------------------------------
# User routes
# ---------------------------------------------------------------------------


class TestList:
    """List, filter and pagination over the visible alerts."""

    def test_list_returns_alerts_without_body_or_metadata(self, factory, enabled):
        """The list returns the alert fields but omits body and metadata."""
        _seed_users(factory)
        alert_id = _make_alert(factory, severity="HIGH")
        client = TestClient(_build_app(factory, principal=_admin_principal()))
        response = client.get("/v1/alerts/")
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 1
        assert body["page"] == 1
        assert body["page_size"] == 50
        item = body["items"][0]
        assert item["id"] == alert_id
        assert item["severity"] == "HIGH"
        assert item["body"] == ""
        assert item["metadata"] is None

    def test_status_filter_returns_only_matching_alerts(self, factory, enabled):
        """The status filter excludes alerts in other states and reports an accurate total."""
        _seed_users(factory)
        open_id = _make_alert(factory, dedup_key="open-one", status="open")
        _make_alert(factory, dedup_key="resolved-one", status="resolved")
        client = TestClient(_build_app(factory, principal=_admin_principal()))
        body = client.get("/v1/alerts/", params={"status": "open"}).json()
        assert body["total"] == 1
        assert [item["id"] for item in body["items"]] == [open_id]

    def test_pagination_returns_requested_page_with_stable_total(self, factory, enabled):
        """Page 2 of size 2 over five alerts returns two items and total stays five."""
        _seed_users(factory)
        for index in range(5):
            _make_alert(factory, dedup_key=f"p-{index}", age_seconds=index)
        client = TestClient(_build_app(factory, principal=_admin_principal()))
        body = client.get("/v1/alerts/", params={"page": 2, "page_size": 2}).json()
        assert body["total"] == 5
        assert body["page"] == 2
        assert len(body["items"]) == 2

    def test_page_size_above_maximum_is_rejected(self, factory, enabled):
        """A page size above MAX_LIST_LIMIT is a 422 before the handler runs."""
        _seed_users(factory)
        client = TestClient(_build_app(factory, principal=_admin_principal()))
        assert client.get("/v1/alerts/", params={"page_size": 500}).status_code == 422

    def test_page_zero_is_rejected(self, factory, enabled):
        """A page number below 1 is a 422."""
        _seed_users(factory)
        client = TestClient(_build_app(factory, principal=_admin_principal()))
        assert client.get("/v1/alerts/", params={"page": 0}).status_code == 422


class TestDetailAndLifecycle:
    """Detail, acknowledge and resolve."""

    def test_detail_returns_body_and_metadata(self, factory, enabled):
        """The detail view includes the body and the stored metadata."""
        _seed_users(factory)
        alert_id = _make_alert(factory)
        client = TestClient(_build_app(factory, principal=_admin_principal()))
        body = client.get(f"/v1/alerts/{alert_id}").json()
        assert body["id"] == alert_id
        assert body["body"] == f"Body for {alert_id[:6]}"
        assert body["metadata"] == {"threat_score": 0.8}

    def test_detail_unknown_id_returns_generic_404(self, factory, enabled):
        """An unknown ID returns 404 with the generic not-found detail and no internal text."""
        _seed_users(factory)
        client = TestClient(_build_app(factory, principal=_admin_principal()))
        response = client.get("/v1/alerts/does-not-exist")
        assert response.status_code == 404
        assert response.json()["detail"] == "alert not found"

    def test_ack_moves_status_and_records_actor(self, factory, enabled):
        """Acknowledging returns the alert as acknowledged with the actor recorded."""
        _seed_users(factory)
        alert_id = _make_alert(factory)
        client = TestClient(_build_app(factory, principal=_admin_principal()))
        body = client.post(f"/v1/alerts/{alert_id}/ack", json={}).json()
        assert body["status"] == "acknowledged"
        assert body["ack_by"] == ADMIN

    def test_ack_is_idempotent_and_keeps_original_ack_time(self, factory, enabled):
        """A second acknowledge returns 200 and does not move the original acknowledgement time."""
        _seed_users(factory)
        alert_id = _make_alert(factory)
        client = TestClient(_build_app(factory, principal=_admin_principal()))
        first = client.post(f"/v1/alerts/{alert_id}/ack", json={}).json()
        second = client.post(f"/v1/alerts/{alert_id}/ack", json={})
        assert second.status_code == 200
        assert second.json()["ack_at"] == first["ack_at"]

    def test_resolve_is_idempotent(self, factory, enabled):
        """Resolving a resolved alert returns 200 and keeps the resolved status."""
        _seed_users(factory)
        alert_id = _make_alert(factory)
        client = TestClient(_build_app(factory, principal=_admin_principal()))
        assert client.post(f"/v1/alerts/{alert_id}/resolve").json()["status"] == "resolved"
        again = client.post(f"/v1/alerts/{alert_id}/resolve")
        assert again.status_code == 200
        assert again.json()["status"] == "resolved"

    def test_ack_after_resolve_is_forbidden_transition(self, factory, enabled):
        """Acknowledging a resolved alert returns 409 with the generic transition detail."""
        _seed_users(factory)
        alert_id = _make_alert(factory, status="resolved")
        client = TestClient(_build_app(factory, principal=_admin_principal()))
        response = client.post(f"/v1/alerts/{alert_id}/ack", json={})
        assert response.status_code == 409
        assert response.json()["detail"] == "transition not allowed for the current alert state"


class TestBulk:
    """Bulk actions and their limit."""

    def test_more_than_100_ids_is_rejected(self, factory, enabled):
        """More than 100 IDs is a 422 before the handler runs."""
        _seed_users(factory)
        client = TestClient(_build_app(factory, principal=_admin_principal()))
        response = client.post("/v1/alerts/bulk", json={"action": "ack", "ids": [f"id-{i}" for i in range(101)]})
        assert response.status_code == 422

    def test_bulk_ack_reports_processed_and_failed_separately(self, factory, enabled):
        """A bulk ack processes the valid ID and reports the unknown one as failed."""
        _seed_users(factory)
        good = _make_alert(factory, dedup_key="bulk-good")
        client = TestClient(_build_app(factory, principal=_admin_principal()))
        body = client.post("/v1/alerts/bulk", json={"action": "ack", "ids": [good, "missing"]}).json()
        assert body["processed"] == [good]
        assert body["failed"] == [{"id": "missing", "reason": "not found"}]

    def test_bulk_read_sets_read_at_on_callers_delivery(self, factory, enabled):
        """A bulk read sets read_at on the caller's in-app delivery for the alert."""
        _seed_users(factory)
        alert_id = _make_alert(factory)
        delivery_id = _deliver(factory, alert_id, ADMIN)
        client = TestClient(_build_app(factory, principal=_admin_principal()))
        body = client.post("/v1/alerts/bulk", json={"action": "read", "ids": [alert_id]}).json()
        assert body["processed"] == [alert_id]
        with factory() as db:
            row = db.execute(select(AlertDelivery).where(AlertDelivery.id == delivery_id)).scalar_one()
        assert row.read_at is not None


class TestPreferences:
    """Preference get and put."""

    def test_put_then_get_round_trips_the_preference(self, factory, enabled):
        """A stored preference is returned by GET with the same values and is_default false."""
        _seed_users(factory)
        client = TestClient(_build_app(factory, principal=_member_principal(None)))
        put = client.put(
            "/v1/alerts/preferences",
            json={"items": [{"scope": "category", "scope_value": "security", "channel": "in_app", "min_severity": "HIGH", "enabled": True}]},
        )
        assert put.status_code == 200
        own = [item for item in client.get("/v1/alerts/preferences").json()["items"] if not item["is_default"]]
        assert len(own) == 1
        assert own[0]["scope"] == "category"
        assert own[0]["scope_value"] == "security"
        assert own[0]["min_severity"] == "HIGH"

    def test_invalid_channel_is_rejected(self, factory, enabled):
        """A channel outside in_app, email and webhook is a 422."""
        _seed_users(factory)
        client = TestClient(_build_app(factory, principal=_member_principal(None)))
        response = client.put(
            "/v1/alerts/preferences",
            json={"items": [{"scope": "global", "scope_value": "", "channel": "sms", "min_severity": "LOW", "enabled": True}]},
        )
        assert response.status_code == 422

    def test_invalid_min_severity_is_rejected(self, factory, enabled):
        """A minimum severity outside LOW..CRITICAL is a 422."""
        _seed_users(factory)
        client = TestClient(_build_app(factory, principal=_member_principal(None)))
        response = client.put(
            "/v1/alerts/preferences",
            json={"items": [{"scope": "global", "scope_value": "", "channel": "in_app", "min_severity": "URGENT", "enabled": True}]},
        )
        assert response.status_code == 422

    def test_unknown_field_is_rejected(self, factory, enabled):
        """Unknown keys are rejected because the models forbid extra fields."""
        _seed_users(factory)
        client = TestClient(_build_app(factory, principal=_member_principal(None)))
        response = client.put(
            "/v1/alerts/preferences",
            json={"items": [{"scope": "global", "scope_value": "", "channel": "in_app", "min_severity": "LOW", "enabled": True, "owner": "x"}]},
        )
        assert response.status_code == 422


class TestTeamScope:
    """Team scoping, the generic 404 for foreign alerts, and that client-supplied team input is ignored."""

    def test_foreign_team_detail_returns_generic_404(self, factory, enabled):
        """A caller scoped to team-b cannot read a team-a alert; the response is the generic 404."""
        _seed_users(factory)
        alert_id = _make_alert(factory, team_id="team-a")
        client = TestClient(_build_app(factory, principal=_member_principal(["team-b"])))
        response = client.get(f"/v1/alerts/{alert_id}")
        assert response.status_code == 404
        assert response.json()["detail"] == "alert not found"

    def test_list_excludes_other_teams_and_global_alerts_for_team_caller(self, factory, enabled):
        """A team-scoped caller sees only alerts for their own team, never another team's or global ones."""
        _seed_users(factory)
        own = _make_alert(factory, team_id="team-a", dedup_key="ta")
        _make_alert(factory, team_id="team-b", dedup_key="tb")
        _make_alert(factory, team_id=None, dedup_key="global")
        client = TestClient(_build_app(factory, principal=_member_principal(["team-a"])))
        body = client.get("/v1/alerts/").json()
        assert body["total"] == 1
        assert [item["id"] for item in body["items"]] == [own]

    def test_client_supplied_team_id_cannot_widen_scope(self, factory, enabled):
        """A team_id query parameter cannot reveal another team's alerts beyond the token scope."""
        _seed_users(factory)
        _make_alert(factory, team_id="team-a", dedup_key="ta2")
        client = TestClient(_build_app(factory, principal=_member_principal(["team-b"])))
        body = client.get("/v1/alerts/", params={"team_id": "team-a"}).json()
        assert body["total"] == 0


class TestStream:
    """SSE stream: catch-up replay and live delivery."""

    def test_catch_up_replays_each_missed_alert_once_in_order(self, factory, enabled, monkeypatch):
        """Three alerts delivered after the cursor are replayed once each, oldest first, with the cursor on each frame."""
        _seed_users(factory)
        alert_ids = [_make_alert(factory, dedup_key=f"s-{i}", age_seconds=30 - i) for i in range(3)]
        delivery_ids = [_deliver(factory, aid, ADMIN, age_seconds=30 - i) for i, aid in enumerate(alert_ids)]

        class _SilentBus:
            """Event bus that never publishes, so only catch-up frames are produced."""

            async def subscribe_events(self):
                """Wait forever without yielding an event.

                Yields:
                    dict: Never yields.
                """
                import asyncio  # pylint: disable=import-outside-toplevel

                await asyncio.Event().wait()
                yield {}

        monkeypatch.setattr(alerts_router_module, "get_alert_event_service", _SilentBus)
        client = TestClient(_build_app(factory, principal=_admin_principal()))
        frames = []
        with client.stream("GET", "/v1/alerts/stream") as response:
            assert response.status_code == 200
            assert response.headers["content-type"].startswith("text/event-stream")
            for line in response.iter_lines():
                if line.startswith("data: "):
                    frames.append(json.loads(line[len("data: ") :]))
                if len(frames) == 3:
                    break

        assert [frame["alert_id"] for frame in frames] == alert_ids
        assert [frame["delivery_id"] for frame in frames] == delivery_ids
        assert all(frame["type"] == "alert" for frame in frames)
        assert all(frame["cursor"].endswith("|" + did) for frame, did in zip(frames, delivery_ids))

    def test_stream_without_identity_is_401(self, factory, enabled):
        """A caller with no identity cannot open the stream and receives the auth detail."""
        _seed_users(factory)
        client = TestClient(_build_app(factory, principal={"email": None, "is_admin": False, "teams": None, "token_teams": None}))
        response = client.get("/v1/alerts/stream")
        assert response.status_code == 401
        assert response.json()["detail"] == "User authentication required"


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------


class TestAdminStatus:
    """GET /admin/alerts/status."""

    def test_status_reports_flags_windows_and_sources(self, factory, enabled):
        """The status response reports the master flag, the retention windows and the active sources."""
        _seed_users(factory)
        client = TestClient(_build_app(factory, principal=_admin_principal()))
        response = client.get("/admin/alerts/status")
        assert response.status_code == 200
        body = response.json()
        assert body["alerting_enabled"] is True
        assert body["dedup_window_seconds"] == 300
        assert body["expiry_days"] == 30
        assert body["retention_days"] == 90
        assert "security" in body["active_sources"]

    def test_status_counts_only_pending_deliveries(self, factory, enabled):
        """pending_deliveries counts outbox rows in the pending state and ignores sent rows."""
        _seed_users(factory)
        alert_id = _make_alert(factory)
        _deliver(factory, alert_id, ADMIN, state="pending")
        _deliver(factory, alert_id, MEMBER, state="sent")
        client = TestClient(_build_app(factory, principal=_admin_principal()))
        assert client.get("/admin/alerts/status").json()["pending_deliveries"] == 1
