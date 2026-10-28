# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/services/test_alert_service.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Tests for the alert service core (Issue #5805).

Each test runs against a real in-memory SQLite database. ``SessionLocal`` is
patched in the alert service module so ``emit()`` and the producer helpers write
to that database. Team membership and role rows are real rows, so the
recipient-permission path is exercised rather than patched out.
"""

# Standard
from datetime import timedelta
from unittest.mock import patch
import uuid

# Third-Party
import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# First-Party
from mcpgateway.db import Alert, AlertDelivery, AlertPreference, Base, EmailTeamMember, EmailUser, Role, SecurityEvent, UserRole, utc_now
from mcpgateway.services import alert_service as alert_service_module
from mcpgateway.services.alert_service import (
    AlertFilters,
    AlertNotFoundError,
    AlertRecipientResolver,
    AlertService,
    AlertTransitionError,
    AlertValidationError,
    emit_alert_safe,
    redact_metadata,
    sanitize_text,
)

_ALERT_TABLES = [
    EmailUser.__table__,
    EmailTeamMember.__table__,
    Role.__table__,
    UserRole.__table__,
    SecurityEvent.__table__,
    Alert.__table__,
    AlertDelivery.__table__,
    AlertPreference.__table__,
]


@pytest.fixture
def session_factory():
    """Create an in-memory SQLite database with the alerting tables and return its session factory."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=_ALERT_TABLES)
    factory = sessionmaker(bind=engine)
    yield factory
    engine.dispose()


@pytest.fixture
def alerting_settings(monkeypatch):
    """Enable alerting with the security and gateway sources, the default dedup window and fan-out cap."""
    settings = alert_service_module.settings
    monkeypatch.setattr(settings, "alerting_enabled", True, raising=False)
    monkeypatch.setattr(settings, "alerting_source_security_enabled", True, raising=False)
    monkeypatch.setattr(settings, "alerting_source_gateway_health_enabled", True, raising=False)
    monkeypatch.setattr(settings, "alerting_dedup_window_seconds", 300, raising=False)
    monkeypatch.setattr(settings, "alerting_max_recipients", 1000, raising=False)
    return settings


@pytest.fixture
def db_session(session_factory):
    """Point the service's ``SessionLocal`` at the test database and yield the factory."""
    with patch.object(alert_service_module, "SessionLocal", session_factory):
        yield session_factory


# ---------------------------------------------------------------------------
# Seeding helpers. They write real rows so the production code paths run.
# ---------------------------------------------------------------------------


def _add_user(factory, email, *, is_admin=False, is_active=True):
    """Insert an ``EmailUser`` row.

    Args:
        factory: Session factory bound to the test database.
        email: User email.
        is_admin: Whether the user is a platform administrator.
        is_active: Whether the account is active.
    """
    with factory() as db:
        db.add(EmailUser(email=email, password_hash=None, full_name=email, is_admin=is_admin, is_active=is_active))  # pragma: allowlist secret
        db.commit()


def _add_team_member(factory, email, team_id, *, is_active=True):
    """Insert an active or inactive ``EmailTeamMember`` row.

    Args:
        factory: Session factory bound to the test database.
        email: Member email.
        team_id: Team identifier.
        is_active: Whether the membership is active.
    """
    with factory() as db:
        db.add(EmailTeamMember(id=uuid.uuid4().hex, team_id=team_id, user_email=email, role="member", is_active=is_active))
        db.commit()


def _grant_team_alert_read(factory, email, team_id, *, granted_by="admin@example.com"):
    """Give a user the ``alerts.read`` permission in a team through a real role assignment.

    Args:
        factory: Session factory bound to the test database.
        email: User email.
        team_id: Team the role is scoped to.
        granted_by: Account recorded as the grantor (must exist).
    """
    with factory() as db:
        role = Role(id=uuid.uuid4().hex, name=f"team-reader-{team_id}", scope="team", permissions=["alerts.read"], created_by=granted_by, is_system_role=False, is_active=True)
        db.add(role)
        db.flush()
        db.add(UserRole(id=uuid.uuid4().hex, user_email=email, role_id=role.id, scope="team", scope_id=team_id, granted_by=granted_by, is_active=True))
        db.commit()


def _add_preference(factory, *, user_email, scope="global", scope_value="", channel="in_app", min_severity="LOW", enabled=True, mute_until=None):
    """Insert an ``AlertPreference`` row.

    Args:
        factory: Session factory bound to the test database.
        user_email: Owner, or None for an administrator default.
        scope: Preference scope.
        scope_value: Scope value (source name for category scope).
        channel: Delivery channel.
        min_severity: Minimum severity to deliver.
        enabled: Whether the channel is enabled.
        mute_until: Optional mute expiry.
    """
    with factory() as db:
        db.add(
            AlertPreference(
                id=uuid.uuid4().hex,
                user_email=user_email,
                scope=scope,
                scope_value=scope_value,
                channel=channel,
                min_severity=min_severity,
                enabled=enabled,
                mute_until=mute_until,
            )
        )
        db.commit()


def _emit(service=None, **overrides):
    """Call ``AlertService.emit`` with a valid security payload, overriding any field given.

    Args:
        service: Optional service instance.
        **overrides: Field values to replace in the default payload.

    Returns:
        AlertEmitResult: Result of the emit.
    """
    params = {
        "source": "security",
        "type": "brute_force",
        "severity": "HIGH",
        "entity_type": "security_event",
        "entity_id": "evt-1",
        "team_id": None,
        "dedup_key": "security:brute_force:10.0.0.1",
        "title": "Brute force detected",
        "body": "Repeated failed logins from 10.0.0.1",
        "metadata": None,
        "security_event_id": None,
    }
    params.update(overrides)
    return (service or AlertService()).emit(**params)


def _recipients(factory, alert_id):
    """Return the sorted recipient emails with an in-app delivery row for an alert.

    Args:
        factory: Session factory bound to the test database.
        alert_id: Alert identifier.

    Returns:
        list[str]: Sorted recipient emails.
    """
    with factory() as db:
        rows = db.execute(select(AlertDelivery.user_email).where(AlertDelivery.alert_id == alert_id)).scalars().all()
    return sorted(rows)


def _row_count(factory, model):
    """Return the number of rows in a table.

    Args:
        factory: Session factory bound to the test database.
        model: Mapped model class.

    Returns:
        int: Row count.
    """
    with factory() as db:
        return int(db.execute(select(func.count()).select_from(model)).scalar_one())


# ---------------------------------------------------------------------------
# Sanitisation helpers
# ---------------------------------------------------------------------------


class TestSanitisation:
    """Unit tests for redaction and text sanitising helpers."""

    def test_redacts_sensitive_keys_at_any_depth_and_keeps_safe_values(self):
        """Sensitive keys are masked at every depth; safe keys keep their values."""
        result = redact_metadata({"gateway": "g1", "password": "hunter2", "nested": {"api_key": "sk-123", "count": 3}})
        assert result == {"gateway": "g1", "password": "***REDACTED***", "nested": {"api_key": "***REDACTED***", "count": 3}}

    def test_redacts_each_documented_fragment_case_insensitively(self):
        """Authorization, token, secret and cookie fragments are all masked regardless of case."""
        result = redact_metadata({"Authorization": "Bearer x", "access_token": "t", "client_secret": "s", "Session_Cookie": "c", "safe": "ok"})
        assert result["Authorization"] == "***REDACTED***"
        assert result["access_token"] == "***REDACTED***"
        assert result["client_secret"] == "***REDACTED***"
        assert result["Session_Cookie"] == "***REDACTED***"
        assert result["safe"] == "ok"

    def test_non_dict_metadata_returns_none(self):
        """Non-mapping input is not stored and yields None."""
        assert redact_metadata("not a dict") is None
        assert redact_metadata(["a", "b"]) is None
        assert redact_metadata(None) is None

    def test_long_string_is_truncated_with_marker(self):
        """A string over the cap is cut and suffixed with the truncation marker."""
        result = redact_metadata({"note": "x" * 1000}, max_string=50)
        assert result["note"] == "x" * 50 + "...<truncated>"

    def test_oversized_payload_is_replaced_with_size_marker(self):
        """A serialised result above the byte cap becomes a marker that records the original size."""
        result = redact_metadata({"blob": "y" * 5000}, max_total_bytes=100)
        assert result["<truncated>"] is True
        assert result["original_size_bytes"] > 100

    def test_sanitize_text_strips_control_characters_and_trims(self):
        """Control characters are removed and surrounding whitespace is trimmed."""
        assert sanitize_text("  hello\x00 world \x07 ", 200, "title") == "hello world"

    def test_sanitize_text_rejects_text_empty_after_cleaning(self):
        """Text that is empty after cleaning raises a validation error that names the field."""
        with pytest.raises(AlertValidationError, match="title must not be empty"):
            sanitize_text("\x00\x01  ", 200, "title")

    def test_sanitize_text_truncates_to_max_length(self):
        """Text longer than the limit is cut to exactly that many characters."""
        assert sanitize_text("a" * 300, 200, "title") == "a" * 200


# ---------------------------------------------------------------------------
# Emission
# ---------------------------------------------------------------------------


class TestEmit:
    """Tests for :meth:`AlertService.emit`."""

    def test_emit_writes_open_alert_with_sanitised_fields(self, alerting_settings, db_session):
        """A successful emit writes one open alert with the expected stored fields."""
        result = _emit()
        assert result.created is True
        assert result.deduplicated is False
        assert result.skipped_reason is None

        with db_session() as db:
            alert = db.execute(select(Alert).where(Alert.id == result.alert_id)).scalar_one()
            assert alert.source == "security"
            assert alert.type == "brute_force"
            assert alert.severity == "HIGH"
            assert alert.status == "open"
            assert alert.title == "Brute force detected"
            assert alert.body == "Repeated failed logins from 10.0.0.1"
            assert alert.team_id is None
            assert alert.count == 1
            assert alert.dedup_key == "security:brute_force:10.0.0.1"

    def test_emit_rejects_blank_title_and_writes_nothing(self, alerting_settings, db_session):
        """A blank title is a validation error and no alert row is created."""
        with pytest.raises(AlertValidationError, match="title must not be empty"):
            _emit(title="   ")
        assert _row_count(db_session, Alert) == 0

    def test_emit_rejects_blank_body(self, alerting_settings, db_session):
        """A body that is empty after cleaning is a validation error."""
        with pytest.raises(AlertValidationError, match="body must not be empty"):
            _emit(body="\x00")

    def test_emit_rejects_unknown_source(self, alerting_settings, db_session):
        """An unknown source is rejected before anything is written."""
        with pytest.raises(AlertValidationError, match="unknown alert source"):
            _emit(source="not-a-source")

    def test_emit_rejects_unknown_severity(self, alerting_settings, db_session):
        """An unknown severity is rejected before anything is written."""
        with pytest.raises(AlertValidationError, match="unknown alert severity"):
            _emit(severity="URGENT")

    def test_emit_rejects_blank_dedup_key(self, alerting_settings, db_session):
        """A blank dedup key is a validation error."""
        with pytest.raises(AlertValidationError, match="dedup_key must not be empty"):
            _emit(dedup_key="   ")

    def test_emit_truncates_title_to_200_and_body_to_4000(self, alerting_settings, db_session):
        """Title is capped at 200 characters and body at 4000."""
        result = _emit(title="T" * 500, body="B" * 9000, dedup_key="long-fields")
        with db_session() as db:
            alert = db.execute(select(Alert).where(Alert.id == result.alert_id)).scalar_one()
            assert alert.title == "T" * 200
            assert alert.body == "B" * 4000

    def test_emit_is_noop_when_master_flag_off(self, monkeypatch, db_session):
        """With alerting disabled emit writes nothing and reports the skip reason."""
        monkeypatch.setattr(alert_service_module.settings, "alerting_enabled", False, raising=False)
        result = _emit()
        assert result.created is False
        assert result.alert_id is None
        assert result.skipped_reason == "alerting_disabled"
        assert _row_count(db_session, Alert) == 0

    def test_emit_is_noop_when_source_flag_off(self, monkeypatch, alerting_settings, db_session):
        """With only the per-source flag off, the source is skipped and the reason says so."""
        monkeypatch.setattr(alert_service_module.settings, "alerting_source_security_enabled", False, raising=False)
        result = _emit()
        assert result.skipped_reason == "source_disabled"
        assert _row_count(db_session, Alert) == 0

    def test_storage_failure_is_reported_not_raised(self, alerting_settings, monkeypatch):
        """A database error is logged and returned as storage_error; the caller never sees an exception."""

        class _BrokenSession:
            """Session stand-in whose every statement fails."""

            def execute(self, *_args, **_kwargs):
                """Raise an operational error for any statement.

                Raises:
                    OperationalError: Always.
                """
                raise OperationalError("SELECT 1", {}, Exception("disk I/O error"))

            def rollback(self):
                """Roll back; nothing to undo on this stand-in."""

            def close(self):
                """Close; nothing to release on this stand-in."""

        monkeypatch.setattr(alert_service_module, "SessionLocal", _BrokenSession)
        result = _emit()
        assert result.alert_id is None
        assert result.created is False
        assert result.skipped_reason == "storage_error"

    def test_fifty_repeats_collapse_into_one_row_with_count_fifty(self, alerting_settings, db_session):
        """Fifty emits inside the dedup window produce one alert whose count is 50."""
        service = AlertService()
        first = _emit(service)
        assert first.created is True
        for _ in range(49):
            repeat = _emit(service)
            assert repeat.deduplicated is True
            assert repeat.alert_id == first.alert_id

        with db_session() as db:
            rows = db.execute(select(Alert)).scalars().all()
        assert len(rows) == 1
        assert rows[0].count == 50

    def test_emit_after_dedup_window_creates_new_row(self, alerting_settings, db_session):
        """Once the last occurrence is older than the window, the next emit creates a new alert."""
        service = AlertService()
        first = _emit(service)
        with db_session() as db:
            alert = db.execute(select(Alert).where(Alert.id == first.alert_id)).scalar_one()
            stale = utc_now() - timedelta(seconds=301)
            alert.first_seen = stale
            alert.last_seen = stale
            db.commit()

        second = _emit(service)
        assert second.created is True
        assert second.alert_id != first.alert_id
        assert _row_count(db_session, Alert) == 2

    def test_stored_metadata_has_secrets_redacted(self, alerting_settings, db_session):
        """Sensitive metadata is redacted before storage and benign metadata is kept."""
        result = _emit(metadata={"password": "hunter2", "threat_score": 0.9}, dedup_key="meta-redact")
        with db_session() as db:
            alert = db.execute(select(Alert).where(Alert.id == result.alert_id)).scalar_one()
        assert alert.alert_metadata == {"password": "***REDACTED***", "threat_score": 0.9}
        assert "hunter2" not in str(alert.alert_metadata)

    def test_security_event_is_marked_alert_sent_with_recipients(self, alerting_settings, db_session):
        """The originating SecurityEvent is marked alert_sent with its recipient list."""
        _add_user(db_session, "admin@example.com", is_admin=True)
        with db_session() as db:
            db.add(
                SecurityEvent(
                    id="sec-evt-1",
                    event_type="authentication_failure",
                    severity="HIGH",
                    category="authentication",
                    client_ip="10.0.0.1",
                    description="failed login",
                    threat_score=0.9,
                    alert_sent=False,
                )
            )
            db.commit()

        result = _emit(security_event_id="sec-evt-1", dedup_key="writeback")
        assert result.recipient_count == 1
        with db_session() as db:
            event = db.execute(select(SecurityEvent).where(SecurityEvent.id == "sec-evt-1")).scalar_one()
        assert event.alert_sent is True
        assert event.alert_sent_at is not None
        assert event.alert_recipients == ["admin@example.com"]


# ---------------------------------------------------------------------------
# Transactions and recipient rules
# ---------------------------------------------------------------------------


class TestTransactionAndRecipients:
    """One-transaction writes and recipient resolution rules."""

    def test_failure_after_alert_flush_leaves_no_orphan_alert(self, alerting_settings, db_session, monkeypatch):
        """If recipient resolution fails after the alert row is flushed, the alert is rolled back."""

        def _fail(*_args, **_kwargs):
            """Simulate a failure during recipient resolution.

            Raises:
                SQLAlchemyError: Always.
            """
            raise SQLAlchemyError("resolver failed")

        monkeypatch.setattr(AlertRecipientResolver, "resolve", staticmethod(_fail))
        result = _emit(dedup_key="orphan-check")
        assert result.skipped_reason == "storage_error"
        assert _row_count(db_session, Alert) == 0
        assert _row_count(db_session, AlertDelivery) == 0

    def test_global_alert_reaches_active_admins_only(self, alerting_settings, db_session):
        """A global alert (team_id None) goes to active administrators and not to ordinary users."""
        _add_user(db_session, "admin@example.com", is_admin=True)
        _add_user(db_session, "plain@example.com", is_admin=False)

        result = _emit(dedup_key="global-admin-only")
        assert result.recipient_count == 1
        assert _recipients(db_session, result.alert_id) == ["admin@example.com"]

    def test_inactive_admin_is_not_a_global_recipient(self, alerting_settings, db_session):
        """A deactivated administrator does not receive global alerts."""
        _add_user(db_session, "gone-admin@example.com", is_admin=True, is_active=False)
        result = _emit(dedup_key="inactive-admin")
        assert result.recipient_count == 0

    def test_team_alert_reaches_member_with_read_permission_only(self, alerting_settings, db_session):
        """A team alert reaches a member holding alerts.read in that team, not an outsider."""
        _add_user(db_session, "admin@example.com", is_admin=True)
        _add_user(db_session, "member@example.com")
        _add_user(db_session, "outsider@example.com")
        _add_team_member(db_session, "member@example.com", "team-a")
        _grant_team_alert_read(db_session, "member@example.com", "team-a")

        result = _emit(team_id="team-a", dedup_key="team-a-alert")
        assert _recipients(db_session, result.alert_id) == ["member@example.com"]

    def test_team_member_without_alerts_read_is_excluded(self, alerting_settings, db_session):
        """A team member who has no alerts.read grant does not receive the team alert."""
        _add_user(db_session, "admin@example.com", is_admin=True)
        _add_user(db_session, "nopriv@example.com")
        _add_team_member(db_session, "nopriv@example.com", "team-n")

        result = _emit(team_id="team-n", dedup_key="team-n-alert")
        assert result.recipient_count == 0

    def test_inactive_team_membership_is_excluded(self, alerting_settings, db_session):
        """A deactivated membership does not receive team alerts even with alerts.read."""
        _add_user(db_session, "admin@example.com", is_admin=True)
        _add_user(db_session, "former@example.com")
        _add_team_member(db_session, "former@example.com", "team-b", is_active=False)
        _grant_team_alert_read(db_session, "former@example.com", "team-b")

        result = _emit(team_id="team-b", dedup_key="team-b-alert")
        assert result.recipient_count == 0

    def test_disabled_in_app_preference_removes_recipient(self, alerting_settings, db_session):
        """A user who disabled in-app alerts gets no delivery row."""
        _add_user(db_session, "muted@example.com", is_admin=True)
        _add_preference(db_session, user_email="muted@example.com", enabled=False)

        result = _emit(dedup_key="disabled-pref")
        assert result.recipient_count == 0

    def test_active_mute_removes_recipient(self, alerting_settings, db_session):
        """An active mute suppresses in-app delivery for that user."""
        _add_user(db_session, "quiet@example.com", is_admin=True)
        _add_preference(db_session, user_email="quiet@example.com", mute_until=utc_now() + timedelta(hours=1))

        result = _emit(dedup_key="muted")
        assert result.recipient_count == 0

    def test_expired_mute_does_not_remove_recipient(self, alerting_settings, db_session):
        """A mute whose end time has passed no longer suppresses delivery."""
        _add_user(db_session, "back@example.com", is_admin=True)
        _add_preference(db_session, user_email="back@example.com", mute_until=utc_now() - timedelta(minutes=5))

        result = _emit(dedup_key="mute-expired")
        assert _recipients(db_session, result.alert_id) == ["back@example.com"]

    def test_min_severity_above_alert_removes_recipient(self, alerting_settings, db_session):
        """A user whose minimum severity is CRITICAL does not receive a HIGH alert."""
        _add_user(db_session, "picky@example.com", is_admin=True)
        _add_preference(db_session, user_email="picky@example.com", min_severity="CRITICAL")

        result = _emit(severity="HIGH", dedup_key="min-sev")
        assert result.recipient_count == 0

    def test_admin_default_preference_applies_when_user_has_none(self, alerting_settings, db_session):
        """An administrator default (user_email NULL) disables in-app delivery for users without their own row."""
        _add_user(db_session, "follower@example.com", is_admin=True)
        _add_preference(db_session, user_email=None, enabled=False)

        result = _emit(dedup_key="admin-default")
        assert result.recipient_count == 0

    def test_fan_out_is_capped_at_max_recipients(self, alerting_settings, db_session, monkeypatch):
        """Recipients beyond alerting_max_recipients are dropped; the stored deliveries match the cap."""
        monkeypatch.setattr(alert_service_module.settings, "alerting_max_recipients", 2, raising=False)
        for index in range(5):
            _add_user(db_session, f"admin{index}@example.com", is_admin=True)

        result = _emit(dedup_key="fanout-cap")
        assert result.recipient_count == 2
        assert _row_count(db_session, AlertDelivery) == 2


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


def _create_alert(factory, dedup_key, team_id=None):
    """Emit an alert and return its identifier.

    Args:
        factory: Session factory fixture (only used to keep the DB patched).
        dedup_key: Dedup key to use.
        team_id: Owning team, or None for a global alert.

    Returns:
        str: Alert identifier.
    """
    del factory  # The database is already patched by the fixture that created it.
    return _emit(dedup_key=dedup_key, team_id=team_id).alert_id


class TestLifecycle:
    """Acknowledge, resolve, suppress and visibility rules."""

    def test_acknowledge_records_status_actor_and_time(self, alerting_settings, db_session):
        """Acknowledging moves the alert to acknowledged and stores the actor and timestamp."""
        _add_user(db_session, "admin@example.com", is_admin=True)
        alert_id = _create_alert(db_session, "ack-1")
        with db_session() as db:
            alert = AlertService().acknowledge(db, alert_id, "admin@example.com", None)
            assert alert.status == "acknowledged"
            assert alert.ack_by == "admin@example.com"
            assert alert.ack_at is not None

    def test_acknowledge_twice_is_idempotent_and_keeps_first_actor(self, alerting_settings, db_session):
        """A second acknowledge returns the same alert and keeps the original actor and time."""
        _add_user(db_session, "admin@example.com", is_admin=True)
        _add_user(db_session, "someone@example.com", is_admin=True)
        alert_id = _create_alert(db_session, "ack-idem")
        service = AlertService()
        with db_session() as db:
            first_ack_at = service.acknowledge(db, alert_id, "admin@example.com", None).ack_at
        with db_session() as db:
            second = service.acknowledge(db, alert_id, "someone@example.com", None)
            assert second.status == "acknowledged"
            assert second.ack_by == "admin@example.com"
            assert second.ack_at == first_ack_at

    def test_acknowledge_after_resolve_is_a_transition_error(self, alerting_settings, db_session):
        """A resolved alert cannot be acknowledged afterwards."""
        _add_user(db_session, "admin@example.com", is_admin=True)
        alert_id = _create_alert(db_session, "resolved-then-ack")
        service = AlertService()
        with db_session() as db:
            service.resolve(db, alert_id, "admin@example.com", None)
        with db_session() as db:
            with pytest.raises(AlertTransitionError, match="transition not allowed"):
                service.acknowledge(db, alert_id, "admin@example.com", None)

    def test_resolve_twice_keeps_original_resolver(self, alerting_settings, db_session):
        """Resolving an already resolved alert is a no-op and keeps the first resolver."""
        _add_user(db_session, "admin@example.com", is_admin=True)
        _add_user(db_session, "other@example.com", is_admin=True)
        alert_id = _create_alert(db_session, "resolve-idem")
        service = AlertService()
        with db_session() as db:
            service.resolve(db, alert_id, "admin@example.com", None)
        with db_session() as db:
            again = service.resolve(db, alert_id, "other@example.com", None)
            assert again.status == "resolved"
            assert again.resolved_by == "admin@example.com"

    def test_suppressed_alert_cannot_be_acknowledged(self, alerting_settings, db_session):
        """Suppressed is terminal: acknowledging a suppressed alert is a transition error."""
        _add_user(db_session, "admin@example.com", is_admin=True)
        alert_id = _create_alert(db_session, "suppressed-terminal")
        with db_session() as db:
            db.execute(Alert.__table__.update().where(Alert.id == alert_id).values(status="suppressed"))
            db.commit()
        with db_session() as db:
            with pytest.raises(AlertTransitionError):
                AlertService().acknowledge(db, alert_id, "admin@example.com", None)

    def test_acknowledge_unknown_alert_is_not_found(self, alerting_settings, db_session):
        """An unknown alert ID raises not-found, not a transition error."""
        _add_user(db_session, "admin@example.com", is_admin=True)
        with db_session() as db:
            with pytest.raises(AlertNotFoundError, match="alert not found"):
                AlertService().acknowledge(db, "does-not-exist", "admin@example.com", None)

    def test_team_alert_is_not_found_for_caller_in_other_team(self, alerting_settings, db_session):
        """A caller scoped to a different team gets not-found for a team alert, with no existence leak."""
        alert_id = _create_alert(db_session, "team-x", team_id="team-x")
        with db_session() as db:
            with pytest.raises(AlertNotFoundError, match="alert not found"):
                AlertService().get_alert(db, alert_id, "member@example.com", ["team-y"])

    def test_global_alert_is_not_found_for_team_scoped_caller(self, alerting_settings, db_session):
        """A global alert is hidden from a non-admin caller even when they hold a team scope."""
        _add_user(db_session, "member@example.com")
        alert_id = _create_alert(db_session, "global-hidden")
        with db_session() as db:
            with pytest.raises(AlertNotFoundError):
                AlertService().get_alert(db, alert_id, "member@example.com", ["team-y"])

    def test_resolve_by_dedup_key_resolves_matching_alert(self, alerting_settings, db_session):
        """Recovery resolves the open alert with the dedup key, records the system actor and returns 1."""
        _add_user(db_session, "admin@example.com", is_admin=True)
        _create_alert(db_session, "recover-key")
        assert AlertService().resolve_by_dedup_key("recover-key") == 1
        with db_session() as db:
            alert = db.execute(select(Alert).where(Alert.dedup_key == "recover-key")).scalar_one()
        assert alert.status == "resolved"
        assert alert.resolved_by == "system"

    def test_resolve_by_dedup_key_with_blank_key_returns_zero(self, alerting_settings, db_session):
        """A blank dedup key matches nothing and returns zero without raising."""
        assert AlertService().resolve_by_dedup_key("   ") == 0


class TestBulkAndListing:
    """Bulk actions and list, filter and pagination behaviour."""

    def test_bulk_over_100_ids_is_rejected(self, alerting_settings, db_session):
        """More than 100 IDs in one bulk call is a validation error and nothing is processed."""
        with db_session() as db:
            with pytest.raises(AlertValidationError, match="at most 100"):
                AlertService().bulk_action(db, "acknowledge", [f"id-{i}" for i in range(101)], "admin@example.com", None)

    def test_bulk_of_exactly_100_ids_is_accepted_and_reports_unknown_ids(self, alerting_settings, db_session):
        """Exactly 100 IDs is within the limit; unknown IDs are reported per item, not raised."""
        with db_session() as db:
            outcome = AlertService().bulk_action(db, "resolve", [f"id-{i}" for i in range(100)], "admin@example.com", None)
        assert outcome["processed"] == []
        assert len(outcome["failed"]) == 100
        assert all(item["reason"] == "not found" for item in outcome["failed"])

    def test_bulk_failure_does_not_stop_the_batch(self, alerting_settings, db_session):
        """A missing ID is reported in failed and the valid IDs around it are still acknowledged."""
        _add_user(db_session, "admin@example.com", is_admin=True)
        good_one = _create_alert(db_session, "bulk-good-1")
        good_two = _create_alert(db_session, "bulk-good-2")
        with db_session() as db:
            outcome = AlertService().bulk_action(db, "acknowledge", [good_one, "missing-id", good_two], "admin@example.com", None)
        assert sorted(outcome["processed"]) == sorted([good_one, good_two])
        assert outcome["failed"] == [{"id": "missing-id", "reason": "not found"}]

    def test_bulk_rejects_unknown_action(self, alerting_settings, db_session):
        """An action other than acknowledge or resolve is a validation error."""
        with db_session() as db:
            with pytest.raises(AlertValidationError, match="unknown bulk action"):
                AlertService().bulk_action(db, "delete", ["x"], "admin@example.com", None)

    def test_list_filter_by_severity_returns_only_matching_rows(self, alerting_settings, db_session):
        """Filtering by severity returns exactly the alerts of that severity."""
        _add_user(db_session, "admin@example.com", is_admin=True)
        _emit(dedup_key="f-high", severity="HIGH")
        _emit(dedup_key="f-low", severity="LOW")
        with db_session() as db:
            page = AlertService().list_alerts(db, "admin@example.com", None, filters=AlertFilters(severity="HIGH"))
        assert page.total == 1
        assert [item.severity for item in page.items] == ["HIGH"]

    def test_list_pagination_total_is_independent_of_page(self, alerting_settings, db_session):
        """Total counts every visible alert while each page holds only the requested slice."""
        _add_user(db_session, "admin@example.com", is_admin=True)
        for index in range(5):
            _emit(dedup_key=f"page-{index}")
        service = AlertService()
        with db_session() as db:
            first = service.list_alerts(db, "admin@example.com", None, limit=2, offset=0)
            tail = service.list_alerts(db, "admin@example.com", None, limit=2, offset=4)
        assert first.total == 5
        assert len(first.items) == 2
        assert len(tail.items) == 1

    def test_list_rejects_out_of_range_limit_and_negative_offset(self, alerting_settings, db_session):
        """Out-of-range paging values are validation errors."""
        with db_session() as db:
            with pytest.raises(AlertValidationError, match="limit must be between 1 and 200"):
                AlertService().list_alerts(db, "admin@example.com", None, limit=0)
            with pytest.raises(AlertValidationError, match="offset must be non-negative"):
                AlertService().list_alerts(db, "admin@example.com", None, offset=-1)

    def test_list_rejects_unknown_status_filter(self, alerting_settings, db_session):
        """An unknown status filter is a validation error."""
        with db_session() as db:
            with pytest.raises(AlertValidationError, match="unknown status filter"):
                AlertService().list_alerts(db, "admin@example.com", None, filters=AlertFilters(status="bogus"))

    def test_public_only_caller_sees_no_team_or_global_alerts(self, alerting_settings, db_session):
        """An empty team scope (public-only) sees no alerts, including global ones."""
        _add_user(db_session, "viewer@example.com")
        _emit(dedup_key="global-hidden-from-public")
        with db_session() as db:
            page = AlertService().list_alerts(db, "viewer@example.com", [])
        assert page.total == 0
        assert page.items == []


class TestPreferences:
    """Preference replacement rules."""

    def test_put_preferences_stores_the_supplied_entry(self, alerting_settings, db_session):
        """A valid replacement stores exactly the supplied entry for the caller."""
        _add_user(db_session, "user@example.com")
        with db_session() as db:
            rows = AlertService().put_preferences(db, "user@example.com", [{"scope": "global", "scope_value": "", "channel": "in_app", "min_severity": "HIGH", "enabled": True}])
        own = [row for row in rows if row.user_email == "user@example.com"]
        assert len(own) == 1
        assert own[0].min_severity == "HIGH"
        assert own[0].channel == "in_app"

    def test_invalid_entry_rejected_and_existing_rows_kept(self, alerting_settings, db_session):
        """An invalid entry is rejected before any write, so the previously stored row survives."""
        _add_user(db_session, "user@example.com")
        service = AlertService()
        with db_session() as db:
            service.put_preferences(db, "user@example.com", [{"scope": "global", "scope_value": "", "channel": "in_app", "min_severity": "LOW", "enabled": True}])
        with db_session() as db:
            with pytest.raises(AlertValidationError, match="unknown preference channel"):
                service.put_preferences(db, "user@example.com", [{"scope": "global", "scope_value": "", "channel": "sms", "min_severity": "LOW", "enabled": True}])
        with db_session() as db:
            remaining = db.execute(select(AlertPreference).where(AlertPreference.user_email == "user@example.com")).scalars().all()
        assert len(remaining) == 1
        assert remaining[0].channel == "in_app"

    def test_global_preference_with_scope_value_is_rejected(self, alerting_settings, db_session):
        """A global preference may not name a scope value."""
        with db_session() as db:
            with pytest.raises(AlertValidationError, match="global preferences must not set scope_value"):
                AlertService().put_preferences(db, "user@example.com", [{"scope": "global", "scope_value": "security", "channel": "in_app"}])

    def test_category_preference_must_name_a_known_source(self, alerting_settings, db_session):
        """A category preference must name a known alert source."""
        with db_session() as db:
            with pytest.raises(AlertValidationError, match="must name a known source"):
                AlertService().put_preferences(db, "user@example.com", [{"scope": "category", "scope_value": "weather", "channel": "in_app"}])

    def test_duplicate_entry_is_rejected(self, alerting_settings, db_session):
        """Two entries with the same scope, value and channel are rejected."""
        entry = {"scope": "global", "scope_value": "", "channel": "in_app", "min_severity": "LOW", "enabled": True}
        with db_session() as db:
            with pytest.raises(AlertValidationError, match="duplicate preference entry"):
                AlertService().put_preferences(db, "user@example.com", [entry, dict(entry)])

    def test_more_than_50_entries_is_rejected(self, alerting_settings, db_session):
        """More than 50 entries is a validation error."""
        entries = [{"scope": "category", "scope_value": "security", "channel": "in_app", "min_severity": "LOW"} for _ in range(51)]
        with db_session() as db:
            with pytest.raises(AlertValidationError, match="too many preference entries"):
                AlertService().put_preferences(db, "user@example.com", entries)


class TestEmitSafe:
    """Behaviour of the producer-facing helper, which must never raise."""

    def test_emit_alert_safe_does_not_open_a_session_when_flag_off(self, monkeypatch):
        """With alerting off the helper returns before any database access."""
        monkeypatch.setattr(alert_service_module.settings, "alerting_enabled", False, raising=False)
        opened = []

        def _track_session():
            """Record that a session was requested.

            Raises:
                AssertionError: Always, because no session may be opened when alerting is off.
            """
            opened.append(True)
            raise AssertionError("a session must not be opened when alerting is off")

        with patch.object(alert_service_module, "SessionLocal", _track_session):
            emit_alert_safe(source="security", type="x", severity="HIGH", entity_type=None, entity_id=None, team_id=None, dedup_key="k", title="t", body="b")
        assert opened == []

    def test_emit_alert_safe_swallows_unexpected_service_errors(self, alerting_settings, monkeypatch):
        """A failing service emit never propagates to the producing operation, and the failure is logged."""

        class _ExplodingService:
            """Service stand-in whose emit raises an unexpected error."""

            def emit(self, **_kwargs):
                """Raise an unexpected error.

                Raises:
                    RuntimeError: Always.
                """
                raise RuntimeError("unexpected")

        monkeypatch.setattr(alert_service_module, "get_alert_service", _ExplodingService)
        with patch.object(alert_service_module.logger, "warning") as warned:
            emit_alert_safe(source="security", type="x", severity="HIGH", entity_type=None, entity_id=None, team_id=None, dedup_key="k", title="t", body="b")
        assert warned.called
