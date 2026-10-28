# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/test_alert_models.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Tests for the alerting ORM models and alerts.* permissions (Issue #5805).

Models are checked against a real SQLite database built from ``Base.metadata``.
Foreign-key cascade is verified by deleting a parent row, with SQLite foreign-key
enforcement turned on for the connection.
"""

# Standard
from datetime import datetime, timezone
import uuid

# Third-Party
from sqlalchemy import create_engine, event, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import pytest

# First-Party
from mcpgateway.db import Alert, AlertChannel, AlertDelivery, AlertPreference, Base, Permissions

_ALERT_TABLES = [Alert.__table__, AlertDelivery.__table__, AlertPreference.__table__, AlertChannel.__table__]


@pytest.fixture
def engine():
    """Create an in-memory SQLite engine with the alerting tables and foreign keys enforced."""
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)

    @event.listens_for(eng, "connect")
    def _enable_fk(dbapi_connection, _record):
        """Enable SQLite foreign-key enforcement on every new connection.

        Args:
            dbapi_connection: Raw DB-API connection.
            _record: Connection record (unused).
        """
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(eng, tables=_ALERT_TABLES)
    yield eng
    eng.dispose()


@pytest.fixture
def session(engine):
    """Yield a session bound to the in-memory database."""
    factory = sessionmaker(bind=engine)
    with factory() as db:
        yield db


def _now():
    """Return a timezone-aware UTC timestamp.

    Returns:
        datetime: Current time in UTC.
    """
    return datetime.now(timezone.utc)


def _alert(**overrides):
    """Build an Alert with all required columns populated.

    Args:
        **overrides: Column values to replace.

    Returns:
        Alert: Unsaved alert.
    """
    now = _now()
    values = {
        "id": uuid.uuid4().hex,
        "source": "security",
        "type": "brute_force",
        "severity": "HIGH",
        "status": "open",
        "title": "Brute force detected",
        "body": "Repeated failures",
        "dedup_key": f"k-{uuid.uuid4().hex}",
        "first_seen": now,
        "last_seen": now,
        "count": 1,
        "created_at": now,
        "updated_at": now,
    }
    values.update(overrides)
    return Alert(**values)


def _delivery(alert_id, **overrides):
    """Build an AlertDelivery for an alert.

    Args:
        alert_id: Parent alert identifier.
        **overrides: Column values to replace.

    Returns:
        AlertDelivery: Unsaved delivery row.
    """
    values = {
        "id": uuid.uuid4().hex,
        "alert_id": alert_id,
        "user_email": "admin@example.com",
        "channel": "in_app",
        "state": "pending",
        "attempts": 0,
        "next_attempt_at": _now(),
        "created_at": _now(),
    }
    values.update(overrides)
    return AlertDelivery(**values)


class TestAlertColumns:
    """The alerts table carries the PRD fields with the right nullability."""

    EXPECTED_COLUMNS = {
        "id",
        "source",
        "type",
        "severity",
        "status",
        "title",
        "body",
        "entity_type",
        "entity_id",
        "team_id",
        "dedup_key",
        "first_seen",
        "last_seen",
        "count",
        "created_at",
        "updated_at",
        "resolved_at",
        "resolved_by",
        "ack_by",
        "ack_at",
        "security_event_id",
        "metadata",
    }

    def test_alerts_table_has_all_prd_columns(self, engine):
        """The alerts table exposes every PRD column, with the JSON metadata stored under 'metadata'."""
        columns = {col["name"] for col in inspect(engine).get_columns("alerts")}
        assert columns == self.EXPECTED_COLUMNS

    def test_team_id_is_nullable_so_global_alerts_are_possible(self, engine):
        """team_id allows NULL, which marks a global (admin-only) alert."""
        cols = {col["name"]: col for col in inspect(engine).get_columns("alerts")}
        assert cols["team_id"]["nullable"] is True

    def test_global_alert_round_trips_with_null_team(self, session):
        """An alert with no team persists and reads back with team_id None."""
        alert = _alert(team_id=None)
        session.add(alert)
        session.commit()
        session.expire_all()
        loaded = session.execute(select(Alert).where(Alert.id == alert.id)).scalar_one()
        assert loaded.team_id is None
        assert loaded.status == "open"

    def test_metadata_attribute_maps_to_metadata_column(self, session):
        """The alert_metadata attribute reads and writes the 'metadata' column."""
        alert = _alert(alert_metadata={"threat_score": 0.9})
        session.add(alert)
        session.commit()
        session.expire_all()
        loaded = session.execute(select(Alert).where(Alert.id == alert.id)).scalar_one()
        assert loaded.alert_metadata == {"threat_score": 0.9}


class TestAlertIndexes:
    """Declared query indexes exist on each table."""

    def test_alert_team_status_created_index(self, engine):
        """The team, status and created index used by the inbox query exists."""
        indexes = {idx["name"]: idx["column_names"] for idx in inspect(engine).get_indexes("alerts")}
        assert indexes["idx_alerts_team_status_created"] == ["team_id", "status", "created_at"]

    def test_alert_dedup_status_index(self, engine):
        """The dedup lookup index covers dedup_key and status."""
        indexes = {idx["name"]: idx["column_names"] for idx in inspect(engine).get_indexes("alerts")}
        assert indexes["idx_alerts_dedup_status"] == ["dedup_key", "status"]

    def test_delivery_state_next_attempt_index_drives_the_dispatcher(self, engine):
        """The outbox poll index covers (state, next_attempt_at)."""
        indexes = {idx["name"]: idx["column_names"] for idx in inspect(engine).get_indexes("alert_deliveries")}
        assert indexes["idx_alert_deliveries_state_next"] == ["state", "next_attempt_at"]

    def test_delivery_user_read_index_supports_unread_counts(self, engine):
        """The inbox index covers (user_email, read_at)."""
        indexes = {idx["name"]: idx["column_names"] for idx in inspect(engine).get_indexes("alert_deliveries")}
        assert indexes["idx_alert_deliveries_user_read"] == ["user_email", "read_at"]


class TestPreferenceUniqueness:
    """alert_preferences rejects a duplicate (user, scope, scope_value, channel)."""

    def test_duplicate_preference_is_rejected(self, session):
        """Two rows with the same owner, scope, value and channel violate the unique constraint."""
        base = {"user_email": "u@example.com", "scope": "global", "scope_value": "", "channel": "in_app", "min_severity": "LOW", "enabled": True}
        session.add(AlertPreference(id=uuid.uuid4().hex, **base))
        session.commit()
        session.add(AlertPreference(id=uuid.uuid4().hex, **base))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

    def test_same_scope_different_channel_is_allowed(self, session):
        """The same scope for another channel is a distinct preference and is accepted."""
        session.add(AlertPreference(id=uuid.uuid4().hex, user_email="u@example.com", scope="global", scope_value="", channel="in_app", min_severity="LOW", enabled=True))
        session.add(AlertPreference(id=uuid.uuid4().hex, user_email="u@example.com", scope="global", scope_value="", channel="email", min_severity="LOW", enabled=True))
        session.commit()
        count = len(session.execute(select(AlertPreference).where(AlertPreference.user_email == "u@example.com")).scalars().all())
        assert count == 2


class TestCascadeDelete:
    """Deleting an alert removes its outbox rows."""

    def test_deleting_alert_cascades_to_deliveries(self, session):
        """Removing the parent alert removes its delivery rows and leaves other alerts' rows intact."""
        first = _alert()
        second = _alert()
        session.add_all([first, second])
        session.flush()
        session.add_all([_delivery(first.id), _delivery(first.id, user_email="other@example.com"), _delivery(second.id)])
        session.commit()

        session.execute(Alert.__table__.delete().where(Alert.id == first.id))
        session.commit()

        remaining = session.execute(select(AlertDelivery)).scalars().all()
        assert len(remaining) == 1
        assert remaining[0].alert_id == second.id

    def test_delivery_without_a_parent_alert_is_rejected(self, session):
        """A delivery pointing at a non-existent alert violates the foreign key."""
        session.add(_delivery("no-such-alert"))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


class TestAlertsPermissions:
    """The four alerts.* permission constants are defined and reachable through get_all_permissions()."""

    @pytest.mark.parametrize(
        "constant,value",
        [
            ("ALERTS_READ", "alerts.read"),
            ("ALERTS_ACKNOWLEDGE", "alerts.acknowledge"),
            ("ALERTS_MANAGE", "alerts.manage"),
            ("ALERTS_SUBSCRIBE", "alerts.subscribe"),
        ],
    )
    def test_constant_has_expected_string_value(self, constant, value):
        """Each constant equals its documented permission string."""
        assert getattr(Permissions, constant) == value

    def test_all_four_appear_in_get_all_permissions(self):
        """The reflective permission listing includes all four alerts permissions."""
        all_perms = Permissions.get_all_permissions()
        for value in ("alerts.read", "alerts.acknowledge", "alerts.manage", "alerts.subscribe"):
            assert value in all_perms

    def test_wildcard_is_not_listed_as_a_normal_permission(self):
        """The wildcard is excluded from the reflective listing, so admin bypass is not a grantable permission."""
        assert "*" not in Permissions.get_all_permissions()
