# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/services/test_alert_delivery_inapp.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Tests for the alert delivery outbox, the in-app adapter and the dispatcher (Issue #5805).

Each test uses a real in-memory SQLite database. ``SessionLocal`` is patched in the
delivery and service modules. The event bus is replaced by a recording fake, so no
Redis connection is needed. Primary-worker election is controlled by patching
``_is_primary`` for the dispatcher module.
"""

# Standard
from datetime import timedelta

# Third-Party
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# First-Party
from mcpgateway.db import Alert, AlertDelivery, AlertPreference, Base, EmailTeamMember, EmailUser, Role, SecurityEvent, UserRole, utc_now
from mcpgateway.services import alert_delivery as delivery_module
from mcpgateway.services import alert_service as alert_service_module
from mcpgateway.services.alert_delivery import (
    AlertDispatcher,
    AlertSnapshot,
    ChannelAdapter,
    DeliveryResult,
    DeliveryTask,
    InAppAdapter,
    build_in_app_event,
)
from mcpgateway.services.alert_service import AlertService

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


class RecordingEventService:
    """Event bus stand-in that records every published event.

    Attributes:
        published: Events in publish order.
        fail: When True, ``publish_event`` raises to simulate a broken bus.
    """

    def __init__(self, fail=False):
        """Create an empty recorder.

        Args:
            fail: Whether publishing should fail.
        """
        self.published = []
        self.fail = fail
        self.initialize_calls = 0

    async def initialize(self):
        """Record an initialisation call."""
        self.initialize_calls += 1

    async def publish_event(self, event):
        """Record one event, or raise when configured to fail.

        Args:
            event: Event payload.

        Raises:
            ConnectionError: When ``fail`` is set.
        """
        if self.fail:
            raise ConnectionError("event bus unavailable")
        self.published.append(event)


class ScriptedAdapter(ChannelAdapter):
    """Channel adapter whose outcome is scripted per call.

    Attributes:
        channel: Channel name served by this adapter.
        results: Results returned in order; the last one repeats.
        calls: Number of ``send`` calls received.
    """

    channel = "email"

    def __init__(self, results):
        """Create the adapter.

        Args:
            results: List of :class:`DeliveryResult` values to return in order.
        """
        self.results = list(results)
        self.calls = 0

    async def send(self, delivery, alert):
        """Return the next scripted result.

        Args:
            delivery: Claimed outbox row.
            alert: Alert being delivered.

        Returns:
            DeliveryResult: The scripted outcome.
        """
        self.calls += 1
        index = min(self.calls - 1, len(self.results) - 1)
        return self.results[index]


@pytest.fixture
def factory():
    """Create an in-memory SQLite database with the alerting tables and return its session factory."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=_TABLES)
    session_factory = sessionmaker(bind=engine)
    yield session_factory
    engine.dispose()


@pytest.fixture
def patched(factory, monkeypatch):
    """Route both the service and the delivery module to the test database and enable alerting."""
    monkeypatch.setattr(alert_service_module, "SessionLocal", factory)
    monkeypatch.setattr(delivery_module, "SessionLocal", factory)
    monkeypatch.setattr(alert_service_module.settings, "alerting_enabled", True, raising=False)
    monkeypatch.setattr(alert_service_module.settings, "alerting_source_security_enabled", True, raising=False)
    monkeypatch.setattr(alert_service_module.settings, "alerting_dedup_window_seconds", 300, raising=False)
    monkeypatch.setattr(alert_service_module.settings, "alerting_max_recipients", 1000, raising=False)
    monkeypatch.setattr(delivery_module.settings, "alerting_dispatch_batch_size", 100, raising=False)
    monkeypatch.setattr(delivery_module.settings, "alerting_delivery_lease_seconds", 60, raising=False)
    monkeypatch.setattr(delivery_module.settings, "alerting_delivery_max_attempts", 3, raising=False)
    monkeypatch.setattr(delivery_module.settings, "alerting_dispatch_poll_seconds", 2, raising=False)
    return factory


def _add_admin(factory, email):
    """Insert an active administrator.

    Args:
        factory: Session factory bound to the test database.
        email: Administrator email.
    """
    with factory() as db:
        db.add(EmailUser(email=email, password_hash=None, full_name=email, is_admin=True, is_active=True))  # pragma: allowlist secret
        db.commit()


def _emit_one(dedup_key="delivery-case"):
    """Emit a global security alert to one admin and return the alert ID.

    Args:
        dedup_key: Dedup key for the alert.

    Returns:
        str: Alert identifier.
    """
    result = AlertService().emit(
        source="security",
        type="brute_force",
        severity="HIGH",
        entity_type=None,
        entity_id=None,
        team_id=None,
        dedup_key=dedup_key,
        title="Brute force detected",
        body="Repeated failed logins",
    )
    return result.alert_id


def _deliveries(factory, alert_id=None):
    """Return all in-app delivery rows, optionally for one alert.

    Args:
        factory: Session factory bound to the test database.
        alert_id: Optional alert filter.

    Returns:
        list[AlertDelivery]: Detached delivery rows.
    """
    with factory() as db:
        query = select(AlertDelivery)
        if alert_id is not None:
            query = query.where(AlertDelivery.alert_id == alert_id)
        rows = db.execute(query).scalars().all()
        for row in rows:
            db.expunge(row)
        return rows


def _task_and_snapshot():
    """Build a matching delivery task and alert snapshot for adapter tests.

    Returns:
        tuple[DeliveryTask, AlertSnapshot]: Ready-to-send pair.
    """
    task = DeliveryTask(delivery_id="d-1", user_email="admin@example.com", channel="in_app", channel_id=None, attempts=0)
    snapshot = AlertSnapshot(
        id="a-1",
        source="security",
        type="brute_force",
        severity="HIGH",
        title="Brute force detected",
        team_id=None,
        created_at=utc_now(),
    )
    return task, snapshot


class TestBuildInAppEvent:
    """The compact in-app push payload."""

    def test_event_carries_routing_fields_and_no_body(self):
        """The event holds the recipient, alert identifiers and title, and omits the body and metadata."""
        task, snapshot = _task_and_snapshot()
        event = build_in_app_event(task, snapshot)
        assert event["type"] == "alert"
        assert event["user_email"] == "admin@example.com"
        assert event["alert_id"] == "a-1"
        assert event["delivery_id"] == "d-1"
        assert event["cursor"] == "d-1"
        assert event["title"] == "Brute force detected"
        assert "body" not in event
        assert "metadata" not in event


class TestInAppAdapter:
    """The adapter pushes through the event service and reports results."""

    @pytest.mark.asyncio
    async def test_send_publishes_through_event_service(self):
        """A successful send publishes exactly one alert event through EventService."""
        bus = RecordingEventService()
        adapter = InAppAdapter(bus)
        task, snapshot = _task_and_snapshot()
        result = await adapter.send(task, snapshot)
        assert result == DeliveryResult(ok=True)
        assert len(bus.published) == 1
        assert bus.published[0]["alert_id"] == "a-1"
        assert bus.published[0]["user_email"] == "admin@example.com"

    @pytest.mark.asyncio
    async def test_push_failure_is_retryable_and_names_no_internal_detail(self):
        """A bus failure is reported as retryable push_failed, with no exception text leaking."""
        adapter = InAppAdapter(RecordingEventService(fail=True))
        task, snapshot = _task_and_snapshot()
        result = await adapter.send(task, snapshot)
        assert result.ok is False
        assert result.error == "push_failed"
        assert result.retryable is True
        assert "unavailable" not in (result.error or "")

    @pytest.mark.asyncio
    async def test_wrong_channel_is_a_permanent_failure(self):
        """A delivery routed to the wrong adapter is rejected as a non-retryable mismatch."""
        adapter = InAppAdapter(RecordingEventService())
        task, snapshot = _task_and_snapshot()
        mismatched = DeliveryTask(delivery_id="d-2", user_email="a@example.com", channel="email", channel_id=None, attempts=0)
        result = await adapter.send(mismatched, snapshot)
        assert result == DeliveryResult(ok=False, error="channel_mismatch", retryable=False)


class TestOutboxRows:
    """Delivery rows are created with the alert, before any push."""

    def test_emit_writes_pending_in_app_rows_for_each_recipient(self, patched):
        """Each recipient gets one pending in-app delivery row linked to the alert."""
        _add_admin(patched, "one@example.com")
        _add_admin(patched, "two@example.com")
        alert_id = _emit_one("two-recipients")

        rows = _deliveries(patched, alert_id)
        assert sorted(row.user_email for row in rows) == ["one@example.com", "two@example.com"]
        assert all(row.state == "pending" for row in rows)
        assert all(row.channel == "in_app" for row in rows)
        assert all(row.attempts == 0 for row in rows)

    def test_rows_exist_before_any_push_happens(self, patched):
        """Persistence happens first: rows exist when the event bus is never touched."""
        _add_admin(patched, "persist@example.com")
        bus = RecordingEventService(fail=True)
        AlertDispatcher(event_service=bus)
        alert_id = _emit_one("persist-first")

        assert len(_deliveries(patched, alert_id)) == 1
        assert bus.published == []


class TestDispatcher:
    """Primary-only polling, state transitions and retry rules."""

    @pytest.mark.asyncio
    async def test_non_primary_worker_does_nothing(self, patched, monkeypatch):
        """A non-primary worker claims nothing and leaves the row pending."""
        _add_admin(patched, "np@example.com")
        alert_id = _emit_one("non-primary")
        monkeypatch.setattr(delivery_module, "_is_primary", lambda: False)
        bus = RecordingEventService()
        claimed = await AlertDispatcher(event_service=bus).run_once()
        assert claimed == 0
        assert bus.published == []
        assert _deliveries(patched, alert_id)[0].state == "pending"

    @pytest.mark.asyncio
    async def test_primary_sends_and_marks_delivery_sent(self, patched, monkeypatch):
        """On the primary, a delivered row moves from pending to sent with a sent_at timestamp."""
        _add_admin(patched, "ok@example.com")
        alert_id = _emit_one("primary-sent")
        monkeypatch.setattr(delivery_module, "_is_primary", lambda: True)
        bus = RecordingEventService()

        claimed = await AlertDispatcher(event_service=bus).run_once()

        assert claimed == 1
        assert len(bus.published) == 1
        row = _deliveries(patched, alert_id)[0]
        assert row.state == "sent"
        assert row.sent_at is not None
        assert row.last_error is None

    @pytest.mark.asyncio
    async def test_three_simulated_workers_deliver_each_row_once(self, patched, monkeypatch):
        """Three dispatchers over the same outbox still yield exactly one push per row."""
        _add_admin(patched, "race@example.com")
        alert_id = _emit_one("three-workers")
        monkeypatch.setattr(delivery_module, "_is_primary", lambda: True)

        bus = RecordingEventService()
        dispatchers = [AlertDispatcher(event_service=bus) for _ in range(3)]
        counts = [await dispatcher.run_once() for dispatcher in dispatchers]

        assert sum(counts) == 1
        assert len(bus.published) == 1
        assert _deliveries(patched, alert_id)[0].state == "sent"

    @pytest.mark.asyncio
    async def test_run_without_redis_keeps_persistence_and_inbox_correct(self, patched, monkeypatch):
        """With no Redis, the local fallback bus still records the delivery and the inbox row stays correct."""
        _add_admin(patched, "noredis@example.com")
        alert_id = _emit_one("no-redis")
        monkeypatch.setattr(delivery_module, "_is_primary", lambda: True)
        bus = RecordingEventService()

        await AlertDispatcher(event_service=bus).run_once()

        row = _deliveries(patched, alert_id)[0]
        assert row.state == "sent"
        assert row.read_at is None
        assert bus.published[0]["alert_id"] == alert_id

    @pytest.mark.asyncio
    async def test_push_goes_through_the_event_service(self, patched, monkeypatch):
        """The default in-app adapter publishes via the supplied EventService."""
        _add_admin(patched, "via-bus@example.com")
        _emit_one("via-bus")
        monkeypatch.setattr(delivery_module, "_is_primary", lambda: True)
        bus = RecordingEventService()
        await AlertDispatcher(event_service=bus).run_once()
        assert [event["user_email"] for event in bus.published] == ["via-bus@example.com"]

    @pytest.mark.asyncio
    async def test_failing_adapter_increments_attempts_then_fails_at_limit(self, patched, monkeypatch):
        """Retryable failures increment attempts and reschedule; the limit makes the row failed."""
        _add_admin(patched, "retry@example.com")
        alert_id = _emit_one("retry-limit")
        monkeypatch.setattr(delivery_module, "_is_primary", lambda: True)

        # The row is claimed by in_app. Force its channel to a failing adapter so retries apply.
        failing = ScriptedAdapter([DeliveryResult(ok=False, error="smtp timeout", retryable=True)])
        dispatcher = AlertDispatcher(adapters={"email": failing}, event_service=RecordingEventService())
        with patched() as db:
            db.execute(AlertDelivery.__table__.update().where(AlertDelivery.alert_id == alert_id).values(channel="email"))
            db.commit()

        # Attempt 1: rescheduled, attempts=1.
        await dispatcher.run_once()
        row = _deliveries(patched, alert_id)[0]
        assert row.state == "pending"
        assert row.attempts == 1
        assert row.last_error == "smtp timeout"

        # Force the row due again, then attempts 2 and 3 (the configured limit).
        for expected_attempts in (2, 3):
            with patched() as db:
                db.execute(AlertDelivery.__table__.update().where(AlertDelivery.alert_id == alert_id).values(next_attempt_at=utc_now() - timedelta(seconds=1)))
                db.commit()
            await dispatcher.run_once()
            row = _deliveries(patched, alert_id)[0]
            assert row.attempts == expected_attempts

        assert row.state == "failed"
        assert row.last_error == "smtp timeout"
        assert failing.calls == 3

    @pytest.mark.asyncio
    async def test_permanent_failure_ends_immediately(self, patched, monkeypatch):
        """A non-retryable failure marks the row failed on the first attempt."""
        _add_admin(patched, "perm@example.com")
        alert_id = _emit_one("permanent")
        monkeypatch.setattr(delivery_module, "_is_primary", lambda: True)
        adapter = ScriptedAdapter([DeliveryResult(ok=False, error="bad recipient", retryable=False)])
        dispatcher = AlertDispatcher(adapters={"email": adapter}, event_service=RecordingEventService())
        with patched() as db:
            db.execute(AlertDelivery.__table__.update().where(AlertDelivery.alert_id == alert_id).values(channel="email"))
            db.commit()

        await dispatcher.run_once()
        row = _deliveries(patched, alert_id)[0]
        assert row.state == "failed"
        assert row.attempts == 1

    @pytest.mark.asyncio
    async def test_row_without_adapter_is_failed_as_no_adapter(self, patched, monkeypatch):
        """A channel with no registered adapter is failed permanently with a generic reason."""
        _add_admin(patched, "noadapter@example.com")
        alert_id = _emit_one("no-adapter")
        monkeypatch.setattr(delivery_module, "_is_primary", lambda: True)
        with patched() as db:
            db.execute(AlertDelivery.__table__.update().where(AlertDelivery.alert_id == alert_id).values(channel="webhook"))
            db.commit()

        await AlertDispatcher(adapters={"in_app": InAppAdapter(RecordingEventService())}, event_service=RecordingEventService()).run_once()
        row = _deliveries(patched, alert_id)[0]
        assert row.state == "failed"
        assert row.last_error == "no_adapter"

    @pytest.mark.asyncio
    async def test_start_is_a_noop_when_alerting_disabled(self, monkeypatch):
        """With the master flag off, start() does not initialise the bus or create a task."""
        monkeypatch.setattr(alert_service_module.settings, "alerting_enabled", False, raising=False)
        bus = RecordingEventService()
        dispatcher = AlertDispatcher(event_service=bus)
        await dispatcher.start()
        assert dispatcher._task is None  # pylint: disable=protected-access
        assert bus.initialize_calls == 0

    @pytest.mark.asyncio
    async def test_start_then_stop_is_idempotent(self, monkeypatch):
        """Start runs the loop once, a second start does not add a task, and stop cancels it."""
        monkeypatch.setattr(alert_service_module.settings, "alerting_enabled", True, raising=False)
        monkeypatch.setattr(delivery_module, "_is_primary", lambda: False)
        bus = RecordingEventService()
        dispatcher = AlertDispatcher(event_service=bus)
        await dispatcher.start()
        first_task = dispatcher._task  # pylint: disable=protected-access
        await dispatcher.start()
        assert dispatcher._task is first_task  # pylint: disable=protected-access
        assert bus.initialize_calls == 1
        await dispatcher.stop()
        assert dispatcher._task is None  # pylint: disable=protected-access
        await dispatcher.stop()


class TestPrimaryCheck:
    """The primary-worker check fails closed."""

    def test_primary_check_error_is_treated_as_non_primary(self, monkeypatch):
        """If the primary election raises, the worker is non-primary and nothing is claimed."""

        def _boom():
            """Raise to simulate a broken election.

            Raises:
                RuntimeError: Always.
            """
            raise RuntimeError("election broke")

        monkeypatch.setattr(delivery_module, "is_primary_worker", _boom)
        assert delivery_module._is_primary() is False  # pylint: disable=protected-access


class TestSingletonsAndSnapshots:
    """Singleton accessors and value-type immutability."""

    def test_alert_event_channel_is_fixed_name(self):
        """The alert event service uses the dedicated mcpgateway:alerts channel."""
        assert delivery_module.ALERT_EVENT_CHANNEL == "mcpgateway:alerts"

    def test_delivery_task_is_frozen(self):
        """Claimed rows are immutable snapshots."""
        task, _ = _task_and_snapshot()
        with pytest.raises(AttributeError):
            task.attempts = 9  # type: ignore[misc]

    def test_dispatcher_defaults_to_in_app_adapter_only(self):
        """Without explicit adapters the dispatcher routes in_app and nothing else."""
        dispatcher = AlertDispatcher(event_service=RecordingEventService())
        assert set(dispatcher._adapters) == {"in_app"}  # pylint: disable=protected-access
        assert isinstance(dispatcher._adapters["in_app"], InAppAdapter)  # pylint: disable=protected-access
