# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/services/test_alert_producers_security_gateway.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Tests for the security and gateway-health alert producers (Issue #5805).

The producers call ``emit_alert_safe`` and write to a real in-memory SQLite
database. Only the database boundary is substituted. The producers, the alert
service and the dedup logic all run for real.
"""

# Standard
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
import uuid

# Third-Party
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# First-Party
from mcpgateway.db import Alert, AlertDelivery, AlertPreference, Base, EmailTeamMember, EmailUser, Role, SecurityEvent, UserRole
from mcpgateway.services import alert_service as alert_service_module
from mcpgateway.services import gateway_service as gateway_module
from mcpgateway.services import security_logger as security_logger_module
from mcpgateway.services.security_logger import SecurityLogger

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


@pytest.fixture
def factory():
    """Create an in-memory SQLite database with the alerting and security tables."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=_TABLES)
    session_factory = sessionmaker(bind=engine)
    yield session_factory
    engine.dispose()


@pytest.fixture
def alerting_on(factory, monkeypatch):
    """Enable alerting for the security and gateway_health sources and route all DB access to the test database."""
    monkeypatch.setattr(alert_service_module, "SessionLocal", factory)
    monkeypatch.setattr(security_logger_module, "SessionLocal", factory)
    for name, value in {
        "alerting_enabled": True,
        "alerting_source_security_enabled": True,
        "alerting_source_gateway_health_enabled": True,
        "alerting_dedup_window_seconds": 300,
        "alerting_max_recipients": 1000,
        "security_threat_score_alert": 0.7,
        "security_failed_auth_threshold": 5,
    }.items():
        monkeypatch.setattr(alert_service_module.settings, name, value, raising=False)
        monkeypatch.setattr(security_logger_module.settings, name, value, raising=False)
    return factory


def _event(event_type="authentication_failure", threat_score=0.0, failed_attempts=0, severity="LOW", client_ip="10.0.0.9", category="authentication"):
    """Build a SecurityEvent-like object for the producer hook.

    Args:
        event_type: Event type value.
        threat_score: Threat score.
        failed_attempts: Recent failed attempts count.
        severity: Event severity string.
        client_ip: Client IP.
        category: Event category.

    Returns:
        SimpleNamespace: Object with the attributes ``_maybe_emit_alert`` reads.
    """
    return SimpleNamespace(
        id=str(uuid.uuid4()),
        event_type=event_type,
        threat_score=threat_score,
        failed_attempts_count=failed_attempts,
        severity=severity,
        client_ip=client_ip,
        category=category,
    )


def _persist_event(factory, event):
    """Insert a real SecurityEvent row matching a stand-in event, so the alert can write back to it.

    Args:
        factory: Session factory bound to the test database.
        event: Stand-in event with id, event_type, severity, category, client_ip and threat_score.
    """
    with factory() as db:
        db.add(
            SecurityEvent(
                id=event.id,
                event_type=event.event_type,
                severity=event.severity,
                category=event.category,
                client_ip=event.client_ip,
                description="auth event",
                threat_score=event.threat_score,
                failed_attempts_count=event.failed_attempts_count,
                alert_sent=False,
            )
        )
        db.commit()


def _alerts(factory):
    """Return all alert rows.

    Args:
        factory: Session factory bound to the test database.

    Returns:
        list[Alert]: Detached alert rows.
    """
    with factory() as db:
        rows = db.execute(select(Alert)).scalars().all()
        for row in rows:
            db.expunge(row)
        return rows


async def _drain_alert_tasks():
    """Wait for fire-and-forget alert emission tasks scheduled by ``emit_alert_safe``."""
    import asyncio  # pylint: disable=import-outside-toplevel

    pending = list(alert_service_module._pending_tasks)  # pylint: disable=protected-access
    if pending:
        await asyncio.gather(*pending)


class TestSecurityProducer:
    """Threshold logic in ``SecurityLogger._maybe_emit_alert``."""

    def test_threat_score_at_or_above_threshold_creates_alert_and_marks_event(self, alerting_on):
        """A threat score of 0.7 (the threshold) creates a security alert and sets alert_sent on the event."""
        logger = SecurityLogger()
        event = _event(threat_score=0.7, severity="HIGH")
        _persist_event(alerting_on, event)

        logger._maybe_emit_alert(event)  # pylint: disable=protected-access

        alerts = _alerts(alerting_on)
        assert len(alerts) == 1
        assert alerts[0].source == "security"
        assert alerts[0].severity == "HIGH"
        assert alerts[0].team_id is None
        assert alerts[0].security_event_id == event.id
        with alerting_on() as db:
            stored = db.execute(select(SecurityEvent).where(SecurityEvent.id == event.id)).scalar_one()
        assert stored.alert_sent is True
        assert stored.alert_sent_at is not None

    def test_threat_score_below_threshold_creates_no_alert(self, alerting_on):
        """A threat score of 0.69 is below the 0.7 threshold, so no alert is created."""
        logger = SecurityLogger()
        logger._maybe_emit_alert(_event(threat_score=0.69))  # pylint: disable=protected-access
        assert _alerts(alerting_on) == []

    def test_failed_auth_at_threshold_creates_alert(self, alerting_on):
        """Five recent authentication failures (the threshold) create an alert even at a low threat score."""
        logger = SecurityLogger()
        event = _event(event_type="authentication_failure", threat_score=0.1, failed_attempts=5)
        _persist_event(alerting_on, event)

        logger._maybe_emit_alert(event)  # pylint: disable=protected-access

        alerts = _alerts(alerting_on)
        assert len(alerts) == 1
        assert alerts[0].type == "authentication_failure"

    def test_failed_auth_below_threshold_creates_no_alert(self, alerting_on):
        """Four failures with a low threat score do not reach the failed-auth threshold."""
        logger = SecurityLogger()
        logger._maybe_emit_alert(_event(event_type="authentication_failure", threat_score=0.1, failed_attempts=4))  # pylint: disable=protected-access
        assert _alerts(alerting_on) == []

    def test_failure_count_is_ignored_for_non_auth_events(self, alerting_on):
        """The failed-auth rule only applies to authentication_failure events."""
        logger = SecurityLogger()
        logger._maybe_emit_alert(_event(event_type="rate_limit", threat_score=0.1, failed_attempts=50))  # pylint: disable=protected-access
        assert _alerts(alerting_on) == []

    def test_flag_off_touches_no_database(self, alerting_on, monkeypatch):
        """With alerting off the producer returns before any session is opened."""
        monkeypatch.setattr(security_logger_module.settings, "alerting_enabled", False, raising=False)
        opened = []

        def _track():
            """Record a session request.

            Raises:
                AssertionError: Always, since no session may open while alerting is off.
            """
            opened.append(True)
            raise AssertionError("no session when alerting is off")

        with patch.object(security_logger_module, "SessionLocal", _track):
            SecurityLogger()._maybe_emit_alert(_event(threat_score=1.0))  # pylint: disable=protected-access
        assert opened == []

    def test_source_flag_off_creates_no_alert(self, alerting_on, monkeypatch):
        """With alerting on but the security source flag off, a breaching event creates no alert."""
        monkeypatch.setattr(security_logger_module.settings, "alerting_source_security_enabled", False, raising=False)
        SecurityLogger()._maybe_emit_alert(_event(threat_score=0.95))  # pylint: disable=protected-access
        assert _alerts(alerting_on) == []

    def test_broken_emit_does_not_affect_the_caller(self, alerting_on, monkeypatch):
        """A failure inside the alert path is swallowed; the producing call still completes."""

        def _explode(**_kwargs):
            """Raise to simulate a broken emit.

            Raises:
                RuntimeError: Always.
            """
            raise RuntimeError("emit exploded")

        monkeypatch.setattr(alert_service_module, "emit_alert_safe", _explode)
        logger = SecurityLogger()
        # Must not raise.
        logger._maybe_emit_alert(_event(threat_score=0.99))  # pylint: disable=protected-access

    def test_repeated_breaches_from_one_ip_dedupe_to_one_alert(self, alerting_on):
        """Repeated breaches from the same IP and type share one dedup key, giving one alert with a count."""
        logger = SecurityLogger()
        for _ in range(3):
            logger._maybe_emit_alert(_event(threat_score=0.8, client_ip="10.1.1.1"))  # pylint: disable=protected-access
        alerts = _alerts(alerting_on)
        assert len(alerts) == 1
        assert alerts[0].count == 3
        assert alerts[0].dedup_key == "security:authentication_failure:10.1.1.1"


class TestGatewayHealthProducer:
    """``GatewayService._handle_gateway_failure`` raises an outage alert, and recovery resolves it."""

    @staticmethod
    def _gateway(gateway_id="gw-1", team_id="team-gw", name="gateway-one", reachable=True, enabled=True):
        """Build a gateway-shaped stand-in.

        Args:
            gateway_id: Gateway identifier.
            team_id: Owning team, or None.
            name: Display name.
            reachable: Reachability flag.
            enabled: Whether the gateway is enabled.

        Returns:
            SimpleNamespace: Object with the attributes the health path reads.
        """
        return SimpleNamespace(id=gateway_id, team_id=team_id, name=name, reachable=reachable, enabled=enabled, auth_query_params=None)

    @staticmethod
    def _service():
        """Build a GatewayService whose deactivation DB write is stubbed out.

        Returns:
            GatewayService: Service with ``set_gateway_state`` replaced by an AsyncMock.
        """
        service = gateway_module.GatewayService()
        service.set_gateway_state = AsyncMock(return_value=None)
        return service

    @pytest.mark.asyncio
    async def test_failure_at_threshold_emits_gateway_unhealthy_alert(self, alerting_on, monkeypatch):
        """Reaching the failure threshold emits an alert keyed gateway:<id>:unhealthy, scoped to the gateway's team."""
        monkeypatch.setattr(gateway_module, "GW_FAILURE_THRESHOLD", 2)
        service = self._service()
        gateway = self._gateway(gateway_id="gw-1", team_id="team-gw")

        with patch.object(gateway_module, "SessionLocal", alerting_on):
            await service._handle_gateway_failure(gateway, error=ConnectionError("refused"))  # pylint: disable=protected-access
            await service._handle_gateway_failure(gateway, error=ConnectionError("refused"))  # pylint: disable=protected-access
        await _drain_alert_tasks()

        alerts = _alerts(alerting_on)
        assert len(alerts) == 1
        assert alerts[0].source == "gateway_health"
        assert alerts[0].type == "gateway_unreachable"
        assert alerts[0].severity == "HIGH"
        assert alerts[0].dedup_key == "gateway:gw-1:unhealthy"
        assert alerts[0].team_id == "team-gw"
        assert alerts[0].entity_id == "gw-1"

    @pytest.mark.asyncio
    async def test_failure_below_threshold_emits_no_alert(self, alerting_on, monkeypatch):
        """A single failure below the threshold does not deactivate the gateway and raises no alert."""
        monkeypatch.setattr(gateway_module, "GW_FAILURE_THRESHOLD", 3)
        service = self._service()
        gateway = self._gateway(gateway_id="gw-2")

        with patch.object(gateway_module, "SessionLocal", alerting_on):
            await service._handle_gateway_failure(gateway, error=ConnectionError("refused"))  # pylint: disable=protected-access

        assert _alerts(alerting_on) == []
        service.set_gateway_state.assert_not_called()

    @pytest.mark.asyncio
    async def test_alert_body_carries_sanitised_error_not_raw_exception_text(self, alerting_on, monkeypatch):
        """The stored body uses the sanitised connection phrase, never raw library exception text."""
        monkeypatch.setattr(gateway_module, "GW_FAILURE_THRESHOLD", 1)
        service = self._service()
        gateway = self._gateway(gateway_id="gw-3")

        with patch.object(gateway_module, "SessionLocal", alerting_on):
            await service._handle_gateway_failure(gateway, error=ConnectionRefusedError(111, "Connection refused"))  # pylint: disable=protected-access
        await _drain_alert_tasks()

        alerts = _alerts(alerting_on)
        assert len(alerts) == 1
        assert alerts[0].body.endswith("Last error: connection refused")
        assert "Errno" not in alerts[0].body
        assert "Connection refused" not in alerts[0].body

    @pytest.mark.asyncio
    async def test_recovery_resolves_the_outage_alert(self, alerting_on, monkeypatch):
        """After a gateway recovers, the open outage alert with its dedup key is resolved."""
        monkeypatch.setattr(gateway_module, "GW_FAILURE_THRESHOLD", 1)
        service = self._service()
        gateway = self._gateway(gateway_id="gw-4")
        with patch.object(gateway_module, "SessionLocal", alerting_on):
            await service._handle_gateway_failure(gateway, error=ConnectionError("refused"))  # pylint: disable=protected-access
        await _drain_alert_tasks()

        from mcpgateway.services.alert_service import AlertService  # pylint: disable=import-outside-toplevel

        resolved = AlertService().resolve_by_dedup_key("gateway:gw-4:unhealthy", resolved_by="system")
        assert resolved == 1
        alerts = _alerts(alerting_on)
        assert alerts[0].status == "resolved"
        assert alerts[0].resolved_by == "system"

    @pytest.mark.asyncio
    async def test_flag_off_touches_no_database(self, alerting_on, monkeypatch):
        """With alerting off the failure path emits nothing and opens no alert session."""
        monkeypatch.setattr(alert_service_module.settings, "alerting_enabled", False, raising=False)
        monkeypatch.setattr(gateway_module, "GW_FAILURE_THRESHOLD", 1)
        service = self._service()
        gateway = self._gateway(gateway_id="gw-5")

        with patch.object(gateway_module, "SessionLocal", alerting_on):
            await service._handle_gateway_failure(gateway, error=ConnectionError("refused"))  # pylint: disable=protected-access

        assert _alerts(alerting_on) == []
