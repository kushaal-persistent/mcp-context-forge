# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/services/alert_delivery.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Alert delivery outbox, channel adapters and dispatcher (Issue #5805).

``AlertService.emit()`` writes one ``alert_deliveries`` row per recipient and
channel in the same transaction as the alert itself. This module drains that
outbox:

* :class:`AlertDispatcher` runs as a background task and only acts on the
  primary worker (:func:`mcpgateway.utils.primary_worker.is_primary_worker`).
  Each tick selects due ``pending`` rows by ``(state, next_attempt_at)``, claims
  each row with a conditional ``UPDATE`` that moves its ``next_attempt_at`` into
  a lease, then hands it to the matching :class:`ChannelAdapter`. The claim is
  portable: it does not use ``SKIP LOCKED``, so it works on SQLite and PostgreSQL.
* :class:`InAppAdapter` pushes a compact event through :class:`EventService`.
  Persistence happens before the push, so a push failure never loses an alert.
  Redis is optional. Without it, the local queue fallback keeps the push path working.

Delivery is at-least-once. A worker that crashes after a successful send but before
it records the result leaves the row leased. Another tick then re-sends it after
the lease expires. Email and webhook adapters, backoff, dead-lettering and
backpressure arrive in later phases; this module uses a fixed retry delay.
"""

# Standard
from abc import ABC, abstractmethod
import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

# Third-Party
from sqlalchemy import func, select, update
from sqlalchemy.exc import SQLAlchemyError

# First-Party
from mcpgateway.config import settings
from mcpgateway.db import Alert, AlertDelivery, SessionLocal, utc_now
from mcpgateway.services.event_service import EventService
from mcpgateway.services.metrics import (
    ALERT_CHANNELS,
    alert_deliveries_total,
    alert_delivery_latency_seconds,
    alert_queue_depth,
    normalize_alert_label,
)
from mcpgateway.utils.primary_worker import is_primary_worker

logger = logging.getLogger(__name__)

ALERT_EVENT_CHANNEL = "mcpgateway:alerts"

STATE_PENDING = "pending"
STATE_SENT = "sent"
STATE_FAILED = "failed"

# Fixed delay before a failed attempt is retried. Backoff with jitter arrives with dead-lettering.
_RETRY_DELAY_SECONDS = 30
_ERROR_MAX_LENGTH = 500
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


# ---------------------------------------------------------------------------
# Value types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AlertSnapshot:
    """Read-only copy of the alert fields an adapter needs.

    Attributes:
        id: Alert identifier.
        source: Producer source (security, gateway_health, ...).
        type: Alert type within the source.
        severity: LOW, MEDIUM, HIGH or CRITICAL.
        title: Sanitised alert title.
        team_id: Owning team, or ``None`` for a global alert.
        created_at: Creation time (UTC).
    """

    id: str
    source: str
    type: str
    severity: str
    title: str
    team_id: Optional[str]
    created_at: datetime


@dataclass(frozen=True)
class DeliveryTask:
    """Read-only copy of one claimed ``alert_deliveries`` row.

    Attributes:
        delivery_id: Outbox row identifier.
        user_email: Recipient.
        channel: Delivery channel (``in_app``, ``email`` or ``webhook``).
        channel_id: External channel configuration identifier, if any.
        attempts: Attempts recorded before this one.
    """

    delivery_id: str
    user_email: str
    channel: str
    channel_id: Optional[str]
    attempts: int


@dataclass(frozen=True)
class DeliveryResult:
    """Outcome of one adapter send.

    Attributes:
        ok: True when the message was delivered.
        error: Short, generic failure reason (never internal detail).
        retryable: False marks the failure as permanent, so the row is failed at once.
    """

    ok: bool
    error: Optional[str] = None
    retryable: bool = True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc(value: datetime) -> datetime:
    """Return a timezone-aware UTC datetime. SQLite returns naive values, which are treated as UTC.

    Args:
        value: Datetime read from the database.

    Returns:
        datetime: Timezone-aware UTC datetime.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _sanitize_error(error: Optional[str]) -> Optional[str]:
    """Strip control characters and bound the length of a recorded error.

    Args:
        error: Raw error text supplied by an adapter.

    Returns:
        Optional[str]: Cleaned text, or ``None`` when nothing remains.
    """
    if not error:
        return None
    text = _CONTROL_CHARS.sub("", str(error)).strip()
    return text[:_ERROR_MAX_LENGTH] or None


def _is_primary() -> bool:
    """Return whether this worker is the primary. Any failure counts as non-primary.

    Returns:
        bool: True only when the primary-worker election confirms this worker.
    """
    try:
        return bool(is_primary_worker())
    except Exception:  # pylint: disable=broad-exception-caught
        logger.warning("Primary-worker check failed; treating this worker as non-primary", exc_info=True)
        return False


def build_in_app_event(delivery: DeliveryTask, alert: AlertSnapshot) -> Dict[str, Any]:
    """Build the compact in-app push event.

    The event carries no body and no metadata. ``user_email`` lets the stream
    filter events per recipient. ``cursor`` is the outbox row identifier, which
    a stream can map back to a row for ``Last-Event-ID`` catch-up.

    Args:
        delivery: Claimed outbox row.
        alert: Alert the row belongs to.

    Returns:
        Dict[str, Any]: JSON-serialisable event payload.
    """
    return {
        "type": "alert",
        "cursor": delivery.delivery_id,
        "delivery_id": delivery.delivery_id,
        "alert_id": alert.id,
        "user_email": delivery.user_email,
        "severity": alert.severity,
        "title": alert.title,
        "team_id": alert.team_id,
        "created_at": _utc(alert.created_at).isoformat(),
    }


# ---------------------------------------------------------------------------
# Channel adapters
# ---------------------------------------------------------------------------


class ChannelAdapter(ABC):
    """Interface implemented by every delivery channel.

    Subclasses set :attr:`channel` and implement :meth:`send`. The dispatcher calls
    :meth:`send` and records the outcome. Adapters must not write to the database.
    """

    channel: str = ""

    @abstractmethod
    async def send(self, delivery: DeliveryTask, alert: AlertSnapshot) -> DeliveryResult:
        """Deliver one alert to one recipient over this channel.

        Args:
            delivery: Claimed outbox row.
            alert: Alert being delivered.

        Returns:
            DeliveryResult: Outcome of the attempt.
        """


class InAppAdapter(ChannelAdapter):
    """Pushes an alert event to live in-app subscribers through :class:`EventService`."""

    channel = "in_app"

    def __init__(self, event_service: EventService) -> None:
        """Initialise the adapter.

        Args:
            event_service: Event bus used for the live push.
        """
        self._event_service = event_service

    async def send(self, delivery: DeliveryTask, alert: AlertSnapshot) -> DeliveryResult:
        """Publish the compact event. The alert already exists in the inbox, so a failure here is retryable.

        Args:
            delivery: Claimed outbox row.
            alert: Alert being delivered.

        Returns:
            DeliveryResult: Success, or a retryable ``push_failed`` result.
        """
        if delivery.channel != self.channel:
            return DeliveryResult(ok=False, error="channel_mismatch", retryable=False)
        try:
            await self._event_service.publish_event(build_in_app_event(delivery, alert))
        except Exception:  # pylint: disable=broad-exception-caught
            logger.warning("In-app push failed for delivery %s; the alert remains in the inbox", delivery.delivery_id, exc_info=True)
            return DeliveryResult(ok=False, error="push_failed", retryable=True)
        return DeliveryResult(ok=True)


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


class AlertDispatcher:
    """Background worker that drains the ``alert_deliveries`` outbox on the primary worker."""

    def __init__(
        self,
        adapters: Optional[Dict[str, ChannelAdapter]] = None,
        event_service: Optional[EventService] = None,
    ) -> None:
        """Initialise the dispatcher.

        Args:
            adapters: Channel name to adapter. Defaults to the in-app adapter only.
            event_service: Event bus for the default in-app adapter. Defaults to the shared service.
        """
        self._event_service = event_service if event_service is not None else get_alert_event_service()
        if adapters is None:
            adapters = {InAppAdapter.channel: InAppAdapter(self._event_service)}
        self._adapters: Dict[str, ChannelAdapter] = dict(adapters)
        self._task: Optional["asyncio.Task[None]"] = None

    async def start(self) -> None:
        """Initialise the event bus and start the polling loop. Idempotent. Does nothing when alerting is disabled."""
        if not getattr(settings, "alerting_enabled", False):
            logger.info("Alert dispatcher not started: alerting_enabled is false")
            return
        if self._task is not None and not self._task.done():
            return
        await self._event_service.initialize()
        self._task = asyncio.create_task(self._loop(), name="alert-dispatcher")
        logger.info("Alert dispatcher started (poll=%ss, batch=%s)", settings.alerting_dispatch_poll_seconds, settings.alerting_dispatch_batch_size)

    async def stop(self) -> None:
        """Cancel the polling loop and wait for it to finish. Idempotent."""
        task = self._task
        self._task = None
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        logger.info("Alert dispatcher stopped")

    async def shutdown(self) -> None:
        """Shutdown hook used by the application lifespan (matches ``shutdown_services``)."""
        await self.stop()

    async def _loop(self) -> None:
        """Run :meth:`run_once` every poll interval until cancelled. Tick errors are logged and the loop continues."""
        while True:
            try:
                await self.run_once()
            except Exception:  # pylint: disable=broad-exception-caught
                logger.error("Alert dispatcher tick failed; retrying on the next poll", exc_info=True)
            await asyncio.sleep(int(settings.alerting_dispatch_poll_seconds))

    async def run_once(self) -> int:
        """Claim and deliver one batch of due deliveries.

        Returns:
            int: Number of deliveries claimed in this tick. Zero on a non-primary worker.
        """
        if not _is_primary():
            return 0

        claimed = await asyncio.to_thread(self._claim_due, utc_now())
        for delivery, alert in claimed:
            adapter = self._adapters.get(delivery.channel)
            if adapter is None:
                result = DeliveryResult(ok=False, error="no_adapter", retryable=False)
            else:
                try:
                    result = await adapter.send(delivery, alert)
                except Exception:  # pylint: disable=broad-exception-caught
                    logger.warning("Adapter %s raised while delivering %s", delivery.channel, delivery.delivery_id, exc_info=True)
                    result = DeliveryResult(ok=False, error="adapter_error", retryable=True)
            try:
                await asyncio.to_thread(self._record_result, delivery, alert, result)
            except Exception:  # pylint: disable=broad-exception-caught
                # The row stays leased and is re-sent after the lease expires (at-least-once).
                logger.error("Failed to record delivery result for %s; it will be retried after its lease", delivery.delivery_id, exc_info=True)

        await asyncio.to_thread(self._refresh_queue_depth)
        return len(claimed)

    @staticmethod
    def _claim_due(now: datetime) -> List[Tuple[DeliveryTask, AlertSnapshot]]:
        """Select due ``pending`` rows and claim each one with a conditional update.

        A row is claimed only when the conditional update matches exactly one row, so
        two workers cannot both claim it. The claim moves ``next_attempt_at`` into the
        lease window.

        Args:
            now: Evaluation time for due rows.

        Returns:
            List[Tuple[DeliveryTask, AlertSnapshot]]: Rows this worker now owns.

        Raises:
            SQLAlchemyError: On storage failure (the transaction is rolled back).
        """
        batch_size = int(settings.alerting_dispatch_batch_size)
        lease_until = now + timedelta(seconds=int(settings.alerting_delivery_lease_seconds))
        claimed: List[Tuple[DeliveryTask, AlertSnapshot]] = []

        db = SessionLocal()
        try:
            rows = db.execute(
                select(AlertDelivery, Alert)
                .join(Alert, Alert.id == AlertDelivery.alert_id)
                .where(AlertDelivery.state == STATE_PENDING, AlertDelivery.next_attempt_at <= now)
                .order_by(AlertDelivery.next_attempt_at, AlertDelivery.created_at)
                .limit(batch_size)
            ).all()

            for delivery_row, alert_row in rows:
                task = DeliveryTask(
                    delivery_id=delivery_row.id,
                    user_email=delivery_row.user_email,
                    channel=delivery_row.channel,
                    channel_id=delivery_row.channel_id,
                    attempts=int(delivery_row.attempts or 0),
                )
                snapshot = AlertSnapshot(
                    id=alert_row.id,
                    source=alert_row.source,
                    type=alert_row.type,
                    severity=alert_row.severity,
                    title=alert_row.title,
                    team_id=alert_row.team_id,
                    created_at=alert_row.created_at,
                )
                claim = db.execute(
                    update(AlertDelivery)
                    .where(
                        AlertDelivery.id == task.delivery_id,
                        AlertDelivery.state == STATE_PENDING,
                        AlertDelivery.next_attempt_at <= now,
                    )
                    .values(next_attempt_at=lease_until)
                    .execution_options(synchronize_session=False)
                )
                if claim.rowcount == 1:
                    claimed.append((task, snapshot))
            db.commit()
        except SQLAlchemyError:
            db.rollback()
            raise
        finally:
            db.close()
        return claimed

    @staticmethod
    def _record_result(delivery: DeliveryTask, alert: AlertSnapshot, result: DeliveryResult) -> None:
        """Persist the outcome of one attempt and update metrics.

        On success the row becomes ``sent``. On failure the attempt count increases.
        The row becomes ``failed`` when the failure is permanent or the attempt
        limit is reached. Otherwise it is rescheduled after a fixed delay.

        Args:
            delivery: Claimed outbox row.
            alert: Alert the row belongs to (used for latency).
            result: Adapter outcome.

        Raises:
            SQLAlchemyError: On storage failure (the transaction is rolled back).
        """
        now = utc_now()
        attempts = delivery.attempts + 1
        channel_label = normalize_alert_label(delivery.channel, ALERT_CHANNELS)

        db = SessionLocal()
        try:
            if result.ok:
                values: Dict[str, Any] = {
                    "state": STATE_SENT,
                    "attempts": attempts,
                    "sent_at": now,
                    "last_error": None,
                }
            else:
                exhausted = (not result.retryable) or attempts >= int(settings.alerting_delivery_max_attempts)
                values = {"attempts": attempts, "last_error": _sanitize_error(result.error)}
                if exhausted:
                    values["state"] = STATE_FAILED
                else:
                    values["next_attempt_at"] = now + timedelta(seconds=_RETRY_DELAY_SECONDS)

            db.execute(
                update(AlertDelivery)
                .where(AlertDelivery.id == delivery.delivery_id, AlertDelivery.state == STATE_PENDING)
                .values(**values)
                .execution_options(synchronize_session=False)
            )
            db.commit()
        except SQLAlchemyError:
            db.rollback()
            raise
        finally:
            db.close()

        if result.ok:
            alert_deliveries_total.labels(channel=channel_label, result="sent").inc()
            latency = (now - _utc(alert.created_at)).total_seconds()
            alert_delivery_latency_seconds.labels(channel=channel_label).observe(max(0.0, latency))
        else:
            alert_deliveries_total.labels(channel=channel_label, result="failed").inc()

    @staticmethod
    def _refresh_queue_depth() -> None:
        """Set the ``alert_queue_depth`` gauge to the number of ``pending`` deliveries."""
        db = SessionLocal()
        try:
            depth = db.execute(select(func.count()).select_from(AlertDelivery).where(AlertDelivery.state == STATE_PENDING)).scalar() or 0
        finally:
            db.close()
        alert_queue_depth.set(int(depth))


# ---------------------------------------------------------------------------
# Singletons
# ---------------------------------------------------------------------------

_event_service_singleton: Optional[EventService] = None
_dispatcher_singleton: Optional[AlertDispatcher] = None


def get_alert_event_service() -> EventService:
    """Return the shared event bus for alert pushes. The dispatcher and the stream endpoint both use it.

    Returns:
        EventService: The shared ``mcpgateway:alerts`` event service.
    """
    global _event_service_singleton  # pylint: disable=global-statement
    if _event_service_singleton is None:
        _event_service_singleton = EventService(ALERT_EVENT_CHANNEL)
    return _event_service_singleton


def get_alert_dispatcher() -> AlertDispatcher:
    """Return the process-wide :class:`AlertDispatcher`.

    Returns:
        AlertDispatcher: The shared dispatcher.
    """
    global _dispatcher_singleton  # pylint: disable=global-statement
    if _dispatcher_singleton is None:
        _dispatcher_singleton = AlertDispatcher()
    return _dispatcher_singleton
