# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/routers/alerts.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Alerts API routers (Issue #5805).

Two routers live in this module:

* ``router`` (prefix ``/alerts``) is the user-facing inbox, preferences and
  live stream. It is mounted only on the versioned API as ``/v1/alerts`` and is
  never added to the deprecated unversioned alias router.
* ``admin_router`` (prefix ``/admin/alerts``) holds administrative endpoints. It
  is mounted in ``main.py`` behind ``enforce_admin_csrf``.

Handlers never read a team from the request body or query to widen access.
Scope comes from :func:`get_scoped_resource_access_context`. A foreign-team alert
returns 404 with a generic body, so the existence of other teams' alerts is not
revealed.

The SSE stream uses a composite cursor ``<created_at ISO>|<delivery id>`` built
from the ``alert_deliveries`` row. Catch-up replays rows ordered by that same
``(created_at, id)`` position, so each missed alert is delivered exactly once.
Database work in the stream runs in short-lived sessions on a worker thread,
never on a request session that would stay open for the life of the connection.
"""

# Standard
import asyncio
from collections import deque
from datetime import datetime, timezone
import json
import logging
from typing import Any, AsyncGenerator, Deque, Dict, List, Optional, Set, Tuple

# Third-Party
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.auth_context import get_scoped_resource_access_context
from mcpgateway.config import settings
from mcpgateway.db import Alert, AlertDelivery, AlertPreference, SessionLocal, get_db
from mcpgateway.middleware.rbac import get_current_user_with_permissions, require_permission
from mcpgateway.schemas_alerts import (
    AlertAckRequest,
    AlertBulkRequest,
    AlertBulkResponse,
    AlertListResponse,
    AlertPreferenceRecord,
    AlertPreferencesResponse,
    AlertPreferencesUpdate,
    AlertResponse,
    AlertStatusResponse,
)
from mcpgateway.services.alert_delivery import get_alert_dispatcher, get_alert_event_service
from mcpgateway.services.alert_service import AlertError, AlertFilters, AlertNotFoundError, AlertPage, AlertTransitionError, AlertValidationError, DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT, get_alert_service
from mcpgateway.services.metrics import ALERT_SOURCES
from mcpgateway.utils.admin_check import is_admin_bypass_granted

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/alerts", tags=["Alerts"])
admin_router = APIRouter(prefix="/admin/alerts", tags=["Alerts Admin"])

# Keepalive interval for the SSE stream, in seconds.
_STREAM_KEEPALIVE_SECONDS = 15
# Rows replayed per catch-up query so a long reconnect cannot exhaust memory.
_STREAM_CATCHUP_BATCH = 100
# Number of recently delivered identifiers remembered to suppress duplicates on the live stream.
_STREAM_SEEN_LIMIT = 1000

_ALERT_NOT_FOUND_DETAIL = "alert not found"
_TRANSITION_DETAIL = "transition not allowed for the current alert state"
_VALIDATION_DETAIL = "invalid request"
_AUTH_REQUIRED_DETAIL = "User authentication required"


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def _require_enabled() -> None:
    """Return 404 for every alerting route while the master flag is off.

    Raises:
        HTTPException: 404 when ``alerting_enabled`` is false.
    """
    if not getattr(settings, "alerting_enabled", False):
        raise HTTPException(status_code=404, detail="Not Found")


def _map_alert_error(exc: AlertError) -> HTTPException:
    """Map an alert service error to an HTTP exception with a generic message.

    Args:
        exc: Error raised by the alert service.

    Returns:
        HTTPException: 404 for not-found, 409 for a forbidden transition,
        422 for invalid input. Any other alert error is a 500 with no detail.
    """
    if isinstance(exc, AlertNotFoundError):
        return HTTPException(status_code=404, detail=_ALERT_NOT_FOUND_DETAIL)
    if isinstance(exc, AlertTransitionError):
        return HTTPException(status_code=409, detail=_TRANSITION_DETAIL)
    if isinstance(exc, AlertValidationError):
        return HTTPException(status_code=422, detail=_VALIDATION_DETAIL)
    logger.error("Unexpected alert service error: %s", type(exc).__name__)
    return HTTPException(status_code=500, detail="alert operation failed")


def _require_user_email(user_email: Optional[str]) -> str:
    """Return the caller identity or raise 401 when none is available.

    Args:
        user_email: Identity from the scope resolver.

    Returns:
        str: The caller identity.

    Raises:
        HTTPException: 401 when the caller has no identity.
    """
    if not user_email:
        raise HTTPException(status_code=401, detail=_AUTH_REQUIRED_DETAIL)
    return user_email


def _utc(value: datetime) -> datetime:
    """Return a timezone-aware UTC datetime. Naive values are treated as UTC.

    Args:
        value: Datetime from the database or an event.

    Returns:
        datetime: Timezone-aware UTC datetime.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _utc_iso(value: datetime) -> str:
    """Format a datetime as an ISO-8601 UTC string.

    Args:
        value: Datetime to format.

    Returns:
        str: ISO-8601 representation in UTC.
    """
    return _utc(value).isoformat()


def _format_cursor(created_at: datetime, delivery_id: str) -> str:
    """Build the composite ``Last-Event-ID`` cursor for a delivery row.

    Args:
        created_at: Delivery creation time.
        delivery_id: Delivery identifier.

    Returns:
        str: Cursor string accepted by :func:`_parse_cursor`.
    """
    return f"{_utc_iso(created_at)}|{delivery_id}"


def _parse_cursor(value: Optional[str]) -> Optional[Tuple[datetime, str]]:
    """Parse a ``Last-Event-ID`` cursor of the form ``<iso timestamp>|<delivery id>``.

    Args:
        value: Raw header value supplied by the client.

    Returns:
        Optional[Tuple[datetime, str]]: Parsed position, or ``None`` when absent or malformed.
    """
    if not value or "|" not in value:
        return None
    ts_text, delivery_id = value.split("|", 1)
    delivery_id = delivery_id.strip()
    if not delivery_id or len(delivery_id) > 64:
        return None
    try:
        ts = _utc(datetime.fromisoformat(ts_text.strip()))
    except ValueError:
        return None
    return ts, delivery_id


def _alert_to_response(alert: Alert, include_body: bool = True) -> AlertResponse:
    """Build the API response for an alert.

    Args:
        alert: Alert row.
        include_body: When False the body and metadata are omitted (list views).

    Returns:
        AlertResponse: Serialisable alert. ``metadata`` is the stored redacted copy.
    """
    return AlertResponse(
        id=alert.id,
        source=alert.source,
        type=alert.type,
        severity=alert.severity,
        status=alert.status,
        title=alert.title,
        body=alert.body if include_body else "",
        entity_type=alert.entity_type,
        entity_id=alert.entity_id,
        team_id=alert.team_id,
        dedup_key=alert.dedup_key,
        first_seen=alert.first_seen,
        last_seen=alert.last_seen,
        count=alert.count,
        created_at=alert.created_at,
        updated_at=alert.updated_at,
        resolved_at=alert.resolved_at,
        resolved_by=alert.resolved_by,
        ack_by=alert.ack_by,
        ack_at=alert.ack_at,
        security_event_id=alert.security_event_id,
        metadata=alert.alert_metadata if include_body else None,
    )


def _preference_to_record(pref: AlertPreference) -> AlertPreferenceRecord:
    """Build the API record for a stored preference row.

    Args:
        pref: Preference row. ``user_email IS NULL`` marks an administrator default.

    Returns:
        AlertPreferenceRecord: Serialisable preference.
    """
    return AlertPreferenceRecord(
        id=pref.id,
        scope=pref.scope,
        scope_value=pref.scope_value or "",
        channel=pref.channel,
        min_severity=pref.min_severity,
        enabled=pref.enabled,
        mute_until=pref.mute_until,
        quiet_hours=pref.quiet_hours,
        is_default=pref.user_email is None,
    )


class _SeenIds:
    """Bounded set of recently delivered identifiers, used to suppress duplicates on the live stream."""

    def __init__(self, limit: int) -> None:
        """Initialise an empty bounded set.

        Args:
            limit: Maximum number of identifiers remembered.
        """
        self._limit = limit
        self._order: Deque[str] = deque()
        self._members: Set[str] = set()

    def add(self, value: str) -> None:
        """Remember an identifier, evicting the oldest when the limit is reached.

        Args:
            value: Identifier to remember.
        """
        if value in self._members:
            return
        self._order.append(value)
        self._members.add(value)
        if len(self._order) > self._limit:
            self._members.discard(self._order.popleft())

    def __contains__(self, value: object) -> bool:
        """Return True when the identifier is remembered.

        Args:
            value: Identifier to test.

        Returns:
            bool: Membership result.
        """
        return value in self._members


def _event_visible(event: Dict[str, Any], user_email: str, token_teams: Optional[List[str]], unrestricted: bool) -> bool:
    """Decide whether a live push event may be forwarded to this stream subscriber.

    The event must be addressed to the caller and its team must be in scope.
    Global alerts (``team_id`` is None) reach unrestricted administrators only.

    Args:
        event: Event published by the in-app adapter.
        user_email: Subscriber identity.
        token_teams: Subscriber team scope.
        unrestricted: True for an unrestricted administrator.

    Returns:
        bool: True when the event should be forwarded.
    """
    if event.get("type") != "alert":
        return False
    if event.get("user_email") != user_email:
        return False
    if unrestricted:
        return True
    team_id = event.get("team_id")
    if team_id is None:
        return False
    return bool(token_teams) and team_id in token_teams


def _catchup_rows(user_email: str, token_teams: Optional[List[str]], unrestricted: bool, position: Optional[Tuple[datetime, str]]) -> List[Tuple[AlertDelivery, Alert]]:
    """Return up to one batch of the caller's in-app deliveries after a position.

    Runs on a short-lived session. Rows are ordered by ``(created_at, id)``. Team
    scope is enforced in the query, so a foreign-team alert is never replayed.

    Args:
        user_email: Recipient.
        token_teams: Caller team scope.
        unrestricted: True for an unrestricted administrator.
        position: Last delivered ``(created_at, id)``, or ``None`` to start at the beginning.

    Returns:
        List[Tuple[AlertDelivery, Alert]]: Matching delivery and alert pairs.
    """
    conditions = [AlertDelivery.user_email == user_email, AlertDelivery.channel == "in_app"]
    if not unrestricted:
        if not token_teams:
            return []
        conditions.append(Alert.team_id.in_(list(token_teams)))
    if position is not None:
        ts, delivery_id = position
        # Bind a naive UTC value: SQLite stores these datetimes without tzinfo, so an
        # aware literal could mis-order rows. PostgreSQL treats the naive value as UTC.
        ts_naive = ts.astimezone(timezone.utc).replace(tzinfo=None)
        conditions.append(or_(AlertDelivery.created_at > ts_naive, and_(AlertDelivery.created_at == ts_naive, AlertDelivery.id > delivery_id)))
    query = select(AlertDelivery, Alert).join(Alert, Alert.id == AlertDelivery.alert_id).where(and_(*conditions))
    query = query.order_by(AlertDelivery.created_at.asc(), AlertDelivery.id.asc()).limit(_STREAM_CATCHUP_BATCH)
    db = SessionLocal()
    try:
        return [(row[0], row[1]) for row in db.execute(query).all()]
    finally:
        db.close()


def _delivery_created_at(delivery_id: str) -> Optional[datetime]:
    """Look up the creation time of one delivery row, for building a live-event cursor.

    Args:
        delivery_id: Delivery identifier from the live event.

    Returns:
        Optional[datetime]: Creation time, or ``None`` when the row no longer exists.
    """
    db = SessionLocal()
    try:
        value = db.execute(select(AlertDelivery.created_at).where(AlertDelivery.id == delivery_id)).scalar_one_or_none()
        return _utc(value) if value is not None else None
    finally:
        db.close()


# ---------------------------------------------------------------------------
# User routes (/v1/alerts)
# Static paths are declared before /{alert_id} so they are not captured by it.
# ---------------------------------------------------------------------------


@router.get("", response_model=AlertListResponse)
@require_permission("alerts.read")
async def list_alerts(
    request: Request,
    status: Optional[str] = Query(None, description="Filter by lifecycle status"),
    severity: Optional[str] = Query(None, description="Filter by severity (LOW..CRITICAL)"),
    source: Optional[str] = Query(None, description="Filter by producer source"),
    unread: bool = Query(False, description="Only alerts with an unread in-app delivery"),
    page: int = Query(1, ge=1, description="1-based page number"),
    page_size: int = Query(DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT, description="Page size"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> AlertListResponse:
    """List alerts visible to the caller, newest first.

    Args:
        request: FastAPI request, used to derive the team scope.
        status: Optional status filter.
        severity: Optional severity filter.
        source: Optional source filter.
        unread: Restrict to alerts the caller has not read.
        page: 1-based page number.
        page_size: Page size (1..200).
        db: Database session.
        user: Authenticated caller.

    Returns:
        AlertListResponse: One page of alerts without bodies.

    Raises:
        HTTPException: 404 when alerting is disabled, 422 on invalid filters.
    """
    _require_enabled()
    user_email, token_teams = get_scoped_resource_access_context(request, user)
    filters = AlertFilters(status=status, severity=severity, source=source, unread_only=unread)
    offset = (page - 1) * page_size
    try:
        result: AlertPage = get_alert_service().list_alerts(db, user_email, token_teams, filters=filters, limit=page_size, offset=offset)
    except AlertError as exc:
        raise _map_alert_error(exc) from exc
    return AlertListResponse(
        items=[_alert_to_response(item, include_body=False) for item in result.items],
        total=result.total,
        page=page,
        page_size=page_size,
    )


@router.get("/stream")
@require_permission("alerts.read")
async def stream_alerts(
    request: Request,
    user=Depends(get_current_user_with_permissions),
) -> StreamingResponse:
    """Stream alert events for the caller over Server-Sent Events.

    When ``Last-Event-ID`` is sent, the stream first replays the caller's in-app
    deliveries created after that position, each exactly once, then switches to
    live events. A 15 second keepalive comment keeps idle connections open. Events
    are filtered to the caller's recipient and team scope. The stream holds no
    request database session.

    Args:
        request: FastAPI request, used for disconnect detection and the cursor header.
        user: Authenticated caller.

    Returns:
        StreamingResponse: ``text/event-stream`` response.

    Raises:
        HTTPException: 404 when alerting is disabled, 401 when the caller has no identity.
    """
    _require_enabled()
    user_email, token_teams = get_scoped_resource_access_context(request, user)
    user_email = _require_user_email(user_email)
    # Unrestricted only for an administrator with no token team restriction.
    unrestricted = await asyncio.to_thread(_is_unrestricted, user_email, token_teams)
    cursor = _parse_cursor(request.headers.get("last-event-id"))

    async def event_generator() -> AsyncGenerator[str, None]:
        """Yield catch-up deliveries, then live events and keepalives.

        Yields:
            str: SSE frames.
        """
        event_service = get_alert_event_service()
        queue: asyncio.Queue = asyncio.Queue()

        async def pump() -> None:
            """Forward published events into the local queue."""
            async for event in event_service.subscribe_events():
                await queue.put(event)

        # Subscribe before catch-up so no event published during replay is lost.
        pump_task = asyncio.create_task(pump())
        seen = _SeenIds(_STREAM_SEEN_LIMIT)
        try:
            position = cursor
            while True:
                rows = await asyncio.to_thread(_catchup_rows, user_email, token_teams, unrestricted, position)
                if not rows:
                    break
                for delivery, alert in rows:
                    cursor_value = _format_cursor(_utc(delivery.created_at), delivery.id)
                    seen.add(delivery.id)
                    payload = {
                        "type": "alert",
                        "cursor": cursor_value,
                        "delivery_id": delivery.id,
                        "alert_id": alert.id,
                        "severity": alert.severity,
                        "title": alert.title,
                        "team_id": alert.team_id,
                        "created_at": _utc_iso(alert.created_at),
                    }
                    yield f"id: {cursor_value}\nevent: alert\ndata: {json.dumps(payload, default=str, separators=(',', ':'))}\n\n"
                    position = (_utc(delivery.created_at), delivery.id)
                if len(rows) < _STREAM_CATCHUP_BATCH:
                    break

            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=_STREAM_KEEPALIVE_SECONDS)
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                if not _event_visible(event, user_email, token_teams, unrestricted):
                    continue
                delivery_id = str(event.get("delivery_id", ""))
                if not delivery_id or delivery_id in seen:
                    continue
                created_at = await asyncio.to_thread(_delivery_created_at, delivery_id)
                if created_at is None:
                    continue
                cursor_value = _format_cursor(created_at, delivery_id)
                seen.add(delivery_id)
                yield f"id: {cursor_value}\nevent: alert\ndata: {json.dumps(event, default=str, separators=(',', ':'))}\n\n"
        finally:
            pump_task.cancel()
            await asyncio.gather(pump_task, return_exceptions=True)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/preferences", response_model=AlertPreferencesResponse)
@require_permission("alerts.subscribe")
async def get_preferences(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> AlertPreferencesResponse:
    """Return the caller's preferences followed by inherited administrator defaults.

    Args:
        request: FastAPI request.
        db: Database session.
        user: Authenticated caller.

    Returns:
        AlertPreferencesResponse: Preference records.

    Raises:
        HTTPException: 404 when alerting is disabled, 401 when the caller has no identity.
    """
    _require_enabled()
    user_email, _token_teams = get_scoped_resource_access_context(request, user)
    user_email = _require_user_email(user_email)
    rows = get_alert_service().get_preferences(db, user_email)
    return AlertPreferencesResponse(items=[_preference_to_record(row) for row in rows])


@router.put("/preferences", response_model=AlertPreferencesResponse)
@require_permission("alerts.subscribe")
async def put_preferences(
    request: Request,
    payload: AlertPreferencesUpdate,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> AlertPreferencesResponse:
    """Replace the caller's preferences. The replacement is atomic.

    Args:
        request: FastAPI request.
        payload: Replacement entries (validated by the schema and the service).
        db: Database session.
        user: Authenticated caller.

    Returns:
        AlertPreferencesResponse: The stored preferences.

    Raises:
        HTTPException: 404 when alerting is disabled, 422 on invalid entries.
    """
    _require_enabled()
    user_email, _token_teams = get_scoped_resource_access_context(request, user)
    user_email = _require_user_email(user_email)
    entries = [item.model_dump() for item in payload.items]
    try:
        rows = get_alert_service().put_preferences(db, user_email, entries)
    except AlertError as exc:
        raise _map_alert_error(exc) from exc
    return AlertPreferencesResponse(items=[_preference_to_record(row) for row in rows])


@router.post("/bulk", response_model=AlertBulkResponse)
@require_permission("alerts.acknowledge")
async def bulk_alerts(
    request: Request,
    payload: AlertBulkRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> AlertBulkResponse:
    """Apply one action to up to 100 alerts. Each alert is processed independently.

    ``read`` marks the caller's in-app deliveries as read. ``ack`` and ``resolve``
    run the lifecycle transitions. Alerts outside the caller's scope or in a
    forbidden state are reported in ``failed`` with a generic reason.

    Args:
        request: FastAPI request.
        payload: Action and IDs (1..100; the schema rejects more with 422).
        db: Database session.
        user: Authenticated caller.

    Returns:
        AlertBulkResponse: Processed IDs and generic failures.

    Raises:
        HTTPException: 404 when alerting is disabled, 422 on invalid input.
    """
    _require_enabled()
    user_email, token_teams = get_scoped_resource_access_context(request, user)
    user_email = _require_user_email(user_email)
    service = get_alert_service()
    if payload.action == "read":
        processed: List[str] = []
        failed: List[Dict[str, str]] = []
        for alert_id in dict.fromkeys(payload.ids):
            try:
                service.mark_read(db, alert_id, user_email, token_teams)
                processed.append(alert_id)
            except AlertNotFoundError:
                db.rollback()
                failed.append({"id": alert_id, "reason": "not found"})
        return AlertBulkResponse(action="read", processed=processed, failed=failed)

    action = "acknowledge" if payload.action == "ack" else "resolve"
    try:
        result = service.bulk_action(db, action, payload.ids, user_email, token_teams)
    except AlertError as exc:
        raise _map_alert_error(exc) from exc
    return AlertBulkResponse(action=payload.action, processed=result["processed"], failed=result["failed"])


@router.get("/{alert_id}", response_model=AlertResponse)
@require_permission("alerts.read")
async def get_alert(
    alert_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> AlertResponse:
    """Return one visible alert, including its body and redacted metadata.

    Args:
        alert_id: Alert identifier.
        request: FastAPI request.
        db: Database session.
        user: Authenticated caller.

    Returns:
        AlertResponse: The alert.

    Raises:
        HTTPException: 404 when the alert is missing or not visible to the caller.
    """
    _require_enabled()
    user_email, token_teams = get_scoped_resource_access_context(request, user)
    try:
        alert = get_alert_service().get_alert(db, alert_id, user_email, token_teams)
    except AlertError as exc:
        raise _map_alert_error(exc) from exc
    return _alert_to_response(alert, include_body=True)


@router.post("/{alert_id}/ack", response_model=AlertResponse)
@require_permission("alerts.acknowledge")
async def acknowledge_alert(
    alert_id: str,
    request: Request,
    payload: Optional[AlertAckRequest] = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> AlertResponse:
    """Acknowledge an alert. Acknowledging an already acknowledged alert is idempotent.

    Args:
        alert_id: Alert identifier.
        request: FastAPI request.
        payload: Optional acknowledgement note. It is accepted for forward compatibility and not persisted in v1.
        db: Database session.
        user: Authenticated caller.

    Returns:
        AlertResponse: The updated alert.

    Raises:
        HTTPException: 404 when not visible, 409 when the transition is forbidden.
    """
    _require_enabled()
    user_email, token_teams = get_scoped_resource_access_context(request, user)
    user_email = _require_user_email(user_email)
    try:
        alert = get_alert_service().acknowledge(db, alert_id, user_email, token_teams)
    except AlertError as exc:
        raise _map_alert_error(exc) from exc
    return _alert_to_response(alert, include_body=True)


@router.post("/{alert_id}/resolve", response_model=AlertResponse)
@require_permission("alerts.acknowledge")
async def resolve_alert(
    alert_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> AlertResponse:
    """Resolve an alert. Resolving an already resolved alert is a no-op.

    Args:
        alert_id: Alert identifier.
        request: FastAPI request.
        db: Database session.
        user: Authenticated caller.

    Returns:
        AlertResponse: The updated alert.

    Raises:
        HTTPException: 404 when not visible, 409 when the transition is forbidden.
    """
    _require_enabled()
    user_email, token_teams = get_scoped_resource_access_context(request, user)
    user_email = _require_user_email(user_email)
    try:
        alert = get_alert_service().resolve(db, alert_id, user_email, token_teams)
    except AlertError as exc:
        raise _map_alert_error(exc) from exc
    return _alert_to_response(alert, include_body=True)


# ---------------------------------------------------------------------------
# Admin routes (/admin/alerts)
# ---------------------------------------------------------------------------


@admin_router.get("/status", response_model=AlertStatusResponse)
@require_permission("alerts.manage", allow_admin_bypass=False)
async def get_alerting_status(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user_with_permissions),
) -> AlertStatusResponse:
    """Return the alerting subsystem status: flags, active sources, dispatcher state and queue depth.

    Args:
        request: FastAPI request (kept for the common handler signature).
        db: Database session used for the queue-depth count.
        user: Authenticated caller holding ``alerts.manage``.

    Returns:
        AlertStatusResponse: Current status.
    """
    del request, user
    # 404 while the master flag is off, like every other alerting route.
    _require_enabled()
    enabled = True
    active_sources: List[str] = []
    if enabled:
        active_sources = [source for source in ALERT_SOURCES if getattr(settings, f"alerting_source_{source}_enabled", False)]
    pending = int(db.execute(select(func.count()).select_from(AlertDelivery).where(AlertDelivery.state == "pending")).scalar() or 0)
    dispatcher_running = False
    if enabled:
        task = getattr(get_alert_dispatcher(), "_task", None)  # pylint: disable=protected-access
        dispatcher_running = task is not None and not task.done()
    return AlertStatusResponse(
        alerting_enabled=enabled,
        active_sources=active_sources,
        dedup_window_seconds=int(settings.alerting_dedup_window_seconds),
        expiry_days=int(settings.alerting_expiry_days),
        retention_days=int(settings.alerting_retention_days),
        dispatcher_running=dispatcher_running,
        pending_deliveries=pending,
        queue_max_depth=int(settings.alerting_queue_max_depth),
    )


def _is_unrestricted(user_email: str, token_teams: Optional[List[str]]) -> bool:
    """Return whether the caller has unrestricted alert visibility, using a short-lived session.

    Delegates to :func:`is_admin_bypass_granted`, the single place that answers
    the visibility-bypass question. Narrowed tokens never bypass.

    Args:
        user_email: Caller identity.
        token_teams: Caller team scope (``None`` means unrestricted).

    Returns:
        bool: True when the caller is an unrestricted administrator.
    """
    db = SessionLocal()
    try:
        return bool(is_admin_bypass_granted(db, user_email, token_teams))
    finally:
        db.close()
