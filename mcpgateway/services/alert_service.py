# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/services/alert_service.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Alert service core (Issue #5805).

Owns the alert lifecycle: emission with deduplication, recipient resolution,
in-app preferences, acknowledge / resolve / bulk actions, team-scoped queries
and user preferences. Delivery (outbox dispatch) is handled by a separate
module in a later phase; this service writes ``alerts`` rows and the
``alert_deliveries`` outbox rows that the dispatcher will later process.

Design notes:

* ``emit()`` is synchronous and opens its own short-lived ``SessionLocal()``
  session. It never shares a request session.
* ``emit()`` raises :class:`AlertValidationError` only for invalid caller input.
  Storage failures are logged and reported through the result, never raised.
* ``emit_alert_safe()`` never raises. Producers on the request path call it;
  when the feature flag is off it returns immediately.
* Visibility follows the Layer-1 contract from
  :mod:`mcpgateway.utils.admin_check`: ``token_teams is None`` plus an
  administrator (or no identity) is the only bypass. ``[]`` is public-only and
  sees no team alerts. A non-empty list limits team alerts to those teams. A
  global alert (``team_id IS NULL``) is visible to unrestricted administrators only.
"""

# Standard
import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import json
import logging
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
import uuid

# Third-Party
from sqlalchemy import and_, delete, false, func, or_, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

# First-Party
from mcpgateway.config import settings
from mcpgateway.db import Alert, AlertDelivery, AlertPreference, EmailTeamMember, EmailUser, Permissions, Role, SecurityEvent, SessionLocal, UserRole, utc_now
from mcpgateway.services.metrics import (
    ALERT_OTHER_LABEL,
    ALERT_SEVERITIES,
    ALERT_SOURCES,
    alert_time_to_ack_seconds,
    alerts_created_total,
    alerts_deduplicated_total,
    alerts_open,
    normalize_alert_label,
)
from mcpgateway.utils.admin_check import is_admin_bypass_granted, is_user_admin

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Exceptions. Messages are deliberately generic (CWE-209): callers map these to
# HTTP responses, so internal detail must never be placed in the message.
# ---------------------------------------------------------------------------


class AlertError(Exception):
    """Base class for alert service errors."""


class AlertNotFoundError(AlertError):
    """The alert does not exist or is not visible to the caller (maps to 404)."""


class AlertTransitionError(AlertError):
    """The requested lifecycle transition is not allowed (maps to 409)."""


class AlertValidationError(AlertError):
    """Input failed validation (maps to 422)."""


class AlertChannelError(AlertError):
    """A delivery channel failed (raised by channel adapters in later phases)."""


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALERT_SOURCES_SET: Set[str] = set(ALERT_SOURCES)
ALERT_SEVERITY_ORDER: Dict[str, int] = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
ALERT_STATUS_OPEN = "open"
ALERT_STATUS_ACKNOWLEDGED = "acknowledged"
ALERT_STATUS_RESOLVED = "resolved"
ALERT_STATUS_EXPIRED = "expired"
ALERT_STATUS_SUPPRESSED = "suppressed"
ALERT_STATUSES: Set[str] = {ALERT_STATUS_OPEN, ALERT_STATUS_ACKNOWLEDGED, ALERT_STATUS_RESOLVED, ALERT_STATUS_EXPIRED, ALERT_STATUS_SUPPRESSED}

# Statuses that deduplication may merge into.
_DEDUP_ELIGIBLE_STATUSES: Tuple[str, ...] = (ALERT_STATUS_OPEN, ALERT_STATUS_ACKNOWLEDGED)

# Allowed lifecycle transitions: current status -> set of target statuses.
# Requesting the current status again is a no-op. Anything not listed is forbidden.
ALLOWED_TRANSITIONS: Dict[str, Set[str]] = {
    ALERT_STATUS_OPEN: {ALERT_STATUS_ACKNOWLEDGED, ALERT_STATUS_RESOLVED, ALERT_STATUS_EXPIRED, ALERT_STATUS_SUPPRESSED},
    ALERT_STATUS_ACKNOWLEDGED: {ALERT_STATUS_RESOLVED, ALERT_STATUS_EXPIRED, ALERT_STATUS_SUPPRESSED},
    ALERT_STATUS_RESOLVED: {ALERT_STATUS_SUPPRESSED},
    ALERT_STATUS_EXPIRED: {ALERT_STATUS_SUPPRESSED},
    ALERT_STATUS_SUPPRESSED: set(),
}

TITLE_MAX_LENGTH = 200
BODY_MAX_LENGTH = 4000
DEDUP_KEY_MAX_LENGTH = 255
BULK_ACTION_MAX_IDS = 100
PREFERENCES_MAX_ENTRIES = 50
METADATA_MAX_DEPTH = 5
METADATA_MAX_ITEMS = 50
METADATA_MAX_STRING = 500
METADATA_MAX_TOTAL_BYTES = 8192
SECURITY_EVENT_RECIPIENTS_CAP = 50
DEFAULT_LIST_LIMIT = 50
MAX_LIST_LIMIT = 200

_SENSITIVE_KEY_FRAGMENTS: Tuple[str, ...] = ("password", "authorization", "token", "secret", "api_key", "cookie")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_REDACTED = "***REDACTED***"

# Preference scopes and channels accepted by the API layer.
PREFERENCE_SCOPES: Set[str] = {"global", "category", "entity"}
PREFERENCE_CHANNELS: Set[str] = {"in_app", "email", "webhook"}


# ---------------------------------------------------------------------------
# Result and filter types
# ---------------------------------------------------------------------------


@dataclass
class AlertEmitResult:
    """Outcome of :meth:`AlertService.emit`.

    Attributes:
        alert_id: ID of the created or merged alert, or ``None`` when nothing was written.
        created: ``True`` when a new alert row was created.
        deduplicated: ``True`` when the emission was folded into an existing alert.
        recipient_count: Number of in-app delivery rows written for a new alert.
        skipped_reason: Why nothing was written (``alerting_disabled``, ``source_disabled``
            or ``storage_error``), otherwise ``None``.
    """

    alert_id: Optional[str] = None
    created: bool = False
    deduplicated: bool = False
    recipient_count: int = 0
    skipped_reason: Optional[str] = None


@dataclass
class AlertFilters:
    """Filters accepted by :meth:`AlertService.list_alerts`.

    Attributes:
        status: Restrict to one lifecycle status.
        severity: Restrict to one severity (LOW..CRITICAL).
        source: Restrict to one producer source.
        unread_only: Restrict to alerts the caller has not read in-app.
    """

    status: Optional[str] = None
    severity: Optional[str] = None
    source: Optional[str] = None
    unread_only: bool = False


@dataclass
class AlertPage:
    """A page of alerts, newest first.

    Attributes:
        items: Alerts on this page.
        total: Total number of visible alerts matching the filters.
        limit: Page size used.
        offset: Offset used.
    """

    items: List[Alert] = field(default_factory=list)
    total: int = 0
    limit: int = DEFAULT_LIST_LIMIT
    offset: int = 0


# ---------------------------------------------------------------------------
# Sanitisation helpers
# ---------------------------------------------------------------------------


def _is_sensitive_key(key: Any) -> bool:
    """Return True when a metadata key name looks like it holds a secret.

    Args:
        key: Metadata key (non-string keys are treated as non-sensitive).

    Returns:
        bool: True when the lower-cased key contains a sensitive fragment.
    """
    if not isinstance(key, str):
        return False
    lowered = key.lower()
    return any(fragment in lowered for fragment in _SENSITIVE_KEY_FRAGMENTS)


def _json_size(value: Any) -> int:
    """Return the size in bytes of a value serialised as compact JSON.

    Args:
        value: JSON-compatible value (non-serialisable items fall back to ``str``).

    Returns:
        int: Length of the UTF-8 encoded JSON.
    """
    return len(json.dumps(value, default=str, separators=(",", ":")).encode("utf-8"))


def redact_metadata(
    data: Any,
    *,
    max_depth: int = METADATA_MAX_DEPTH,
    max_items: int = METADATA_MAX_ITEMS,
    max_string: int = METADATA_MAX_STRING,
    max_total_bytes: int = METADATA_MAX_TOTAL_BYTES,
) -> Optional[Dict[str, Any]]:
    """Return a redacted, size-bounded copy of alert metadata.

    Keys containing ``password``, ``authorization``, ``token``, ``secret``,
    ``api_key`` or ``cookie`` (case-insensitive, at any depth) have their values
    replaced with a fixed marker. Recursion depth, item counts, string length and
    the serialised total size are capped. Non-dict input returns ``None``.

    Args:
        data: Metadata mapping to sanitise.
        max_depth: Nesting depth beyond which values are replaced with a marker.
        max_items: Maximum items kept per mapping or list.
        max_string: Maximum length of any string value.
        max_total_bytes: Maximum serialised size of the result.

    Returns:
        Optional[Dict[str, Any]]: A sanitised dict, or ``None`` if the input is not a dict.

    Examples:
        >>> redact_metadata({"password": "x", "gateway": "g1"})
        {'password': '***REDACTED***', 'gateway': 'g1'}
        >>> redact_metadata("not a dict") is None
        True
    """
    if not isinstance(data, dict):
        return None

    def _walk(value: Any, depth: int) -> Any:
        if depth > max_depth:
            return "<truncated>"
        if isinstance(value, dict):
            out: Dict[str, Any] = {}
            for index, (key, item) in enumerate(value.items()):
                if index >= max_items:
                    out["<truncated>"] = True
                    break
                key_text = str(key)[:METADATA_MAX_STRING]
                out[key_text] = _REDACTED if _is_sensitive_key(key) else _walk(item, depth + 1)
            return out
        if isinstance(value, (list, tuple)):
            items = [_walk(item, depth + 1) for item in list(value)[:max_items]]
            if len(value) > max_items:
                items.append("<truncated>")
            return items
        if isinstance(value, str):
            return value if len(value) <= max_string else value[:max_string] + "...<truncated>"
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return str(value)[:max_string]

    result = _walk(data, 0)
    if not isinstance(result, dict):
        return None
    size = _json_size(result)
    if size > max_total_bytes:
        return {"<truncated>": True, "original_size_bytes": size}
    return result


def sanitize_text(value: Any, max_length: int, field_name: str) -> str:
    """Strip control characters, trim and truncate text content.

    Args:
        value: Raw text value.
        max_length: Maximum number of characters kept.
        field_name: Field name, used only in the validation error.

    Returns:
        str: The sanitised text.

    Raises:
        AlertValidationError: If the value is empty after sanitising.

    Examples:
        >>> sanitize_text("  hello\\x00 world ", 200, "title")
        'hello world'
    """
    text = "" if value is None else str(value)
    text = _CONTROL_CHARS.sub("", text).strip()
    if len(text) > max_length:
        text = text[:max_length]
    if not text:
        raise AlertValidationError(f"{field_name} must not be empty")
    return text


def _as_utc(value: datetime) -> datetime:
    """Return a timezone-aware UTC datetime.

    SQLite returns naive datetimes even for timezone-aware columns, so naive
    values are treated as UTC.

    Args:
        value: Datetime from the database or application.

    Returns:
        datetime: Timezone-aware UTC datetime.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Flag, visibility and permission helpers
# ---------------------------------------------------------------------------


def _source_enabled(source: str) -> Optional[str]:
    """Check the master flag and the per-source flag.

    Args:
        source: Canonical source name (for example ``security``).

    Returns:
        Optional[str]: ``None`` when the source may emit, otherwise the skip reason.
    """
    if not getattr(settings, "alerting_enabled", False):
        return "alerting_disabled"
    if not getattr(settings, f"alerting_source_{source}_enabled", False):
        return "source_disabled"
    return None


def _is_visible(alert: Alert, unrestricted: bool, token_teams: Optional[List[str]]) -> bool:
    """Decide whether an alert is visible under the Layer-1 visibility contract.

    Args:
        alert: Alert row to check.
        unrestricted: True when the caller is an unrestricted administrator
            (see :func:`mcpgateway.utils.admin_check.is_admin_bypass_granted`).
        token_teams: Caller team scope; ``[]`` is public-only.

    Returns:
        bool: True when the caller may see the alert.
    """
    if unrestricted:
        return True
    if alert.team_id is None:
        # Global alerts are for unrestricted administrators only.
        return False
    return bool(token_teams) and alert.team_id in token_teams


def _user_permission_set(db: Session, user_email: str, team_id: Optional[str]) -> Set[str]:
    """Collect effective permissions for a user in a team context, synchronously.

    Mirrors ``PermissionService._get_user_roles`` for team context: global and
    personal roles, plus team roles scoped to ``team_id`` or unscoped to any
    team. Permissions from every active role are unioned.

    Args:
        db: Synchronous session.
        user_email: User to evaluate.
        team_id: Team context.

    Returns:
        Set[str]: Effective permission strings.
    """
    now = utc_now()
    scope_conditions = [UserRole.scope == "global", UserRole.scope == "personal"]
    if team_id:
        scope_conditions.append(and_(UserRole.scope == "team", or_(UserRole.scope_id == team_id, UserRole.scope_id.is_(None))))
    else:
        scope_conditions.append(and_(UserRole.scope == "team", UserRole.scope_id.is_(None)))

    rows = db.execute(
        select(Role.permissions)
        .select_from(UserRole)
        .join(Role, UserRole.role_id == Role.id)
        .where(
            UserRole.user_email == user_email,
            UserRole.is_active.is_(True),
            Role.is_active.is_(True),
            or_(*scope_conditions),
            or_(UserRole.expires_at.is_(None), UserRole.expires_at > now),
        )
    ).all()

    permissions: Set[str] = set()
    for (raw,) in rows:
        if isinstance(raw, list):
            permissions.update(str(item) for item in raw)
    return permissions


def _has_alert_read(db: Session, user_email: str, team_id: Optional[str]) -> bool:
    """Return True when the user may read alerts for the given team context.

    Args:
        db: Synchronous session.
        user_email: User to evaluate.
        team_id: Team context.

    Returns:
        bool: True when the user is an administrator or holds ``alerts.read`` or the wildcard.
    """
    if is_user_admin(db, user_email):
        return True
    perms = _user_permission_set(db, user_email, team_id)
    return Permissions.ALERTS_READ in perms or Permissions.ALL_PERMISSIONS in perms


# ---------------------------------------------------------------------------
# Recipient resolution
# ---------------------------------------------------------------------------


class AlertRecipientResolver:
    """Resolve the users who should receive an alert, with in-app preferences applied."""

    @staticmethod
    def resolve(db: Session, team_id: Optional[str], severity: str, source: str) -> List[str]:
        """Return the recipient emails for an alert.

        Team alerts go to active members of the team who hold ``alerts.read``.
        Global alerts (``team_id is None``) go to active administrators only. In-app
        preferences are applied: a disabled in-app channel, a ``min_severity`` above
        the alert severity, or an active ``mute_until`` removes the recipient. The
        result is capped at ``alerting_max_recipients``.

        Args:
            db: Synchronous session.
            team_id: Owning team, or ``None`` for a global alert.
            severity: Alert severity (LOW..CRITICAL).
            source: Alert source, used for preference scoping.

        Returns:
            List[str]: Sorted, de-duplicated recipient email addresses.
        """
        if team_id is None:
            rows = db.execute(select(EmailUser.email).where(EmailUser.is_admin.is_(True), EmailUser.is_active.is_(True))).all()
        else:
            rows = db.execute(
                select(EmailUser.email)
                .join(EmailTeamMember, EmailTeamMember.user_email == EmailUser.email)
                .where(
                    EmailTeamMember.team_id == team_id,
                    EmailTeamMember.is_active.is_(True),
                    EmailUser.is_active.is_(True),
                )
            ).all()

        recipients: List[str] = []
        for email in sorted({row[0] for row in rows}):
            if team_id is None:
                if not _is_active_admin(db, email):
                    continue
            elif not _has_alert_read(db, email, team_id):
                continue
            if not AlertRecipientResolver._preferences_allow(db, email, severity, source):
                continue
            recipients.append(email)

        cap = int(getattr(settings, "alerting_max_recipients", 1000))
        if len(recipients) > cap:
            logger.warning("Alert recipient fan-out truncated from %d to %d (alerting_max_recipients)", len(recipients), cap)
            recipients = recipients[:cap]
        return recipients

    @staticmethod
    def _preferences_allow(db: Session, user_email: str, severity: str, source: str) -> bool:
        """Apply in-app preferences to one alert for one recipient.

        Rows that apply are the user's own rows and the administrator defaults
        (``user_email IS NULL``), limited to the global scope or this source's
        category. The most specific row wins: own before default, then category
        before global. With no applicable row, in-app delivery is allowed.

        Args:
            db: Synchronous session.
            user_email: Recipient.
            severity: Alert severity.
            source: Alert source (the category scope value).

        Returns:
            bool: True when the in-app delivery should be created.
        """
        rows = (
            db.execute(
                select(AlertPreference).where(
                    or_(AlertPreference.user_email == user_email, AlertPreference.user_email.is_(None)),
                    AlertPreference.channel == "in_app",
                    or_(
                        and_(AlertPreference.scope == "category", AlertPreference.scope_value == source),
                        and_(AlertPreference.scope == "global", AlertPreference.scope_value == ""),
                    ),
                )
            )
            .scalars()
            .all()
        )
        if not rows:
            return True
        rows.sort(key=lambda row: (0 if row.user_email == user_email else 1, 0 if row.scope == "category" else 1))
        pref = rows[0]
        if not pref.enabled:
            return False
        if pref.mute_until is not None and _as_utc(pref.mute_until) > utc_now():
            return False
        min_rank = ALERT_SEVERITY_ORDER.get(str(pref.min_severity).upper(), 0)
        return ALERT_SEVERITY_ORDER.get(severity, 0) >= min_rank


def _is_active_admin(db: Session, user_email: str) -> bool:
    """Return True when the user is an active administrator.

    Args:
        db: Synchronous session.
        user_email: User to evaluate.

    Returns:
        bool: True for an active account with ``is_admin`` set.
    """
    user = db.execute(select(EmailUser).where(EmailUser.email == user_email)).scalar_one_or_none()
    return bool(user is not None and user.is_admin is True and user.is_active is True)


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class AlertService:
    """Alert lifecycle, emission, visibility and preferences."""

    # ----- emission ---------------------------------------------------------

    def emit(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
        self,
        source: str,
        type: str,  # pylint: disable=redefined-builtin
        severity: str,
        entity_type: Optional[str],
        entity_id: Optional[str],
        team_id: Optional[str],
        dedup_key: str,
        title: str,
        body: str,
        metadata: Optional[Dict[str, Any]] = None,
        security_event_id: Optional[str] = None,
    ) -> AlertEmitResult:
        """Create an alert, or fold it into a recent duplicate, and fan it out to recipients.

        The alert row, the per-recipient ``alert_deliveries`` rows and the optional
        ``SecurityEvent`` update are written in one transaction on a short-lived session.
        A storage failure is rolled back, logged and reported as
        ``skipped_reason="storage_error"``; it is not raised.

        Args:
            source: Producer source (security, gateway_health, performance, a2a, plugin).
            type: Alert type within the source (for example ``brute_force``).
            severity: LOW, MEDIUM, HIGH or CRITICAL (case-insensitive).
            entity_type: Subject entity type, if any.
            entity_id: Subject entity identifier, if any.
            team_id: Owning team, or ``None`` for a global alert.
            dedup_key: Key used to merge repeated occurrences within the dedup window.
            title: Short title (truncated to 200 characters).
            body: Body text (truncated to 4000 characters).
            metadata: Optional context; sensitive keys are redacted.
            security_event_id: Originating ``SecurityEvent`` ID, if any.

        Returns:
            AlertEmitResult: What was written, or why nothing was written.

        Raises:
            AlertValidationError: On an unknown source or severity, an empty dedup key,
                or empty title or body after sanitising.
        """
        source_name = str(source or "").strip().lower()
        if source_name not in ALERT_SOURCES_SET:
            raise AlertValidationError("unknown alert source")
        severity_name = str(severity or "").strip().upper()
        if severity_name not in ALERT_SEVERITY_ORDER:
            raise AlertValidationError("unknown alert severity")
        dedup_clean = str(dedup_key or "").strip()[:DEDUP_KEY_MAX_LENGTH]
        if not dedup_clean:
            raise AlertValidationError("dedup_key must not be empty")
        title_clean = sanitize_text(title, TITLE_MAX_LENGTH, "title")
        body_clean = sanitize_text(body, BODY_MAX_LENGTH, "body")
        meta_clean = redact_metadata(metadata)

        skipped = _source_enabled(source_name)
        if skipped is not None:
            return AlertEmitResult(skipped_reason=skipped)

        source_label = normalize_alert_label(source_name, ALERT_SOURCES)
        severity_label = normalize_alert_label(severity_name, ALERT_SEVERITIES)
        now = utc_now()
        window = timedelta(seconds=int(settings.alerting_dedup_window_seconds))

        db = SessionLocal()
        try:
            existing = (
                db.execute(
                    select(Alert)
                    .where(
                        Alert.dedup_key == dedup_clean,
                        Alert.status.in_(_DEDUP_ELIGIBLE_STATUSES),
                        Alert.last_seen >= now - window,
                    )
                    .order_by(Alert.last_seen.desc())
                    .limit(1)
                )
                .scalars()
                .first()
            )
            if existing is not None:
                existing.count = (existing.count or 1) + 1
                existing.last_seen = now
                db.commit()
                alerts_deduplicated_total.labels(source=source_label).inc()
                return AlertEmitResult(alert_id=existing.id, deduplicated=True)

            alert = Alert(
                id=uuid.uuid4().hex,
                source=source_name,
                type=(str(type or "").strip()[:100] or "generic"),
                severity=severity_name,
                status=ALERT_STATUS_OPEN,
                title=title_clean[:TITLE_MAX_LENGTH],
                body=body_clean,
                entity_type=(str(entity_type)[:50] if entity_type else None),
                entity_id=(str(entity_id)[:255] if entity_id else None),
                team_id=team_id,
                dedup_key=dedup_clean,
                first_seen=now,
                last_seen=now,
                count=1,
                created_at=now,
                updated_at=now,
                security_event_id=security_event_id,
                alert_metadata=meta_clean,
            )
            db.add(alert)
            db.flush()

            recipients = AlertRecipientResolver.resolve(db, team_id, severity_name, source_name)
            for email in recipients:
                db.add(
                    AlertDelivery(
                        id=uuid.uuid4().hex,
                        alert_id=alert.id,
                        user_email=email,
                        channel="in_app",
                        channel_id=None,
                        state="pending",
                        attempts=0,
                        next_attempt_at=now,
                        created_at=now,
                    )
                )

            if security_event_id:
                db.execute(
                    update(SecurityEvent)
                    .where(SecurityEvent.id == security_event_id)
                    .values(alert_sent=True, alert_sent_at=now, alert_recipients=list(recipients)[:SECURITY_EVENT_RECIPIENTS_CAP])
                )

            db.commit()
            alerts_created_total.labels(source=source_label, severity=severity_label).inc()
            return AlertEmitResult(alert_id=alert.id, created=True, recipient_count=len(recipients))
        except SQLAlchemyError:
            db.rollback()
            logger.warning("Alert emission failed at the storage layer; the producing operation was not affected", exc_info=True)
            return AlertEmitResult(skipped_reason="storage_error")
        finally:
            db.close()

    # ----- lifecycle --------------------------------------------------------

    def _load_visible(self, db: Session, alert_id: str, user_email: Optional[str], token_teams: Optional[List[str]]) -> Alert:
        """Load an alert, raising not-found when it is missing or not visible to the caller.

        Args:
            db: Session.
            alert_id: Alert identifier.
            user_email: Caller identity.
            token_teams: Caller team scope.

        Returns:
            Alert: The visible alert.

        Raises:
            AlertNotFoundError: When the alert is missing or not visible.
        """
        alert = db.execute(select(Alert).where(Alert.id == alert_id)).scalar_one_or_none()
        unrestricted = is_admin_bypass_granted(db, user_email, token_teams)
        if alert is None or not _is_visible(alert, unrestricted, token_teams):
            raise AlertNotFoundError("alert not found")
        return alert

    @staticmethod
    def _transition(alert: Alert, target: str, actor: str, now: datetime) -> bool:
        """Apply a validated lifecycle transition to an alert in place.

        Args:
            alert: Alert to modify.
            target: Target status.
            actor: Identity recorded for the action.
            now: Timestamp for the change.

        Returns:
            bool: True when the status changed, False when it was already at the target.

        Raises:
            AlertTransitionError: When the transition is not allowed.
        """
        current = alert.status
        if target == current:
            return False
        if target not in ALLOWED_TRANSITIONS.get(current, set()):
            raise AlertTransitionError("transition not allowed for the current alert state")

        alert.status = target
        alert.updated_at = now
        if target == ALERT_STATUS_ACKNOWLEDGED:
            alert.ack_by = actor
            alert.ack_at = now
            seconds = max(0.0, (_as_utc(now) - _as_utc(alert.created_at)).total_seconds())
            alert_time_to_ack_seconds.observe(seconds)
        elif target == ALERT_STATUS_RESOLVED:
            alert.resolved_at = now
            alert.resolved_by = actor
        return True

    def acknowledge(self, db: Session, alert_id: str, user_email: str, token_teams: Optional[List[str]]) -> Alert:
        """Acknowledge an alert. Acknowledging an already acknowledged alert is idempotent.

        Also records the caller's in-app delivery as acknowledged and read.

        Args:
            db: Session. Committed by this method.
            alert_id: Alert identifier.
            user_email: Actor.
            token_teams: Caller team scope.

        Returns:
            Alert: The updated alert.

        Raises:
            AlertNotFoundError: When the alert is not visible to the caller.
            AlertTransitionError: When the alert cannot be acknowledged from its current state.
        """
        now = utc_now()
        alert = self._load_visible(db, alert_id, user_email, token_teams)
        if alert.status == ALERT_STATUS_ACKNOWLEDGED:
            return alert
        self._transition(alert, ALERT_STATUS_ACKNOWLEDGED, user_email, now)
        db.execute(
            update(AlertDelivery)
            .where(AlertDelivery.alert_id == alert.id, AlertDelivery.user_email == user_email, AlertDelivery.channel == "in_app")
            .values(ack_at=now, read_at=func.coalesce(AlertDelivery.read_at, now))
        )
        db.commit()
        self._refresh_open_gauge(db)
        return alert

    def resolve(self, db: Session, alert_id: str, user_email: str, token_teams: Optional[List[str]]) -> Alert:
        """Resolve an alert. Resolving an already resolved alert is a no-op.

        Args:
            db: Session. Committed by this method.
            alert_id: Alert identifier.
            user_email: Actor.
            token_teams: Caller team scope.

        Returns:
            Alert: The updated alert.

        Raises:
            AlertNotFoundError: When the alert is not visible to the caller.
            AlertTransitionError: When the alert cannot be resolved from its current state.
        """
        now = utc_now()
        alert = self._load_visible(db, alert_id, user_email, token_teams)
        self._transition(alert, ALERT_STATUS_RESOLVED, user_email, now)
        db.commit()
        self._refresh_open_gauge(db)
        return alert

    def resolve_by_dedup_key(self, dedup_key: str, resolved_by: str = "system") -> int:
        """Resolve every open or acknowledged alert with a given dedup key.

        Producers call this when a condition recovers (for example a gateway returning
        to healthy). It runs on a short-lived session and never raises.

        Args:
            dedup_key: Dedup key of the alerts to resolve.
            resolved_by: Actor recorded on the alerts.

        Returns:
            int: Number of alerts resolved (0 when nothing matched or on failure).
        """
        dedup_clean = str(dedup_key or "").strip()[:DEDUP_KEY_MAX_LENGTH]
        if not dedup_clean:
            return 0
        db = SessionLocal()
        try:
            now = utc_now()
            alerts = db.execute(select(Alert).where(Alert.dedup_key == dedup_clean, Alert.status.in_((ALERT_STATUS_OPEN, ALERT_STATUS_ACKNOWLEDGED)))).scalars().all()
            changed = 0
            for alert in alerts:
                if self._transition(alert, ALERT_STATUS_RESOLVED, resolved_by, now):
                    changed += 1
            db.commit()
            self._refresh_open_gauge(db)
            return changed
        except (SQLAlchemyError, AlertError):
            db.rollback()
            logger.warning("Failed to resolve alerts for a recovered condition", exc_info=True)
            return 0
        finally:
            db.close()

    def bulk_action(self, db: Session, action: str, alert_ids: Iterable[str], user_email: str, token_teams: Optional[List[str]]) -> Dict[str, Any]:
        """Apply one lifecycle action to many alerts.

        Each alert is processed independently. A not-found or not-allowed alert is
        reported in ``failed`` with a generic reason and does not stop the batch.

        Args:
            db: Session.
            action: ``acknowledge`` or ``resolve``.
            alert_ids: Alert identifiers (at most 100, duplicates ignored).
            user_email: Actor.
            token_teams: Caller team scope.

        Returns:
            Dict[str, Any]: ``processed`` IDs and ``failed`` entries with a generic reason.

        Raises:
            AlertValidationError: On an unknown action, an empty list, or more than 100 IDs.
        """
        if action not in ("acknowledge", "resolve"):
            raise AlertValidationError("unknown bulk action")
        ids = list(dict.fromkeys(str(item) for item in alert_ids))
        if not ids:
            raise AlertValidationError("no alert IDs supplied")
        if len(ids) > BULK_ACTION_MAX_IDS:
            raise AlertValidationError(f"at most {BULK_ACTION_MAX_IDS} alert IDs may be processed at once")

        processed: List[str] = []
        failed: List[Dict[str, str]] = []
        for alert_id in ids:
            try:
                if action == "acknowledge":
                    self.acknowledge(db, alert_id, user_email, token_teams)
                else:
                    self.resolve(db, alert_id, user_email, token_teams)
                processed.append(alert_id)
            except AlertNotFoundError:
                db.rollback()
                failed.append({"id": alert_id, "reason": "not found"})
            except AlertTransitionError:
                db.rollback()
                failed.append({"id": alert_id, "reason": "transition not allowed"})
        return {"processed": processed, "failed": failed}

    def mark_read(self, db: Session, alert_id: str, user_email: str, token_teams: Optional[List[str]]) -> None:
        """Mark the caller's in-app delivery for an alert as read.

        Args:
            db: Session. Committed by this method.
            alert_id: Alert identifier.
            user_email: Recipient.
            token_teams: Caller team scope.

        Raises:
            AlertNotFoundError: When the alert is not visible to the caller.
        """
        alert = self._load_visible(db, alert_id, user_email, token_teams)
        db.execute(
            update(AlertDelivery)
            .where(AlertDelivery.alert_id == alert.id, AlertDelivery.user_email == user_email, AlertDelivery.channel == "in_app", AlertDelivery.read_at.is_(None))
            .values(read_at=utc_now())
        )
        db.commit()

    @staticmethod
    def _refresh_open_gauge(db: Session) -> None:
        """Refresh the ``alerts_open`` gauge from a grouped count.

        Failures are logged and ignored, so metrics never affect the caller.

        Args:
            db: Session used for the count.
        """
        try:
            rows = db.execute(select(Alert.severity, func.count(Alert.id)).where(Alert.status == ALERT_STATUS_OPEN).group_by(Alert.severity)).all()
            counts = {severity: 0 for severity in ALERT_SEVERITIES}
            for severity, total in rows:
                label = normalize_alert_label(severity, ALERT_SEVERITIES, default=ALERT_OTHER_LABEL)
                if label in counts:
                    counts[label] += int(total)
            for label, total in counts.items():
                alerts_open.labels(severity=label).set(total)
        except Exception:  # pylint: disable=broad-except
            logger.debug("Could not refresh alerts_open gauge", exc_info=True)

    # ----- queries ----------------------------------------------------------

    def get_alert(self, db: Session, alert_id: str, user_email: Optional[str], token_teams: Optional[List[str]]) -> Alert:
        """Return one visible alert.

        Args:
            db: Session.
            alert_id: Alert identifier.
            user_email: Caller identity.
            token_teams: Caller team scope.

        Returns:
            Alert: The alert.

        Raises:
            AlertNotFoundError: When the alert is missing or not visible.
        """
        return self._load_visible(db, alert_id, user_email, token_teams)

    def list_alerts(  # pylint: disable=too-many-branches
        self,
        db: Session,
        user_email: Optional[str],
        token_teams: Optional[List[str]],
        filters: Optional[AlertFilters] = None,
        limit: int = DEFAULT_LIST_LIMIT,
        offset: int = 0,
    ) -> AlertPage:
        """List alerts visible to the caller, newest first.

        Visibility matches :meth:`get_alert`. Unrestricted administrators see every
        alert. Other callers see alerts for teams in their token scope only, and
        never global alerts. ``unread_only`` restricts to alerts with an unread
        in-app delivery for the caller.

        Args:
            db: Session.
            user_email: Caller identity.
            token_teams: Caller team scope.
            filters: Optional filters.
            limit: Page size (1..200).
            offset: Offset (>= 0).

        Returns:
            AlertPage: The page and total count.

        Raises:
            AlertValidationError: On an invalid limit, offset or filter value.
        """
        if limit < 1 or limit > MAX_LIST_LIMIT:
            raise AlertValidationError(f"limit must be between 1 and {MAX_LIST_LIMIT}")
        if offset < 0:
            raise AlertValidationError("offset must be non-negative")
        filters = filters or AlertFilters()
        if filters.status is not None and filters.status not in ALERT_STATUSES:
            raise AlertValidationError("unknown status filter")
        if filters.severity is not None and filters.severity.upper() not in ALERT_SEVERITY_ORDER:
            raise AlertValidationError("unknown severity filter")
        if filters.source is not None and filters.source.lower() not in ALERT_SOURCES_SET:
            raise AlertValidationError("unknown source filter")

        conditions = []
        if not is_admin_bypass_granted(db, user_email, token_teams):
            if token_teams:
                conditions.append(Alert.team_id.in_(list(token_teams)))
            else:
                # Public-only and unauthenticated callers see no team or global alerts.
                conditions.append(false())

        if filters.status:
            conditions.append(Alert.status == filters.status)
        if filters.severity:
            conditions.append(Alert.severity == filters.severity.upper())
        if filters.source:
            conditions.append(Alert.source == filters.source.lower())
        if filters.unread_only and user_email:
            unread_ids = select(AlertDelivery.alert_id).where(AlertDelivery.user_email == user_email, AlertDelivery.channel == "in_app", AlertDelivery.read_at.is_(None))
            conditions.append(Alert.id.in_(unread_ids))

        base = select(Alert)
        if conditions:
            base = base.where(and_(*conditions))
        total = db.execute(select(func.count()).select_from(base.subquery())).scalar_one()
        items = db.execute(base.order_by(Alert.created_at.desc(), Alert.id.desc()).limit(limit).offset(offset)).scalars().all()
        return AlertPage(items=list(items), total=int(total), limit=limit, offset=offset)

    # ----- preferences ------------------------------------------------------

    def get_preferences(self, db: Session, user_email: str) -> List[AlertPreference]:
        """Return the user's preference rows followed by the inherited administrator defaults.

        Args:
            db: Session.
            user_email: User whose preferences are returned.

        Returns:
            List[AlertPreference]: Own rows, then defaults (``user_email IS NULL``).
        """
        rows = (
            db.execute(
                select(AlertPreference)
                .where(or_(AlertPreference.user_email == user_email, AlertPreference.user_email.is_(None)))
                .order_by(AlertPreference.scope, AlertPreference.scope_value, AlertPreference.channel)
            )
            .scalars()
            .all()
        )
        own = [row for row in rows if row.user_email == user_email]
        defaults = [row for row in rows if row.user_email is None]
        return own + defaults

    def put_preferences(self, db: Session, user_email: str, preferences: Sequence[Dict[str, Any]]) -> List[AlertPreference]:
        """Replace the caller's preference rows with the supplied set.

        Every entry is validated before anything is written. The replacement is atomic:
        on a validation error the existing rows are left unchanged.

        Args:
            db: Session. Committed by this method.
            user_email: Owner of the preferences.
            preferences: Entries with ``scope``, ``scope_value``, ``channel``,
                ``min_severity``, ``enabled``, ``mute_until`` and optional ``quiet_hours``.

        Returns:
            List[AlertPreference]: The caller's stored rows followed by the defaults.

        Raises:
            AlertValidationError: When an entry is invalid or duplicated.
        """
        if len(preferences) > PREFERENCES_MAX_ENTRIES:
            raise AlertValidationError("too many preference entries")
        normalised: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        for entry in preferences:
            scope = str(entry.get("scope", "")).lower()
            if scope not in PREFERENCE_SCOPES:
                raise AlertValidationError("unknown preference scope")
            channel = str(entry.get("channel", "")).lower()
            if channel not in PREFERENCE_CHANNELS:
                raise AlertValidationError("unknown preference channel")
            min_severity = str(entry.get("min_severity", "LOW")).upper()
            if min_severity not in ALERT_SEVERITY_ORDER:
                raise AlertValidationError("unknown minimum severity")
            scope_value = str(entry.get("scope_value") or "").strip()[:255]
            if scope == "global" and scope_value:
                raise AlertValidationError("global preferences must not set scope_value")
            if scope == "category":
                scope_value = scope_value.lower()
                if scope_value not in ALERT_SOURCES_SET:
                    raise AlertValidationError("category preference must name a known source")
            mute_until = entry.get("mute_until")
            if mute_until is not None and not isinstance(mute_until, datetime):
                raise AlertValidationError("mute_until must be a datetime")
            key = (scope, scope_value, channel)
            if key in normalised:
                raise AlertValidationError("duplicate preference entry")
            normalised[key] = {
                "scope": scope,
                "scope_value": scope_value,
                "channel": channel,
                "min_severity": min_severity,
                "enabled": bool(entry.get("enabled", True)),
                "mute_until": mute_until,
                "quiet_hours": entry.get("quiet_hours"),
            }

        try:
            db.execute(delete(AlertPreference).where(AlertPreference.user_email == user_email))
            now = utc_now()
            for values in normalised.values():
                db.add(AlertPreference(id=uuid.uuid4().hex, user_email=user_email, created_at=now, updated_at=now, **values))
            db.commit()
        except SQLAlchemyError:
            db.rollback()
            raise
        return self.get_preferences(db, user_email)


# ---------------------------------------------------------------------------
# Producer-facing entry points
# ---------------------------------------------------------------------------

_pending_tasks: Set["asyncio.Task[Any]"] = set()
_service_singleton: Optional[AlertService] = None


def get_alert_service() -> AlertService:
    """Return the process-wide :class:`AlertService` instance.

    Returns:
        AlertService: The shared service.
    """
    global _service_singleton  # pylint: disable=global-statement
    if _service_singleton is None:
        _service_singleton = AlertService()
    return _service_singleton


def _emit_logged(kwargs: Dict[str, Any]) -> None:
    """Run :meth:`AlertService.emit` and log any failure instead of raising.

    Args:
        kwargs: Keyword arguments for :meth:`AlertService.emit`.
    """
    try:
        get_alert_service().emit(**kwargs)
    except Exception:  # pylint: disable=broad-except
        logger.warning("Alert emission failed; the producing operation was not affected", exc_info=True)


def emit_alert_safe(**kwargs: Any) -> None:
    """Emit an alert without ever raising to the caller.

    Returns immediately when ``alerting_enabled`` is false. Inside a running event loop
    the write is offloaded with ``asyncio.to_thread`` as a fire-and-forget task, so the
    request path only pays for enqueueing; the task reference is retained until it
    finishes. Without a running loop the write runs inline. All failures are logged.

    Args:
        **kwargs: Keyword arguments accepted by :meth:`AlertService.emit`.
    """
    try:
        if not getattr(settings, "alerting_enabled", False):
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None:
            task = loop.create_task(asyncio.to_thread(_emit_logged, kwargs))
            _pending_tasks.add(task)
            task.add_done_callback(_pending_tasks.discard)
            return
        _emit_logged(kwargs)
    except Exception:  # pylint: disable=broad-except
        logger.warning("Alert emission could not be scheduled; the producing operation was not affected", exc_info=True)
