# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/schemas_alerts.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Pydantic request and response models for the alerts API (Issue #5805).

No model accepts a ``team_id`` or owner input. Team scope is derived on the
server from the authenticated caller, never from the request body. Models do
not allow extra fields, so unknown keys are rejected.
"""

# Standard
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

# Third-Party
from pydantic import BaseModel, ConfigDict, Field

ALERT_SEVERITY_VALUES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
PREFERENCE_CHANNEL_VALUES = ("in_app", "email", "webhook")


class AlertResponse(BaseModel):
    """One alert as returned by the API.

    ``metadata`` is the already-redacted copy stored by the service.
    """

    model_config = ConfigDict(extra="forbid", from_attributes=True)

    id: str
    source: str
    type: str
    severity: str
    status: str
    title: str
    body: str
    entity_type: Optional[str] = None
    entity_id: Optional[str] = None
    team_id: Optional[str] = None
    dedup_key: str
    first_seen: datetime
    last_seen: datetime
    count: int
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    ack_by: Optional[str] = None
    ack_at: Optional[datetime] = None
    security_event_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class AlertListResponse(BaseModel):
    """A page of alerts, newest first."""

    model_config = ConfigDict(extra="forbid")

    items: List[AlertResponse]
    total: int
    page: int = Field(..., ge=1)
    page_size: int = Field(..., ge=1)


class AlertAckRequest(BaseModel):
    """Optional body for acknowledging an alert.

    The note is accepted for forward compatibility and is not persisted in v1.
    """

    model_config = ConfigDict(extra="forbid")

    note: Optional[str] = Field(default=None, max_length=500)


class AlertBulkRequest(BaseModel):
    """Bulk lifecycle action over up to 100 alerts."""

    model_config = ConfigDict(extra="forbid")

    action: Literal["read", "ack", "resolve"]
    ids: List[str] = Field(..., min_length=1, max_length=100)


class AlertBulkFailure(BaseModel):
    """One alert that could not be processed in a bulk request."""

    model_config = ConfigDict(extra="forbid")

    id: str
    reason: str


class AlertBulkResponse(BaseModel):
    """Result of a bulk request. Each alert is processed independently."""

    model_config = ConfigDict(extra="forbid")

    action: str
    processed: List[str]
    failed: List[AlertBulkFailure]


class AlertPreferenceItem(BaseModel):
    """One routing preference entry.

    ``scope_value`` is required for the ``category`` scope (a source name) and
    must be empty for the ``global`` scope. The service enforces both rules.
    """

    model_config = ConfigDict(extra="forbid")

    scope: Literal["global", "category", "entity"]
    scope_value: str = Field(default="", max_length=255)
    channel: Literal["in_app", "email", "webhook"]
    min_severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "LOW"
    enabled: bool = True
    mute_until: Optional[datetime] = None
    quiet_hours: Optional[Dict[str, Any]] = None


class AlertPreferenceRecord(AlertPreferenceItem):
    """A stored preference row as returned by the API."""

    id: str
    is_default: bool = False


class AlertPreferencesResponse(BaseModel):
    """The caller's preferences followed by inherited administrator defaults."""

    model_config = ConfigDict(extra="forbid")

    items: List[AlertPreferenceRecord]


class AlertPreferencesUpdate(BaseModel):
    """Replacement set of the caller's preferences (at most 50 entries)."""

    model_config = ConfigDict(extra="forbid")

    items: List[AlertPreferenceItem] = Field(..., max_length=50)


class AlertStatusResponse(BaseModel):
    """Admin status of the alerting subsystem."""

    model_config = ConfigDict(extra="forbid")

    alerting_enabled: bool
    active_sources: List[str]
    dedup_window_seconds: int
    expiry_days: int
    retention_days: int
    dispatcher_running: bool
    pending_deliveries: int
    queue_max_depth: int
