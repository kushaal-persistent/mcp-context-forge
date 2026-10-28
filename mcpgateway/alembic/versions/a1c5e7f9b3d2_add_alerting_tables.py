# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/alembic/versions/a1c5e7f9b3d2_add_alerting_tables.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Add alerting and notification tables.

Revision ID: a1c5e7f9b3d2
Revises: c7e91a2b4d60
Create Date: 2026-10-26 00:00:00.000000

Creates the durable alert store used by the alerting subsystem:

* ``alerts`` - team-scoped alert records with deduplication and lifecycle state.
* ``alert_deliveries`` - transactional outbox with per-recipient inbox state.
* ``alert_preferences`` - per-user routing preferences (channel and severity).
* ``alert_channels`` - external delivery channels (webhook / email).

Every ``create_table`` is guarded by an inspector check so the migration is
idempotent. The downgrade drops the tables in foreign-key-safe order.
"""

# Standard
from typing import Sequence, Union

# Third-Party
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "a1c5e7f9b3d2"  # pragma: allowlist secret
down_revision: Union[str, Sequence[str], None] = "c7e91a2b4d60"  # pragma: allowlist secret
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(name: str) -> bool:
    """Return True when the table already exists on the bound connection.

    Args:
        name: Table name to check.

    Returns:
        bool: True if the table exists.
    """
    return sa.inspect(op.get_bind()).has_table(name)


def upgrade() -> None:
    """Create the alerting tables and their indexes when absent."""
    if not _has_table("alerts"):
        op.create_table(
            "alerts",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("source", sa.String(length=50), nullable=False),
            sa.Column("type", sa.String(length=100), nullable=False),
            sa.Column("severity", sa.String(length=20), nullable=False),
            sa.Column("status", sa.String(length=20), nullable=False),
            sa.Column("title", sa.String(length=200), nullable=False),
            sa.Column("body", sa.Text(), nullable=False),
            sa.Column("entity_type", sa.String(length=50), nullable=True),
            sa.Column("entity_id", sa.String(length=255), nullable=True),
            sa.Column("team_id", sa.String(length=36), nullable=True),
            sa.Column("dedup_key", sa.String(length=255), nullable=False),
            sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
            sa.Column("count", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("resolved_by", sa.String(length=255), nullable=True),
            sa.Column("ack_by", sa.String(length=255), nullable=True),
            sa.Column("ack_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("security_event_id", sa.String(length=36), nullable=True),
            sa.Column("metadata", sa.JSON(), nullable=True),
        )
        op.create_index("ix_alerts_team_id", "alerts", ["team_id"])
        op.create_index("idx_alerts_team_status_created", "alerts", ["team_id", "status", "created_at"])
        op.create_index("idx_alerts_dedup_status", "alerts", ["dedup_key", "status"])
        op.create_index("idx_alerts_severity_created", "alerts", ["severity", "created_at"])

    if not _has_table("alert_deliveries"):
        op.create_table(
            "alert_deliveries",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("alert_id", sa.String(length=36), sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False),
            sa.Column("user_email", sa.String(length=255), nullable=False),
            sa.Column("channel", sa.String(length=20), nullable=False),
            sa.Column("channel_id", sa.String(length=36), nullable=True),
            sa.Column("state", sa.String(length=20), nullable=False),
            sa.Column("attempts", sa.Integer(), nullable=False),
            sa.Column("last_error", sa.Text(), nullable=True),
            sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("ack_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index("idx_alert_deliveries_user_read", "alert_deliveries", ["user_email", "read_at"])
        op.create_index("idx_alert_deliveries_state_next", "alert_deliveries", ["state", "next_attempt_at"])
        op.create_index("idx_alert_deliveries_alert", "alert_deliveries", ["alert_id"])

    if not _has_table("alert_preferences"):
        op.create_table(
            "alert_preferences",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("user_email", sa.String(length=255), nullable=True),
            sa.Column("scope", sa.String(length=20), nullable=False),
            sa.Column("scope_value", sa.String(length=255), nullable=False),
            sa.Column("channel", sa.String(length=20), nullable=False),
            sa.Column("min_severity", sa.String(length=20), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False),
            sa.Column("mute_until", sa.DateTime(timezone=True), nullable=True),
            sa.Column("quiet_hours", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("user_email", "scope", "scope_value", "channel", name="uq_alert_preferences_user_scope_channel"),
        )

    if not _has_table("alert_channels"):
        op.create_table(
            "alert_channels",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("type", sa.String(length=20), nullable=False),
            sa.Column("name", sa.String(length=100), nullable=False),
            sa.Column("url", sa.Text(), nullable=True),
            sa.Column("secret_encrypted", sa.Text(), nullable=True),
            sa.Column("team_id", sa.String(length=36), nullable=True),
            sa.Column("enabled", sa.Boolean(), nullable=False),
            sa.Column("created_by", sa.String(length=255), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_alert_channels_team_id", "alert_channels", ["team_id"])


def downgrade() -> None:
    """Drop the alerting tables in foreign-key-safe order."""
    # Children first: alert_deliveries references alerts.
    for table in ("alert_channels", "alert_preferences", "alert_deliveries", "alerts"):
        if _has_table(table):
            op.drop_table(table)
