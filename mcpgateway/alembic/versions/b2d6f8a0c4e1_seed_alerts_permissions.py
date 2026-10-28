# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/alembic/versions/b2d6f8a0c4e1_seed_alerts_permissions.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Seed alerts.* permissions into default team-scoped roles.

Revision ID: b2d6f8a0c4e1
Revises: a1c5e7f9b3d2
Create Date: 2026-10-26 00:00:01.000000

Backfills the alerts.* permissions into the existing default roles:

* team_admin: alerts.read, alerts.acknowledge, alerts.subscribe, alerts.manage
* developer: alerts.read, alerts.subscribe
* viewer: alerts.read, alerts.subscribe

platform_admin already holds the wildcard permission and is unaffected.
platform_viewer is deliberately unchanged because alerts are team-scoped.
The developer and viewer grants keep the invariant viewer < developer < team_admin
that the RBAC permission matrix asserts.

The upgrade is idempotent. The downgrade removes only the permissions it added.
"""

# Standard
from datetime import datetime, timezone
import json
from typing import Sequence, Union

# Third-Party
from alembic import op
import sqlalchemy as sa
from sqlalchemy import text

# revision identifiers, used by Alembic.
revision: str = "b2d6f8a0c4e1"  # pragma: allowlist secret
down_revision: Union[str, Sequence[str], None] = "a1c5e7f9b3d2"  # pragma: allowlist secret
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

ROLE_PERMISSION_ADDITIONS: list[tuple[str, str, list[str]]] = [
    # (role_name, scope, permissions_to_add)
    ("team_admin", "team", ["alerts.read", "alerts.acknowledge", "alerts.subscribe", "alerts.manage"]),
    ("developer", "team", ["alerts.read", "alerts.subscribe"]),
    ("viewer", "team", ["alerts.read", "alerts.subscribe"]),
]


def _load_permissions(raw_permissions: object) -> list[str]:
    """Normalize stored role permissions into a list of strings.

    Args:
        raw_permissions: Raw permissions value from the role row.

    Returns:
        list[str]: Normalized list of permission strings.
    """
    if not raw_permissions:
        return []

    parsed = raw_permissions
    if isinstance(parsed, (bytes, bytearray)):
        parsed = parsed.decode("utf-8")

    if isinstance(parsed, str):
        try:
            parsed = json.loads(parsed)
        except json.JSONDecodeError:
            return []

    if isinstance(parsed, list):
        return [perm for perm in parsed if isinstance(perm, str)]

    return []


def _update_role_permissions(conn, role_name: str, scope: str, permissions: list[str], add: bool) -> None:
    """Add or remove permissions from a role, idempotently.

    Args:
        conn: Active Alembic connection.
        role_name: Role name to update.
        scope: Role scope ('team' or 'global') to disambiguate roles with the same name.
        permissions: Permission values to add or remove.
        add: When True, add permissions; when False, remove permissions.
    """
    row = conn.execute(
        text("SELECT id, permissions FROM roles WHERE name = :name AND scope = :scope AND is_active = :active LIMIT 1"),
        {"name": role_name, "scope": scope, "active": True},
    ).fetchone()

    if not row:
        print(f"{role_name} role not found. Skipping.")
        return

    role_id = row[0]
    current_permissions = _load_permissions(row[1])

    if add:
        updated_permissions = list(current_permissions)
        for permission in permissions:
            if permission not in updated_permissions:
                updated_permissions.append(permission)
    else:
        updated_permissions = [permission for permission in current_permissions if permission not in permissions]

    if updated_permissions == current_permissions:
        print(f"{role_name} role already has the required permissions. Skipping.")
        return

    dialect_name = conn.dialect.name
    if dialect_name == "postgresql":
        update_query = text("""
            UPDATE roles
            SET permissions = CAST(:permissions AS JSONB), updated_at = :updated_at
            WHERE id = :role_id
            """)
        updated_at: object = datetime.now(timezone.utc)
    else:
        update_query = text("""
            UPDATE roles
            SET permissions = :permissions, updated_at = :updated_at
            WHERE id = :role_id
            """)
        # Match the sqlite3 default adapter's storage format exactly; binding a
        # datetime object would trip the Python 3.12+ deprecated-adapter warning.
        updated_at = datetime.now(timezone.utc).isoformat(" ")

    conn.execute(
        update_query,
        {
            "permissions": json.dumps(updated_permissions),
            "updated_at": updated_at,
            "role_id": role_id,
        },
    )
    print(f"Updated role '{role_name}' permissions.")


def upgrade() -> None:
    """Backfill alerts.* permissions into the default team-scoped roles."""
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    if "roles" not in inspector.get_table_names():
        print("roles table not found. Skipping migration.")
        return

    for role_name, scope, permissions in ROLE_PERMISSION_ADDITIONS:
        _update_role_permissions(conn, role_name, scope, permissions, add=True)


def downgrade() -> None:
    """Remove the alerts.* permissions added by this migration."""
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    if "roles" not in inspector.get_table_names():
        print("roles table not found. Skipping migration.")
        return

    for role_name, scope, permissions in ROLE_PERMISSION_ADDITIONS:
        _update_role_permissions(conn, role_name, scope, permissions, add=False)
