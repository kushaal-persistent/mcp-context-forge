# -*- coding: utf-8 -*-
"""Location: ./tests/migration/test_alerting_migration.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Migration tests for the alerting tables and alerts.* role seed (Issue #5805).

Each test runs the real migration ``upgrade()`` and ``downgrade()`` functions on a
temporary SQLite database through an Alembic ``Operations`` context. No container
runtime is required. Migration modules are loaded from their file paths because
the revision identifiers are not valid Python module names.
"""

# Standard
import importlib.util
import json
from pathlib import Path

# Third-Party
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory
import pytest
from sqlalchemy import create_engine, inspect, text

VERSIONS_DIR = Path(__file__).resolve().parents[2] / "mcpgateway" / "alembic" / "versions"
ALERTING_TABLE_REV = "a1c5e7f9b3d2"
ALERTING_SEED_REV = "b2d6f8a0c4e1"
PREVIOUS_HEAD = "c7e91a2b4d60"

EXPECTED_TABLES = {"alerts", "alert_deliveries", "alert_preferences", "alert_channels"}
EXPECTED_INDEXES = {
    "alerts": {"ix_alerts_team_id", "idx_alerts_team_status_created", "idx_alerts_dedup_status", "idx_alerts_severity_created"},
    "alert_deliveries": {"idx_alert_deliveries_user_read", "idx_alert_deliveries_state_next", "idx_alert_deliveries_alert"},
    "alert_channels": {"ix_alert_channels_team_id"},
}


def _load_migration(filename: str, module_name: str):
    """Load a migration module from the versions directory by file name.

    Args:
        filename: File name inside ``mcpgateway/alembic/versions``.
        module_name: Module name to register the loaded module under.

    Returns:
        module: The loaded migration module.
    """
    spec = importlib.util.spec_from_file_location(module_name, VERSIONS_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TABLE_MIGRATION = _load_migration("a1c5e7f9b3d2_add_alerting_tables.py", "alerting_table_migration")
SEED_MIGRATION = _load_migration("b2d6f8a0c4e1_seed_alerts_permissions.py", "alerting_seed_migration")


def _run(engine, fn):
    """Run a migration function inside an Alembic operations context on the engine's connection.

    Args:
        engine: SQLAlchemy engine to run against.
        fn: Callable that takes no arguments and uses ``alembic.op``.
    """
    with engine.connect() as conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            fn()
        conn.commit()


@pytest.fixture
def engine(tmp_path):
    """Provide an empty SQLite database with a minimal ``roles`` table matching the production schema."""
    db_file = tmp_path / "alerts_migration.db"
    eng = create_engine(f"sqlite:///{db_file}")
    with eng.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE roles ("
                "id VARCHAR(36) PRIMARY KEY, name VARCHAR(255) NOT NULL, description TEXT, "
                "scope VARCHAR(20) NOT NULL, permissions TEXT NOT NULL, is_active BOOLEAN NOT NULL, "
                "updated_at DATETIME)"
            )
        )
    yield eng
    eng.dispose()


def _index_names(engine, table):
    """Return the index names on a table.

    Args:
        engine: SQLAlchemy engine.
        table: Table name.

    Returns:
        set[str]: Index names.
    """
    return {idx["name"] for idx in inspect(engine).get_indexes(table)}


class TestRevisionChain:
    """The migration files form one linear chain with a single head."""

    def test_chain_has_exactly_one_head_and_alerting_is_on_top(self):
        """Alembic resolves one head, and it is the alerting role seed."""
        cfg = Config()
        cfg.set_main_option("script_location", str(VERSIONS_DIR.parent))
        script = ScriptDirectory.from_config(cfg)
        assert script.get_heads() == [ALERTING_SEED_REV]

    def test_table_migration_revises_previous_head(self):
        """The table migration sits directly after the previous head."""
        assert TABLE_MIGRATION.revision == ALERTING_TABLE_REV
        assert TABLE_MIGRATION.down_revision == PREVIOUS_HEAD

    def test_seed_migration_revises_table_migration(self):
        """The seed migration sits directly after the table migration."""
        assert SEED_MIGRATION.revision == ALERTING_SEED_REV
        assert SEED_MIGRATION.down_revision == ALERTING_TABLE_REV


class TestTableMigration:
    """Table creation, indexes, idempotence and downgrade."""

    def test_upgrade_creates_the_four_alerting_tables(self, engine):
        """Upgrade creates alerts, alert_deliveries, alert_preferences and alert_channels."""
        _run(engine, TABLE_MIGRATION.upgrade)
        tables = set(inspect(engine).get_table_names())
        assert EXPECTED_TABLES <= tables

    def test_upgrade_creates_declared_indexes(self, engine):
        """Each table has its declared indexes."""
        _run(engine, TABLE_MIGRATION.upgrade)
        for table, expected in EXPECTED_INDEXES.items():
            assert expected <= _index_names(engine, table), f"missing index on {table}"

    def test_preferences_unique_constraint_is_created(self, engine):
        """alert_preferences enforces uniqueness on (user_email, scope, scope_value, channel)."""
        _run(engine, TABLE_MIGRATION.upgrade)
        uniques = inspect(engine).get_unique_constraints("alert_preferences")
        names = {constraint["name"] for constraint in uniques}
        assert "uq_alert_preferences_user_scope_channel" in names

    def test_deliveries_foreign_key_cascades_from_alert(self, engine):
        """alert_deliveries references alerts with ON DELETE CASCADE."""
        _run(engine, TABLE_MIGRATION.upgrade)
        fks = inspect(engine).get_foreign_keys("alert_deliveries")
        assert len(fks) == 1
        assert fks[0]["referred_table"] == "alerts"
        assert fks[0]["options"].get("ondelete", "").upper() == "CASCADE"

    def test_upgrade_is_idempotent(self, engine):
        """Running the table migration twice does not raise and leaves the same tables."""
        _run(engine, TABLE_MIGRATION.upgrade)
        before = set(inspect(engine).get_table_names())
        _run(engine, TABLE_MIGRATION.upgrade)
        assert set(inspect(engine).get_table_names()) == before

    def test_downgrade_drops_the_four_tables(self, engine):
        """Downgrade removes exactly the alerting tables and leaves unrelated tables alone."""
        _run(engine, TABLE_MIGRATION.upgrade)
        _run(engine, TABLE_MIGRATION.downgrade)
        tables = set(inspect(engine).get_table_names())
        assert not (EXPECTED_TABLES & tables)
        assert "roles" in tables

    def test_downgrade_is_safe_when_tables_are_already_absent(self, engine):
        """Downgrade on a database without the tables is a no-op, not an error."""
        _run(engine, TABLE_MIGRATION.downgrade)
        assert not (EXPECTED_TABLES & set(inspect(engine).get_table_names()))


def _insert_role(engine, role_id, name, scope, permissions):
    """Insert a role row into the test roles table.

    Args:
        engine: SQLAlchemy engine.
        role_id: Role identifier.
        name: Role name.
        scope: Role scope.
        permissions: Permission list stored as JSON text.
    """
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO roles (id, name, scope, permissions, is_active) VALUES (:id, :name, :scope, :perms, 1)"),
            {"id": role_id, "name": name, "scope": scope, "perms": json.dumps(permissions)},
        )


def _role_permissions(engine, name, scope="team"):
    """Return the stored permission list for a role.

    Args:
        engine: SQLAlchemy engine.
        name: Role name.
        scope: Role scope.

    Returns:
        list[str]: Stored permissions.
    """
    with engine.connect() as conn:
        raw = conn.execute(text("SELECT permissions FROM roles WHERE name = :name AND scope = :scope"), {"name": name, "scope": scope}).scalar_one()
    return json.loads(raw)


class TestRoleSeedMigration:
    """The alerts.* permissions are added to the default team roles."""

    def test_seed_adds_expected_permissions_to_team_admin(self, engine):
        """team_admin gains read, acknowledge, subscribe and manage."""
        _insert_role(engine, "r-admin", "team_admin", "team", ["teams.read"])
        _run(engine, SEED_MIGRATION.upgrade)
        perms = _role_permissions(engine, "team_admin")
        assert {"alerts.read", "alerts.acknowledge", "alerts.subscribe", "alerts.manage"} <= set(perms)
        assert "teams.read" in perms

    def test_seed_adds_read_and_subscribe_to_developer_and_viewer(self, engine):
        """developer and viewer gain read and subscribe, and no acknowledge or manage."""
        _insert_role(engine, "r-dev", "developer", "team", [])
        _insert_role(engine, "r-view", "viewer", "team", [])
        _run(engine, SEED_MIGRATION.upgrade)
        for role in ("developer", "viewer"):
            perms = set(_role_permissions(engine, role))
            assert {"alerts.read", "alerts.subscribe"} <= perms
            assert "alerts.acknowledge" not in perms
            assert "alerts.manage" not in perms

    def test_seed_is_idempotent(self, engine):
        """Running the seed twice produces exactly one copy of each permission."""
        _insert_role(engine, "r-admin", "team_admin", "team", [])
        _run(engine, SEED_MIGRATION.upgrade)
        first = _role_permissions(engine, "team_admin")
        _run(engine, SEED_MIGRATION.upgrade)
        second = _role_permissions(engine, "team_admin")
        assert first == second
        assert len(second) == len(set(second))

    def test_seed_keeps_existing_permissions_untouched(self, engine):
        """Existing non-alerting permissions survive the additive seed."""
        _insert_role(engine, "r-dev", "developer", "team", ["tools.read", "gateways.read"])
        _run(engine, SEED_MIGRATION.upgrade)
        perms = set(_role_permissions(engine, "developer"))
        assert {"tools.read", "gateways.read"} <= perms

    def test_seed_skips_missing_roles_without_error(self, engine):
        """When a default role does not exist the seed skips it and does not raise."""
        _run(engine, SEED_MIGRATION.upgrade)
        with engine.connect() as conn:
            count = conn.execute(text("SELECT COUNT(*) FROM roles")).scalar_one()
        assert count == 0

    def test_downgrade_removes_only_the_added_permissions(self, engine):
        """Downgrade removes the alerts.* grants and keeps the role's own permissions."""
        _insert_role(engine, "r-dev", "developer", "team", ["tools.read"])
        _run(engine, SEED_MIGRATION.upgrade)
        _run(engine, SEED_MIGRATION.downgrade)
        perms = _role_permissions(engine, "developer")
        assert perms == ["tools.read"]

    def test_load_permissions_normalises_stored_values(self):
        """The loader accepts JSON text, bytes and lists, and drops non-string entries."""
        load = SEED_MIGRATION._load_permissions  # pylint: disable=protected-access
        assert load('["a", "b"]') == ["a", "b"]
        assert load(b'["x"]') == ["x"]
        assert load(["p", 1, "q"]) == ["p", "q"]
        assert load("not json") == []
        assert load(None) == []
