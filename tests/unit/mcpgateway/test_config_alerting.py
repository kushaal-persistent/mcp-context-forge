# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/test_config_alerting.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Tests for the alerting settings and feature flags (Issue #5805).

The ``Settings`` class is constructed with explicit keyword arguments so the test
does not depend on the developer's environment. Defaults are read from the field
definitions. Validation failures are checked on their message, not only on the
exception type.
"""

# Third-Party
from pydantic import ValidationError
import pytest

# First-Party
from mcpgateway.config import Settings

ALERTING_DEFAULTS = {
    "alerting_enabled": False,
    "alerting_source_security_enabled": True,
    "alerting_source_gateway_health_enabled": True,
    "alerting_source_performance_enabled": False,
    "alerting_source_a2a_enabled": False,
    "alerting_source_plugin_enabled": False,
    "alerting_dedup_window_seconds": 300,
    "alerting_expiry_days": 30,
    "alerting_retention_days": 90,
    "alerting_max_recipients": 1000,
    "alerting_queue_max_depth": 10000,
    "alerting_dispatch_poll_seconds": 2,
    "alerting_dispatch_batch_size": 100,
    "alerting_delivery_max_attempts": 5,
    "alerting_delivery_lease_seconds": 60,
}


def _settings(**overrides):
    """Build a Settings instance that ignores the process environment for alerting keys.

    Args:
        **overrides: Alerting fields to set explicitly.

    Returns:
        Settings: The constructed settings.
    """
    return Settings(**overrides)


class TestAlertingDefaults:
    """Every alerting default matches the approved strategy."""

    @pytest.mark.parametrize("name,expected", sorted(ALERTING_DEFAULTS.items()))
    def test_default_value(self, name, expected):
        """Each alerting field has the documented default, read from the field definition."""
        field = Settings.model_fields[name]
        assert field.default == expected, f"{name} default is {field.default!r}, expected {expected!r}"

    def test_master_flag_defaults_off_so_existing_behaviour_is_unchanged(self):
        """With no configuration the alerting subsystem is disabled."""
        assert Settings.model_fields["alerting_enabled"].default is False

    def test_dedup_window_default_is_300_seconds(self):
        """The dedup window defaults to five minutes (300 s)."""
        assert Settings.model_fields["alerting_dedup_window_seconds"].default == 300

    def test_expiry_and_retention_defaults_are_30_and_90_days(self):
        """Expiry defaults to 30 days and deletion to 90 days."""
        assert Settings.model_fields["alerting_expiry_days"].default == 30
        assert Settings.model_fields["alerting_retention_days"].default == 90

    def test_fan_out_cap_default_is_1000(self):
        """The per-alert recipient cap defaults to 1000."""
        assert Settings.model_fields["alerting_max_recipients"].default == 1000


class TestPerSourceFlags:
    """Each producer source has its own flag and the flags are independent."""

    @pytest.mark.parametrize("source", ["security", "gateway_health", "performance", "a2a", "plugin"])
    def test_source_flag_exists_and_is_boolean(self, source):
        """Every source has a boolean alerting_source_<name>_enabled field."""
        field = Settings.model_fields[f"alerting_source_{source}_enabled"]
        assert field.annotation is bool

    def test_security_and_gateway_are_on_by_default_and_later_sources_off(self):
        """Round 2 sources default on; performance, A2A and plugin default off until their phase ships."""
        assert Settings.model_fields["alerting_source_security_enabled"].default is True
        assert Settings.model_fields["alerting_source_gateway_health_enabled"].default is True
        assert Settings.model_fields["alerting_source_performance_enabled"].default is False
        assert Settings.model_fields["alerting_source_a2a_enabled"].default is False
        assert Settings.model_fields["alerting_source_plugin_enabled"].default is False

    def test_disabling_one_source_does_not_change_another(self):
        """Turning off the security source leaves gateway health on."""
        settings = _settings(alerting_source_security_enabled=False)
        assert settings.alerting_source_security_enabled is False
        assert settings.alerting_source_gateway_health_enabled is True


class TestInvalidValuesRejected:
    """Out-of-range and malformed values fail at settings load with a precise message."""

    @pytest.mark.parametrize(
        "field,value",
        [
            ("alerting_dedup_window_seconds", 0),
            ("alerting_dedup_window_seconds", -1),
            ("alerting_dedup_window_seconds", 86401),
            ("alerting_expiry_days", 0),
            ("alerting_retention_days", 0),
            ("alerting_retention_days", 3651),
            ("alerting_max_recipients", 0),
            ("alerting_queue_max_depth", 99),
            ("alerting_dispatch_poll_seconds", 0),
            ("alerting_dispatch_poll_seconds", 61),
            ("alerting_dispatch_batch_size", 0),
            ("alerting_dispatch_batch_size", 1001),
            ("alerting_delivery_max_attempts", 0),
            ("alerting_delivery_max_attempts", 51),
            ("alerting_delivery_lease_seconds", 4),
        ],
    )
    def test_out_of_range_value_is_rejected(self, field, value):
        """A value outside its declared bounds raises a ValidationError that names the field."""
        with pytest.raises(ValidationError) as exc_info:
            _settings(**{field: value})
        assert field in str(exc_info.value)

    def test_non_integer_dedup_window_is_rejected(self):
        """A non-numeric dedup window is rejected rather than silently coerced."""
        with pytest.raises(ValidationError) as exc_info:
            _settings(alerting_dedup_window_seconds="soon")
        assert "alerting_dedup_window_seconds" in str(exc_info.value)

    def test_non_boolean_master_flag_is_rejected(self):
        """A master flag that is not a recognisable boolean is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            _settings(alerting_enabled="maybe")
        assert "alerting_enabled" in str(exc_info.value)


class TestRetentionAgainstExpiry:
    """Retention may never be shorter than expiry."""

    def test_retention_below_expiry_is_rejected_with_both_values_in_message(self):
        """Retention shorter than expiry is rejected and the message reports both numbers."""
        with pytest.raises(ValidationError) as exc_info:
            _settings(alerting_expiry_days=30, alerting_retention_days=10)
        message = str(exc_info.value)
        assert "alerting_retention_days (10)" in message
        assert "alerting_expiry_days (30)" in message

    def test_retention_equal_to_expiry_is_accepted(self):
        """Retention equal to expiry is the boundary and is valid."""
        settings = _settings(alerting_expiry_days=30, alerting_retention_days=30)
        assert settings.alerting_retention_days == settings.alerting_expiry_days

    def test_retention_above_expiry_is_accepted(self):
        """The default ordering (90 days retention, 30 days expiry) is valid."""
        settings = _settings()
        assert settings.alerting_retention_days > settings.alerting_expiry_days


class TestAlertingLoadsFromEnvironment:
    """Environment variables map onto the typed fields."""

    def test_master_flag_and_dedup_window_read_from_env(self, monkeypatch):
        """ALERTING_ENABLED and ALERTING_DEDUP_WINDOW_SECONDS are parsed into typed values."""
        monkeypatch.setenv("ALERTING_ENABLED", "true")
        monkeypatch.setenv("ALERTING_DEDUP_WINDOW_SECONDS", "120")
        settings = Settings()
        assert settings.alerting_enabled is True
        assert settings.alerting_dedup_window_seconds == 120

    def test_invalid_env_value_fails_at_load(self, monkeypatch):
        """An invalid environment value fails settings load, not later at runtime."""
        monkeypatch.setenv("ALERTING_DELIVERY_MAX_ATTEMPTS", "0")
        with pytest.raises(ValidationError) as exc_info:
            Settings()
        assert "alerting_delivery_max_attempts" in str(exc_info.value)
