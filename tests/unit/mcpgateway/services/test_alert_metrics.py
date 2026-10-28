# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/services/test_alert_metrics.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Tests for the alerting Prometheus metrics (Issue #5805, PRD FR-27).

The tests use the real default prometheus registry. They check that the eight
alert collectors are registered, that re-importing the module does not duplicate
them, and that label values stay bounded.
"""

# Third-Party
from prometheus_client import REGISTRY
import pytest

# First-Party
from mcpgateway.services import metrics as metrics_module
from mcpgateway.services.metrics import (
    ALERT_CHANNELS,
    ALERT_OTHER_LABEL,
    ALERT_SEVERITIES,
    ALERT_SOURCES,
    alert_deliveries_dropped_total,
    alert_deliveries_total,
    alert_delivery_latency_seconds,
    alert_queue_depth,
    alert_time_to_ack_seconds,
    alerts_created_total,
    alerts_deduplicated_total,
    alerts_open,
    normalize_alert_label,
)

# Registry names (the key used by _get_registry_collector) for the eight alert collectors.
EXPECTED_REGISTRY_NAMES = {
    "alerts_created_total",
    "alerts_deduplicated_total",
    "alert_deliveries_total",
    "alert_delivery_latency_seconds",
    "alert_queue_depth",
    "alert_deliveries_dropped_total",
    "alerts_open",
    "alert_time_to_ack_seconds",
}


def _collector_names():
    """Return the set of metric family names currently exposed by the default registry.

    Returns:
        set[str]: Family names as Prometheus reports them.
    """
    return {family.name for family in REGISTRY.collect()}


class TestRegistration:
    """All eight alert collectors are registered exactly once."""

    @pytest.mark.parametrize(
        "name",
        [
            "alerts_created",
            "alerts_deduplicated",
            "alert_deliveries",
            "alert_delivery_latency_seconds",
            "alert_queue_depth",
            "alert_deliveries_dropped",
            "alerts_open",
            "alert_time_to_ack_seconds",
        ],
    )
    def test_family_is_exposed_by_the_default_registry(self, name):
        """Each documented alert metric family appears in the default registry."""
        assert name in _collector_names()

    def test_all_eight_registry_keys_resolve_to_collectors(self):
        """The registry lookup used by the factory finds all eight collectors."""
        for name in EXPECTED_REGISTRY_NAMES:
            assert metrics_module._get_registry_collector(name) is not None  # pylint: disable=protected-access

    def test_module_collector_is_the_instance_held_by_the_registry(self):
        """The module-level collector is the same object the default registry holds, so nothing is duplicated."""
        registered = metrics_module._get_registry_collector("alerts_created_total")  # pylint: disable=protected-access
        assert metrics_module.alerts_created_total is registered

    def test_get_or_create_returns_existing_collector_without_registering_again(self):
        """Asking the factory for an already-registered name returns the existing collector and does not call the factory."""
        calls = []

        def _factory():
            """Record a construction attempt.

            Returns:
                None: Never reached for an existing name.
            """
            calls.append(True)

        existing = metrics_module._get_or_create_collector("alerts_created_total", _factory)  # pylint: disable=protected-access
        assert existing is metrics_module.alerts_created_total
        assert calls == []


class TestBoundedLabels:
    """Free text and identifiers never become label values."""

    def test_label_sets_are_the_documented_bounded_sets(self):
        """The allow-lists match the PRD: five sources, four severities, three channels."""
        assert ALERT_SOURCES == ("security", "gateway_health", "performance", "a2a", "plugin")
        assert ALERT_SEVERITIES == ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert ALERT_CHANNELS == ("in_app", "email", "webhook")

    def test_unknown_source_maps_to_other(self):
        """A source outside the allow-list is folded into 'other' rather than creating a series."""
        assert normalize_alert_label("weather-plugin-xyz", ALERT_SOURCES) == ALERT_OTHER_LABEL

    def test_email_address_as_severity_maps_to_other(self):
        """A user identifier used as a severity value cannot create a new time series."""
        assert normalize_alert_label("alice@example.com", ALERT_SEVERITIES) == ALERT_OTHER_LABEL

    def test_uuid_as_channel_maps_to_other(self):
        """An alert or team identifier used as a channel value is folded into 'other'."""
        assert normalize_alert_label("9f8e7d6c5b4a39281716151413121110", ALERT_CHANNELS) == ALERT_OTHER_LABEL

    def test_case_insensitive_match_returns_canonical_member(self):
        """A differently cased known value returns the canonical allow-list member."""
        assert normalize_alert_label("high", ALERT_SEVERITIES) == "HIGH"
        assert normalize_alert_label("  In_App ", ALERT_CHANNELS) == "in_app"

    def test_none_and_non_string_values_fall_back_to_default(self):
        """None and non-string values return the supplied default, never raise."""
        assert normalize_alert_label(None, ALERT_SOURCES, default="security") == "security"
        assert normalize_alert_label(42, ALERT_SEVERITIES) == ALERT_OTHER_LABEL

    def test_enum_like_value_is_unwrapped(self):
        """An enum-style object contributes its .value to the match."""

        class _Sev:
            """Minimal enum stand-in exposing a value attribute."""

            value = "CRITICAL"

        assert normalize_alert_label(_Sev(), ALERT_SEVERITIES) == "CRITICAL"

    def test_created_counter_is_labelled_only_by_bounded_dimensions(self):
        """The created counter is labelled only by source and severity, the two bounded dimensions."""
        assert tuple(alerts_created_total._labelnames) == ("source", "severity")  # pylint: disable=protected-access

    def test_delivery_counter_labels_are_channel_and_result(self):
        """The delivery counter is labelled only by channel and result."""
        assert tuple(alert_deliveries_total._labelnames) == ("channel", "result")  # pylint: disable=protected-access

    def test_no_alert_metric_carries_user_or_team_label(self):
        """No alert collector exposes a user, team or alert-identifier label."""
        forbidden = {"user", "user_email", "team", "team_id", "alert_id", "email"}
        for collector in (alerts_created_total, alerts_deduplicated_total, alert_deliveries_total, alerts_open, alerts_deduplicated_total, alert_deliveries_dropped_total):
            labels = set(collector._labelnames)  # pylint: disable=protected-access
            assert not (labels & forbidden), f"{collector} has an unbounded label"

    def test_gauges_and_histograms_expose_expected_shapes(self):
        """Queue depth is an unlabelled gauge; the ack and latency histograms are labelled as designed."""
        assert tuple(alert_queue_depth._labelnames) == ()  # pylint: disable=protected-access
        assert tuple(alerts_open._labelnames) == ("severity",)  # pylint: disable=protected-access
        assert tuple(alert_delivery_latency_seconds._labelnames) == ("channel",)  # pylint: disable=protected-access
        assert tuple(alert_time_to_ack_seconds._labelnames) == ()  # pylint: disable=protected-access
