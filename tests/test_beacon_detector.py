"""
tests/test_beacon_detector.py - Unit tests for beacon detection.

Tests:
- Regular interval connections → beacon alert
- Irregular (user-driven) connections → no alert
- Not enough data points → no alert
- Known destination in baseline → lower severity
"""

from __future__ import annotations

import pytest
from datetime import datetime

from sentinelpi.detectors.beacon_detector import BeaconDetector
from sentinelpi.models import AlertCategory
from tests.fixtures.sample_data import make_beacon_events, make_irregular_events


@pytest.fixture
def beacon_detector(config, db, baseline, device_tracker):
    return BeaconDetector(config=config, db=db, baseline=baseline, device_tracker=device_tracker)


class TestBeaconDetector:

    def test_regular_intervals_trigger_beacon_alert(self, beacon_detector):
        """Very regular outbound connections should trigger a BEACON alert."""
        events = make_beacon_events(
            src_ip="192.168.1.100",
            dst_ip="198.51.100.42",
            dst_port=4444,   # Suspicious port
            interval_seconds=60.0,
            jitter_fraction=0.03,
            count=15,
        )

        alerts = []
        for event in events:
            new_alerts = beacon_detector.process_event(event)
            alerts.extend(new_alerts)

        assert len(alerts) > 0, "Expected beacon alert for regular-interval connections"
        assert any(a.category == AlertCategory.BEACON for a in alerts)
        assert any("beacon" in a.title.lower() for a in alerts)

    def test_irregular_traffic_no_alert(self, beacon_detector):
        """Irregular (user-driven) traffic should not trigger beacon detection."""
        events = make_irregular_events(
            src_ip="192.168.1.100",
            dst_ip="93.184.216.34",
            dst_port=443,
            count=20,
        )

        alerts = []
        for event in events:
            alerts.extend(beacon_detector.process_event(event))

        beacon_alerts = [a for a in alerts if a.category == AlertCategory.BEACON]
        assert len(beacon_alerts) == 0, (
            f"Expected no beacon alerts for irregular traffic, got: {[a.title for a in beacon_alerts]}"
        )

    def test_insufficient_data_no_alert(self, beacon_detector):
        """Not enough data points should not trigger any alert."""
        events = make_beacon_events(
            count=3,   # Below minimum
            interval_seconds=60.0,
            jitter_fraction=0.01,
        )

        alerts = []
        for event in events:
            alerts.extend(beacon_detector.process_event(event))

        assert len(alerts) == 0, "Expected no alerts with insufficient data"

    def test_beacon_confidence_field_present(self, beacon_detector):
        """Beacon alerts should include a valid confidence score."""
        events = make_beacon_events(
            interval_seconds=30.0,
            jitter_fraction=0.02,
            count=15,
        )

        alerts = []
        for event in events:
            alerts.extend(beacon_detector.process_event(event))

        for alert in alerts:
            assert 0.0 <= alert.confidence <= 1.0, f"Invalid confidence: {alert.confidence}"
            assert alert.confidence_rationale, "Expected non-empty confidence_rationale"

    def test_beacon_alert_has_recommended_action(self, beacon_detector):
        """Every beacon alert must include a recommended action."""
        events = make_beacon_events(count=15, interval_seconds=45.0, jitter_fraction=0.02)
        alerts = []
        for event in events:
            alerts.extend(beacon_detector.process_event(event))

        for alert in [a for a in alerts if a.category == AlertCategory.BEACON]:
            assert alert.recommended_action, "Expected recommended_action in beacon alert"
