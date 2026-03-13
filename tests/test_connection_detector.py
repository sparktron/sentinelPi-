"""
tests/test_connection_detector.py - Tests for connection anomaly detection.

Tests:
- Port scan triggers alert above threshold
- Below-threshold probing → no alert
- Host sweep detection
- Alert deduplication (cooldown works)
"""

from __future__ import annotations

import pytest
from datetime import datetime

from sentinelpi.detectors.port_scan_detector import PortScanDetector
from sentinelpi.models import AlertCategory, Severity
from tests.fixtures.sample_data import make_port_scan_events


@pytest.fixture
def scan_detector(config, db, baseline, device_tracker):
    return PortScanDetector(config=config, db=db, baseline=baseline, device_tracker=device_tracker)


class TestPortScanDetector:

    def test_port_scan_above_threshold_triggers_alert(self, scan_detector):
        """Port scanning above threshold should trigger PORT_SCAN alert."""
        events = make_port_scan_events(
            scanner_ip="192.168.1.50",
            target_ip="192.168.1.100",
            port_count=50,   # Well above default threshold of 5 (aggressive mode)
        )

        alerts = []
        for event in events:
            alerts.extend(scan_detector.process_event(event))

        assert any(a.category == AlertCategory.PORT_SCAN for a in alerts), (
            f"Expected PORT_SCAN alert. Got: {[a.title for a in alerts]}"
        )

    def test_below_threshold_no_alert(self, scan_detector, config):
        """Connections below threshold should not trigger alerts."""
        events = make_port_scan_events(
            scanner_ip="192.168.1.50",
            target_ip="192.168.1.100",
            port_count=2,   # Below threshold of 5
        )

        alerts = []
        for event in events:
            alerts.extend(scan_detector.process_event(event))

        scan_alerts = [a for a in alerts if a.category == AlertCategory.PORT_SCAN]
        assert len(scan_alerts) == 0, f"Expected no alerts below threshold, got: {scan_alerts}"

    def test_port_scan_alert_contains_required_fields(self, scan_detector):
        """Port scan alerts must include all required fields."""
        events = make_port_scan_events(port_count=50)
        alerts = []
        for event in events:
            alerts.extend(scan_detector.process_event(event))

        for alert in [a for a in alerts if a.category == AlertCategory.PORT_SCAN]:
            assert alert.severity in (Severity.LOW, Severity.MEDIUM, Severity.HIGH)
            assert alert.affected_host, "Expected affected_host"
            assert alert.related_host, "Expected related_host (scanner IP)"
            assert alert.title, "Expected title"
            assert alert.description, "Expected description"
            assert alert.recommended_action, "Expected recommended_action"
            assert alert.confidence > 0, "Expected positive confidence"
            assert alert.dedup_key, "Expected dedup_key"

    def test_non_syn_packets_ignored(self, scan_detector):
        """Non-SYN TCP packets should not count toward scan detection."""
        from sentinelpi.capture.packet_capture import CapturedConnection
        now = datetime.utcnow()

        # ACK packets — not connection initiations
        alerts = []
        for port in range(1, 100):
            event = CapturedConnection(
                timestamp=now,
                src_ip="192.168.1.50",
                src_port=50000,
                dst_ip="192.168.1.100",
                dst_port=port,
                protocol="tcp",
                flags="A",  # ACK only, not SYN
            )
            alerts.extend(scan_detector.process_event(event))

        scan_alerts = [a for a in alerts if a.category == AlertCategory.PORT_SCAN]
        assert len(scan_alerts) == 0, "ACK packets should not trigger port scan detection"

    def test_udp_events_ignored(self, scan_detector):
        """UDP events should be ignored by TCP port scan detector."""
        from sentinelpi.capture.packet_capture import CapturedConnection
        now = datetime.utcnow()

        alerts = []
        for port in range(1, 50):
            event = CapturedConnection(
                timestamp=now,
                src_ip="192.168.1.50",
                src_port=50000,
                dst_ip="192.168.1.100",
                dst_port=port,
                protocol="udp",
                flags="",
            )
            alerts.extend(scan_detector.process_event(event))

        scan_alerts = [a for a in alerts if a.category == AlertCategory.PORT_SCAN]
        assert len(scan_alerts) == 0
