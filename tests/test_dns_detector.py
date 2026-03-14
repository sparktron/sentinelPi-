"""
tests/test_dns_detector.py - Tests for DNS anomaly detection.

Tests:
- High-entropy DGA domain names trigger alerts
- Normal domains do not trigger alerts
- NXDOMAIN rate detection
- DNS tunneling (long subdomain label)
- Whitelisted domains are skipped
"""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta

from sentinelpi.detectors.dns_detector import DNSDetector
from sentinelpi.models import AlertCategory, Severity
from tests.fixtures.sample_data import make_dga_dns_events, make_dns_tunnel_event


@pytest.fixture
def dns_detector(config, db, baseline, device_tracker):
    return DNSDetector(config=config, db=db, baseline=baseline, device_tracker=device_tracker)


class TestDNSDetector:

    def test_dga_domains_trigger_alerts(self, dns_detector):
        """High-entropy DGA-like domains should trigger DNS anomaly alerts."""
        events = make_dga_dns_events(count=30)
        alerts = []
        for event in events:
            alerts.extend(dns_detector.process_event(event))

        # Should see NXDOMAIN rate or entropy alerts
        dns_alerts = [a for a in alerts if a.category == AlertCategory.DNS_ANOMALY]
        assert len(dns_alerts) > 0, (
            f"Expected DNS anomaly alerts for DGA-like traffic, got none. "
            f"All alerts: {[a.title for a in alerts]}"
        )

    def test_normal_domain_no_alert(self, dns_detector):
        """Well-known low-entropy domains should not trigger alerts."""
        from sentinelpi.capture.packet_capture import CapturedDNS
        normal = CapturedDNS(
            timestamp=datetime.utcnow(),
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            query_name="google.com",
            query_type="A",
            is_response=False,
            is_nxdomain=False,
        )
        alerts = dns_detector.process_event(normal)
        assert len(alerts) == 0, f"Normal domain should not trigger alerts: {[a.title for a in alerts]}"

    def test_dns_tunneling_long_label(self, dns_detector):
        """Very long subdomain label should trigger DNS tunneling alert."""
        event = make_dns_tunnel_event()
        alerts = dns_detector.process_event(event)

        tunnel_alerts = [a for a in alerts if "tunnel" in a.title.lower() or "long" in a.description.lower()]
        assert len(tunnel_alerts) > 0, (
            f"Expected DNS tunneling alert. Got: {[a.title for a in alerts]}"
        )

    def test_nxdomain_flood_triggers_alert(self, dns_detector):
        """High rate of NXDOMAIN responses should trigger alert."""
        events = make_dga_dns_events(src_ip="192.168.1.100", count=30)

        alerts = []
        for event in events:
            alerts.extend(dns_detector.process_event(event))

        nxdomain_alerts = [
            a for a in alerts
            if "nxdomain" in a.title.lower() or "nxdomain" in a.description.lower()
        ]
        # With 30 NXDOMAINs, should trigger
        assert len(nxdomain_alerts) > 0, (
            f"Expected NXDOMAIN rate alert. All alerts: {[a.title for a in alerts]}"
        )

    def test_whitelisted_domain_no_alert(self, dns_detector, config):
        """Whitelisted domains should never trigger alerts."""
        config.whitelist_domains = ["cloudfront.net"]
        from sentinelpi.capture.packet_capture import CapturedDNS

        # High-entropy but whitelisted CDN subdomain
        event = CapturedDNS(
            timestamp=datetime.utcnow(),
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            query_name="d3abc123xyz.cloudfront.net",
            query_type="A",
            is_response=False,
        )
        alerts = dns_detector.process_event(event)
        assert len(alerts) == 0, f"Whitelisted domain triggered alerts: {[a.title for a in alerts]}"

    def test_alert_fields_complete(self, dns_detector):
        """DNS anomaly alerts must have all required fields."""
        event = make_dns_tunnel_event()
        alerts = dns_detector.process_event(event)

        for alert in alerts:
            assert alert.severity in list(Severity)
            assert alert.category == AlertCategory.DNS_ANOMALY
            assert alert.affected_host
            assert alert.title
            assert alert.description
            assert alert.recommended_action
            assert alert.dedup_key
