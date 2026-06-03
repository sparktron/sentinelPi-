"""
tests/test_doh_detector.py - Tests for Phase 1 DoH/DoT bypass detection.

The detector flags local clients resolving names over encrypted DNS (DoT on
TCP 853, or DoH on TCP 443 to a known resolver IP), bypassing the configured
DNS. Sanctioned resolvers and local/whitelisted destinations are skipped.
"""

from __future__ import annotations

import pytest

from sentinelpi.detectors.doh_detector import DoHDetector
from sentinelpi.models import AlertCategory, Severity


@pytest.fixture
def doh_detector(config, db, baseline, device_tracker):
    return DoHDetector(config=config, db=db, baseline=baseline, device_tracker=device_tracker)


def _conn(dst_ip, dst_port, src_ip="192.168.1.50", protocol="tcp"):
    from sentinelpi.capture.packet_capture import CapturedConnection
    from sentinelpi.utils import clock
    return CapturedConnection(
        timestamp=clock.now(), src_ip=src_ip, src_port=51000,
        dst_ip=dst_ip, dst_port=dst_port, protocol=protocol, flags="S",
    )


def test_dot_to_any_external_is_flagged(doh_detector):
    alerts = doh_detector.process_event(_conn("203.0.113.50", 853))
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.MEDIUM
    assert alerts[0].category == AlertCategory.DNS_ANOMALY
    assert alerts[0].extra["mode"] == "DoT"


def test_doh_to_known_resolver_is_flagged(doh_detector):
    alerts = doh_detector.process_event(_conn("1.1.1.1", 443))
    assert len(alerts) == 1
    assert alerts[0].extra["mode"] == "DoH"
    assert alerts[0].extra["provider"] == "Cloudflare"


def test_https_to_unknown_ip_is_not_flagged(doh_detector):
    # Port 443 to a non-resolver IP is just normal HTTPS.
    assert doh_detector.process_event(_conn("93.184.216.34", 443)) == []


def test_known_resolver_name_resolution(doh_detector):
    alerts = doh_detector.process_event(_conn("9.9.9.9", 853))
    assert alerts[0].extra["provider"] == "Quad9"


def test_local_destination_is_ignored(doh_detector):
    # DoT to a local resolver (e.g. your own Pi-hole) is not a bypass.
    assert doh_detector.process_event(_conn("192.168.1.1", 853)) == []


def test_non_tcp_is_ignored(doh_detector):
    assert doh_detector.process_event(_conn("1.1.1.1", 443, protocol="udp")) == []


def test_sanctioned_resolver_is_skipped(config, db, baseline, device_tracker):
    config.monitoring.doh_sanctioned_resolvers = ["1.1.1.1"]
    det = DoHDetector(config=config, db=db, baseline=baseline, device_tracker=device_tracker)
    assert det.process_event(_conn("1.1.1.1", 443)) == []
    # A different resolver is still flagged.
    assert len(det.process_event(_conn("8.8.8.8", 853))) == 1


def test_whitelisted_destination_is_skipped(config, db, baseline, device_tracker):
    config.whitelist_ips = ["1.1.1.1"]
    det = DoHDetector(config=config, db=db, baseline=baseline, device_tracker=device_tracker)
    assert det.process_event(_conn("1.1.1.1", 443)) == []


def test_cooldown_suppresses_repeat(doh_detector):
    first = doh_detector.process_event(_conn("1.1.1.1", 443))
    second = doh_detector.process_event(_conn("1.1.1.1", 443))
    assert len(first) == 1
    assert second == []


def test_different_client_not_suppressed(doh_detector):
    a = doh_detector.process_event(_conn("8.8.8.8", 853, src_ip="192.168.1.10"))
    b = doh_detector.process_event(_conn("8.8.8.8", 853, src_ip="192.168.1.11"))
    assert len(a) == 1 and len(b) == 1
