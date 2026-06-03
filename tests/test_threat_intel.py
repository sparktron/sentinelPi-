"""
tests/test_threat_intel.py - Tests for Phase 1 threat-intel blocklist matching.

Covers the pure feed parsers, the ThreatIntelService match/refresh/cache logic
(with an injected fetcher — no network), and the ThreatIntelDetector promoting
known-bad destinations to HIGH alerts.
"""

from __future__ import annotations

import pytest

from sentinelpi.config.manager import ThreatIntelConfig
from sentinelpi.intel.threat_feeds import (
    ThreatIntelService,
    _parse_line_list,
    _parse_spamhaus_drop,
    _parse_urlhaus_hosts,
    _host_from_url,
    _classify_host,
)


# ------------------------------------------------------------------- parsers
def test_parse_line_list_skips_comments_and_blanks():
    text = "# header\n\n45.9.148.99\n185.220.101.1   extra\n# trailing\n"
    assert _parse_line_list(text) == ["45.9.148.99", "185.220.101.1"]


def test_parse_spamhaus_drop_extracts_cidr_only():
    text = "; comment\n1.10.16.0/20 ; SBL256894\n223.254.0.0/16 ; SBL230805\n"
    assert _parse_spamhaus_drop(text) == ["1.10.16.0/20", "223.254.0.0/16"]


def test_parse_urlhaus_extracts_hosts():
    text = "# urls\nhttp://evil.example.com/payload.exe\nhttps://1.2.3.4:8080/x\n"
    assert _parse_urlhaus_hosts(text) == ["evil.example.com", "1.2.3.4"]


def test_host_from_url_strips_scheme_port_path_userinfo():
    assert _host_from_url("https://user:pw@Bad.Example.com:443/a/b") == "bad.example.com"


def test_classify_host():
    assert _classify_host("8.8.8.8") == "ip"
    assert _classify_host("evil.example.com") == "domain"


# ------------------------------------------------------------------- service
def _service_with(tmp_path, feeds: dict, feed_names) -> ThreatIntelService:
    """Build a service whose cache dir is pre-seeded with the given feed text."""
    cfg = ThreatIntelConfig(enabled=True, cache_dir=str(tmp_path), feeds=feed_names)
    svc = ThreatIntelService(cfg)
    for name, text in feeds.items():
        (tmp_path / f"{name}.txt").write_text(text, encoding="utf-8")
    svc.load()
    return svc


def test_service_matches_exact_ip(tmp_path):
    svc = _service_with(tmp_path, {"feodo": "45.9.148.99\n"}, ["feodo"])
    hit = svc.match_ip("45.9.148.99")
    assert hit is not None
    assert hit.source == "feodo"
    assert hit.kind == "ip"
    assert svc.match_ip("8.8.8.8") is None


def test_service_matches_cidr(tmp_path):
    svc = _service_with(tmp_path, {"spamhaus_drop": "1.10.16.0/20 ; SBL1\n"}, ["spamhaus_drop"])
    assert svc.match_ip("1.10.16.5") is not None
    assert svc.match_ip("1.10.99.5") is None


def test_service_matches_domain_and_parent(tmp_path):
    svc = _service_with(tmp_path, {"urlhaus": "http://evil.example.com/x\n"}, ["urlhaus"])
    assert svc.match_domain("evil.example.com") is not None
    # subdomain of a listed domain matches the parent indicator
    assert svc.match_domain("a.b.evil.example.com") is not None
    # a different domain that merely shares a suffix label does not
    assert svc.match_domain("notevil.example.com") is None
    assert svc.match_domain("example.com") is None


def test_unknown_feed_is_skipped(tmp_path):
    svc = _service_with(tmp_path, {}, ["does_not_exist"])
    assert svc.indicator_count == 0


def test_missing_cache_yields_no_indicators(tmp_path):
    cfg = ThreatIntelConfig(enabled=True, cache_dir=str(tmp_path), feeds=["feodo"])
    svc = ThreatIntelService(cfg)
    svc.load()  # no cache files written
    assert svc.indicator_count == 0
    assert svc.match_ip("45.9.148.99") is None


def test_refresh_uses_injected_fetcher_and_caches(tmp_path):
    cfg = ThreatIntelConfig(enabled=True, cache_dir=str(tmp_path), feeds=["feodo"])
    calls = []

    def fake_fetch(url, timeout):
        calls.append(url)
        return "45.9.148.99\n185.220.101.1\n"

    svc = ThreatIntelService(cfg, fetcher=fake_fetch)
    assert svc.refresh() is True
    assert calls and "feodotracker" in calls[0]
    assert svc.match_ip("45.9.148.99") is not None
    # Cache file was written for reuse on next startup.
    assert (tmp_path / "feodo.txt").exists()


def test_refresh_failure_keeps_previous_cache(tmp_path):
    cfg = ThreatIntelConfig(enabled=True, cache_dir=str(tmp_path), feeds=["feodo"])
    (tmp_path / "feodo.txt").write_text("45.9.148.99\n", encoding="utf-8")

    def boom(url, timeout):
        raise ConnectionError("network down")

    svc = ThreatIntelService(cfg, fetcher=boom)
    assert svc.refresh() is False
    # Fell back to the existing cache rather than wiping it.
    assert svc.match_ip("45.9.148.99") is not None


# ------------------------------------------------------------------- detector
@pytest.fixture
def intel_detector(config, db, baseline, device_tracker, tmp_path):
    from sentinelpi.detectors.threat_intel_detector import ThreatIntelDetector

    svc = _service_with(
        tmp_path,
        {"feodo": "45.9.148.99\n", "urlhaus": "http://evil.example.com/x\n"},
        ["feodo", "urlhaus"],
    )
    det = ThreatIntelDetector(
        config=config, db=db, baseline=baseline, device_tracker=device_tracker, intel=svc
    )
    return det


def _conn(dst_ip, src_ip="192.168.1.50"):
    from sentinelpi.capture.packet_capture import CapturedConnection
    from sentinelpi.utils import clock
    return CapturedConnection(
        timestamp=clock.now(), src_ip=src_ip, src_port=44000,
        dst_ip=dst_ip, dst_port=443, protocol="tcp", flags="S",
    )


def _dns(query_name, response_ip="", src_ip="192.168.1.50"):
    from sentinelpi.capture.packet_capture import CapturedDNS
    from sentinelpi.utils import clock
    return CapturedDNS(
        timestamp=clock.now(), src_ip=src_ip, dst_ip="192.168.1.1",
        query_name=query_name, query_type="A", is_response=bool(response_ip),
        response_ip=response_ip,
    )


def test_detector_flags_known_bad_ip(intel_detector):
    from sentinelpi.models import Severity, AlertCategory
    alerts = intel_detector.process_event(_conn("45.9.148.99"))
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.HIGH
    assert alerts[0].category == AlertCategory.THREAT_INTEL
    assert alerts[0].related_host == "45.9.148.99"


def test_detector_flags_known_bad_domain(intel_detector):
    from sentinelpi.models import Severity
    alerts = intel_detector.process_event(_dns("a.evil.example.com"))
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.HIGH


def test_detector_flags_resolved_bad_ip(intel_detector):
    alerts = intel_detector.process_event(_dns("lookup.example.net", response_ip="45.9.148.99"))
    assert len(alerts) == 1
    assert alerts[0].related_host == "45.9.148.99"


def test_detector_ignores_clean_traffic(intel_detector):
    assert intel_detector.process_event(_conn("8.8.8.8")) == []
    assert intel_detector.process_event(_dns("good.example.com")) == []


def test_detector_ignores_local_destination(intel_detector):
    # Even if a local IP somehow appeared on a list, internal traffic is skipped.
    assert intel_detector.process_event(_conn("192.168.1.99")) == []


def test_detector_cooldown_suppresses_repeat(intel_detector):
    first = intel_detector.process_event(_conn("45.9.148.99"))
    second = intel_detector.process_event(_conn("45.9.148.99"))
    assert len(first) == 1
    assert second == []  # within cooldown
