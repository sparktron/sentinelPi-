"""
tests/test_asn_detector.py - Tests for Phase 1 ASN / hosting-provider tagging.

Covers the ASNLookup graceful-degrade contract and the ASNReputationDetector,
which flags connections to configured suspicious ASNs or operator-name keywords.
ASN lookups are injected, so no GeoLite2-ASN database is needed.
"""

from __future__ import annotations

import pytest

from sentinelpi.detectors.asn_detector import ASNReputationDetector
from sentinelpi.models import AlertCategory, Severity

# Fake ASN db: IP → (asn, org).
_ASN = {
    "203.0.113.10": (13335, "CLOUDFLARENET"),
    "198.51.100.5": (60068, "Bulletproof Hosting LLC"),
    "192.0.2.7": (66666, "Sketchy Hoster"),
    "8.8.8.8": (15169, "GOOGLE"),
}


def _asn_lookup(ip):
    return _ASN.get(ip, (0, ""))


def _conn(dst_ip, src_ip="192.168.1.50"):
    from sentinelpi.capture.packet_capture import CapturedConnection
    from sentinelpi.utils import clock
    return CapturedConnection(
        timestamp=clock.now(), src_ip=src_ip, src_port=40000,
        dst_ip=dst_ip, dst_port=443, protocol="tcp", flags="S",
    )


def _detector(config, db, baseline, device_tracker):
    return ASNReputationDetector(
        config=config, db=db, baseline=baseline, device_tracker=device_tracker,
        asn_lookup=_asn_lookup,
    )


# --------------------------------------------------------------------- lookup
def test_asn_lookup_unavailable_returns_unknown():
    from sentinelpi.utils.asn import ASNLookup
    look = ASNLookup("/nonexistent/GeoLite2-ASN.mmdb")
    assert look.available is False
    assert look.lookup_asn("8.8.8.8") == (0, "")


# ------------------------------------------------------------------- keywords
def test_builtin_bulletproof_keyword_flags(config, db, baseline, device_tracker):
    det = _detector(config, db, baseline, device_tracker)
    alerts = det.process_event(_conn("198.51.100.5"))
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.MEDIUM
    assert alerts[0].category == AlertCategory.CONNECTION_ANOMALY
    assert alerts[0].extra["asn"] == 60068


def test_clean_provider_not_flagged(config, db, baseline, device_tracker):
    det = _detector(config, db, baseline, device_tracker)
    assert det.process_event(_conn("203.0.113.10")) == []  # Cloudflare
    assert det.process_event(_conn("8.8.8.8")) == []        # Google


def test_unknown_asn_is_silent(config, db, baseline, device_tracker):
    det = _detector(config, db, baseline, device_tracker)
    assert det.process_event(_conn("1.2.3.4")) == []  # not in fake db → (0, "")


# ----------------------------------------------------------- configurable lists
def test_configured_suspicious_asn_flags(config, db, baseline, device_tracker):
    config.monitoring.suspicious_asns = [15169]  # flag Google for this test
    det = _detector(config, db, baseline, device_tracker)
    alerts = det.process_event(_conn("8.8.8.8"))
    assert len(alerts) == 1
    assert "15169" in alerts[0].confidence_rationale


def test_configured_keyword_flags(config, db, baseline, device_tracker):
    config.monitoring.suspicious_asn_keywords = ["sketchy"]
    det = _detector(config, db, baseline, device_tracker)
    alerts = det.process_event(_conn("192.0.2.7"))
    assert len(alerts) == 1
    assert alerts[0].extra["org"] == "Sketchy Hoster"


# ------------------------------------------------------------------ skip rules
def test_private_destination_ignored(config, db, baseline, device_tracker):
    det = _detector(config, db, baseline, device_tracker)
    assert det.process_event(_conn("10.0.0.5")) == []


def test_whitelisted_destination_ignored(config, db, baseline, device_tracker):
    config.whitelist_ips = ["198.51.100.5"]
    det = _detector(config, db, baseline, device_tracker)
    assert det.process_event(_conn("198.51.100.5")) == []


def test_cooldown_suppresses_repeat(config, db, baseline, device_tracker):
    det = _detector(config, db, baseline, device_tracker)
    first = det.process_event(_conn("198.51.100.5"))
    second = det.process_event(_conn("198.51.100.5"))
    assert len(first) == 1 and second == []
