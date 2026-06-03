"""
tests/test_geo_country_detector.py - Tests for Phase 1 new-country detection.

Covers the host_countries DB store and the GeoCountryDetector, which alerts the
first time a local host connects to a previously-unseen country. GeoIP lookups
are injected, so no GeoLite2 database is needed.
"""

from __future__ import annotations

import pytest

from sentinelpi.detectors.geo_country_detector import GeoCountryDetector
from sentinelpi.models import AlertCategory, Severity

# Fake GeoIP: maps test IPs to country codes/names.
_GEO = {"203.0.113.10": "US", "198.51.100.5": "RU", "192.0.2.7": "DE"}
_NAMES = {"203.0.113.10": "United States", "198.51.100.5": "Russia", "192.0.2.7": "Germany"}


def _geo_lookup(ip):
    return _GEO.get(ip, "")


def _name_lookup(ip):
    return _NAMES.get(ip, "")


def _conn(dst_ip, src_ip="192.168.1.50"):
    from sentinelpi.capture.packet_capture import CapturedConnection
    from sentinelpi.utils import clock
    return CapturedConnection(
        timestamp=clock.now(), src_ip=src_ip, src_port=40000,
        dst_ip=dst_ip, dst_port=443, protocol="tcp", flags="S",
    )


@pytest.fixture
def geo_detector(config, db, baseline, device_tracker):
    return GeoCountryDetector(
        config=config, db=db, baseline=baseline, device_tracker=device_tracker,
        geo_lookup=_geo_lookup, name_lookup=_name_lookup,
    )


# ------------------------------------------------------------------- DB store
def test_record_host_country_newness(db):
    assert db.record_host_country("192.168.1.50", "US") is True
    assert db.record_host_country("192.168.1.50", "US") is False  # already known
    assert db.record_host_country("192.168.1.50", "RU") is True   # new country
    assert db.get_host_countries("192.168.1.50") == {"US", "RU"}


# -------------------------------------------------------------------- detector
def test_first_country_triggers_alert(geo_detector):
    alerts = geo_detector.process_event(_conn("203.0.113.10"))
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.MEDIUM
    assert alerts[0].category == AlertCategory.CONNECTION_ANOMALY
    assert alerts[0].extra["country"] == "US"
    assert "United States" in alerts[0].title


def test_same_country_no_repeat(geo_detector):
    assert len(geo_detector.process_event(_conn("203.0.113.10"))) == 1
    # Another US IP — same country, already known for this host.
    _GEO["203.0.113.99"] = "US"
    assert geo_detector.process_event(_conn("203.0.113.99")) == []


def test_different_country_triggers_again(geo_detector):
    assert len(geo_detector.process_event(_conn("203.0.113.10"))) == 1   # US
    assert len(geo_detector.process_event(_conn("198.51.100.5"))) == 1   # RU


def test_unknown_geo_is_silent(geo_detector):
    # IP not in the GeoIP db → lookup returns "" → no alert, nothing recorded.
    assert geo_detector.process_event(_conn("8.8.8.8")) == []


def test_private_destination_ignored(geo_detector):
    assert geo_detector.process_event(_conn("10.0.0.5")) == []


def test_whitelisted_destination_ignored(config, db, baseline, device_tracker):
    config.whitelist_ips = ["198.51.100.5"]
    det = GeoCountryDetector(
        config=config, db=db, baseline=baseline, device_tracker=device_tracker,
        geo_lookup=_geo_lookup, name_lookup=_name_lookup,
    )
    assert det.process_event(_conn("198.51.100.5")) == []


def test_persists_across_detector_instances(config, db, baseline, device_tracker):
    det1 = GeoCountryDetector(
        config=config, db=db, baseline=baseline, device_tracker=device_tracker,
        geo_lookup=_geo_lookup, name_lookup=_name_lookup,
    )
    assert len(det1.process_event(_conn("192.0.2.7"))) == 1   # DE, first time

    # A fresh detector (simulating a restart) seeds from the DB and stays quiet.
    det2 = GeoCountryDetector(
        config=config, db=db, baseline=baseline, device_tracker=device_tracker,
        geo_lookup=_geo_lookup, name_lookup=_name_lookup,
    )
    assert det2.process_event(_conn("192.0.2.7")) == []


def test_learning_phase_records_but_does_not_alert(config, db, device_tracker):
    from sentinelpi.baseline.engine import BaselineEngine

    config.monitoring.baseline_learning_hours = 24  # still learning
    learning_baseline = BaselineEngine(config, db)
    det = GeoCountryDetector(
        config=config, db=db, baseline=learning_baseline, device_tracker=device_tracker,
        geo_lookup=_geo_lookup, name_lookup=_name_lookup,
    )

    assert det.process_event(_conn("203.0.113.10")) == []     # no alert while learning
    assert db.get_host_countries("192.168.1.50") == {"US"}    # but the country is recorded
