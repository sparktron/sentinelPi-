"""
tests/test_host_profile.py - Per-host behavioural profile detection.

Verifies the host_profile store and detector: it learns each local host's
usual destination ports and internal peers, then flags the first off-profile
value once that dimension's profile is established. It stays quiet during the
global learning phase and persists learned values across detector instances.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sentinelpi.detectors.host_profile_detector import HostProfileDetector
from sentinelpi.models import AlertCategory, Severity
from sentinelpi.utils import clock


def _conn(src_ip="192.168.1.50", dst_ip="93.184.216.34", dst_port=443):
    from sentinelpi.capture.packet_capture import CapturedConnection
    return CapturedConnection(
        timestamp=datetime(2026, 6, 13, 12, 0, tzinfo=timezone.utc),
        src_ip=src_ip,
        src_port=40000,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol="tcp",
        flags="S",
    )


def _detector(config, db, baseline, device_tracker):
    config.monitoring.host_profile_min_known_ports = 3
    config.monitoring.host_profile_min_known_peers = 2
    baseline._start_time = datetime(2020, 1, 1, tzinfo=timezone.utc)
    return HostProfileDetector(config=config, db=db, baseline=baseline, device_tracker=device_tracker)


def _seed(db, ip, dimension, values):
    for value in values:
        db.record_host_profile_value(ip, dimension, str(value))


def test_record_host_profile_value_newness(db):
    assert db.record_host_profile_value("192.168.1.50", "dst_port", "443") is True
    assert db.record_host_profile_value("192.168.1.50", "dst_port", "443") is False
    assert db.record_host_profile_value("192.168.1.50", "dst_port", "22") is True
    assert db.get_host_profile_values("192.168.1.50", "dst_port") == {"443", "22"}


def test_no_alert_until_port_profile_established(config, db, baseline, device_tracker):
    detector = _detector(config, db, baseline, device_tracker)
    _seed(db, "192.168.1.50", "dst_port", [80, 443])

    assert detector.process_event(_conn(dst_port=22)) == []
    assert "22" in db.get_host_profile_values("192.168.1.50", "dst_port")


def test_alerts_on_new_port_once_established(config, db, baseline, device_tracker):
    detector = _detector(config, db, baseline, device_tracker)
    _seed(db, "192.168.1.50", "dst_port", [53, 80, 443])

    alerts = detector.process_event(_conn(dst_port=445))

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.MEDIUM
    assert alerts[0].category == AlertCategory.CONNECTION_ANOMALY
    assert alerts[0].affected_host == "192.168.1.50"
    assert alerts[0].extra == {"dimension": "dst_port", "value": "445", "known": 3}


def test_known_port_no_alert(config, db, baseline, device_tracker):
    detector = _detector(config, db, baseline, device_tracker)
    _seed(db, "192.168.1.50", "dst_port", [53, 80, 443])

    assert detector.process_event(_conn(dst_port=443)) == []


def test_alerts_on_new_internal_peer_once_established(config, db, baseline, device_tracker):
    detector = _detector(config, db, baseline, device_tracker)
    _seed(db, "192.168.1.50", "peer", ["192.168.1.10", "192.168.1.11"])

    alerts = detector.process_event(_conn(dst_ip="192.168.1.99", dst_port=443))

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.MEDIUM
    assert alerts[0].related_host == "192.168.1.99"
    assert alerts[0].extra == {"dimension": "peer", "value": "192.168.1.99", "known": 2}


def test_external_peer_not_profiled(config, db, baseline, device_tracker):
    detector = _detector(config, db, baseline, device_tracker)
    _seed(db, "192.168.1.50", "peer", ["192.168.1.10", "192.168.1.11"])

    assert detector.process_event(_conn(dst_ip="93.184.216.34", dst_port=443)) == []
    assert "93.184.216.34" not in db.get_host_profile_values("192.168.1.50", "peer")


def test_non_local_source_ignored(config, db, baseline, device_tracker):
    detector = _detector(config, db, baseline, device_tracker)
    _seed(db, "8.8.8.8", "dst_port", [53, 80, 443])

    assert detector.process_event(_conn(src_ip="8.8.8.8", dst_port=22)) == []


def test_learning_phase_records_but_no_alert(config, db, device_tracker):
    from sentinelpi.baseline.engine import BaselineEngine

    config.monitoring.host_profile_min_known_ports = 3
    config.monitoring.baseline_learning_hours = 24
    learning_baseline = BaselineEngine(config, db)
    learning_baseline._start_time = datetime(2026, 6, 13, 11, 0, tzinfo=timezone.utc)
    detector = HostProfileDetector(config=config, db=db, baseline=learning_baseline, device_tracker=device_tracker)
    _seed(db, "192.168.1.50", "dst_port", [53, 80, 443])

    with clock.use_clock(clock.FixedClock(datetime(2026, 6, 13, 12, 0, tzinfo=timezone.utc))):
        assert detector.process_event(_conn(dst_port=22)) == []
    assert "22" in db.get_host_profile_values("192.168.1.50", "dst_port")


def test_persists_across_instances(config, db, baseline, device_tracker):
    config.monitoring.host_profile_min_known_ports = 3
    baseline._start_time = datetime(2020, 1, 1, tzinfo=timezone.utc)
    _seed(db, "192.168.1.50", "dst_port", [53, 80, 443])

    det1 = HostProfileDetector(config=config, db=db, baseline=baseline, device_tracker=device_tracker)
    assert len(det1.process_event(_conn(dst_port=22))) == 1

    det2 = HostProfileDetector(config=config, db=db, baseline=baseline, device_tracker=device_tracker)
    assert det2.process_event(_conn(dst_port=22)) == []
