"""
tests/test_active_hours.py - Per-host active-hours anomaly detection (Phase 4).

Verifies the host_activity_hours store and the detector: it learns a host's
normal hours and flags the first activity in a never-before-seen hour, but only
once the host's profile is established (and not during global learning).
Time is pinned with FixedClock.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from sentinelpi.detectors.active_hours_detector import ActiveHoursDetector
from sentinelpi.models import AlertCategory, Severity
from sentinelpi.utils import clock


def _at_hour(hour: int):
    return clock.FixedClock(datetime(2026, 6, 4, hour, 30, tzinfo=timezone.utc))


def _conn(src_ip="192.168.1.50"):
    from sentinelpi.capture.packet_capture import CapturedConnection
    return CapturedConnection(
        timestamp=clock.now(), src_ip=src_ip, src_port=40000,
        dst_ip="93.184.216.34", dst_port=443, protocol="tcp", flags="S",
    )


@pytest.fixture
def detector(config, db, baseline, device_tracker):
    config.monitoring.active_hours_min_known = 6
    # Pin the baseline out of the learning phase deterministically (the tests
    # jump the clock around, so a real-time start_time could read as learning).
    baseline._start_time = datetime(2020, 1, 1, tzinfo=timezone.utc)
    return ActiveHoursDetector(config=config, db=db, baseline=baseline, device_tracker=device_tracker)


def _seed_hours(db, ip, hours):
    for h in hours:
        db.record_host_hour(ip, h)


# ------------------------------------------------------------------- DB store
def test_record_host_hour_newness(db):
    assert db.record_host_hour("192.168.1.50", 9) is True
    assert db.record_host_hour("192.168.1.50", 9) is False
    assert db.record_host_hour("192.168.1.50", 10) is True
    assert db.get_host_hours("192.168.1.50") == {9, 10}


# -------------------------------------------------------------------- detector
def test_no_alert_until_profile_established(detector, db):
    # Fewer than min_known (6) hours known -> learning the profile, no alerts.
    _seed_hours(db, "192.168.1.50", [8, 9, 10])
    with clock.use_clock(_at_hour(3)):
        assert detector.process_event(_conn()) == []
    # The new hour was still recorded.
    assert 3 in db.get_host_hours("192.168.1.50")


def test_alerts_on_new_hour_once_established(detector, db):
    _seed_hours(db, "192.168.1.50", [8, 9, 10, 11, 12, 13])  # 6 known
    with clock.use_clock(_at_hour(3)):
        alerts = detector.process_event(_conn())
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.MEDIUM
    assert alerts[0].category == AlertCategory.CONNECTION_ANOMALY
    assert alerts[0].extra["hour"] == 3


def test_known_hour_no_alert(detector, db):
    _seed_hours(db, "192.168.1.50", [8, 9, 10, 11, 12, 3])  # 3 already known
    with clock.use_clock(_at_hour(3)):
        assert detector.process_event(_conn()) == []


def test_non_local_source_ignored(detector, db):
    _seed_hours(db, "8.8.8.8", [8, 9, 10, 11, 12, 13])
    with clock.use_clock(_at_hour(3)):
        assert detector.process_event(_conn(src_ip="8.8.8.8")) == []


def test_learning_phase_records_but_no_alert(config, db, device_tracker):
    from sentinelpi.baseline.engine import BaselineEngine
    config.monitoring.active_hours_min_known = 6
    config.monitoring.baseline_learning_hours = 24  # still learning
    learning_baseline = BaselineEngine(config, db)
    # Pin start just before the test hour so is_learning is deterministically True.
    learning_baseline._start_time = datetime(2026, 6, 4, 3, 0, tzinfo=timezone.utc)
    det = ActiveHoursDetector(config=config, db=db, baseline=learning_baseline,
                              device_tracker=device_tracker)
    _seed_hours(db, "192.168.1.50", [8, 9, 10, 11, 12, 13])
    with clock.use_clock(_at_hour(3)):
        assert det.process_event(_conn()) == []
    assert 3 in db.get_host_hours("192.168.1.50")


def test_persists_across_instances(config, db, baseline, device_tracker):
    config.monitoring.active_hours_min_known = 6
    baseline._start_time = datetime(2020, 1, 1, tzinfo=timezone.utc)
    _seed_hours(db, "192.168.1.50", [8, 9, 10, 11, 12, 13])
    det1 = ActiveHoursDetector(config=config, db=db, baseline=baseline, device_tracker=device_tracker)
    with clock.use_clock(_at_hour(3)):
        assert len(det1.process_event(_conn())) == 1
    # Fresh instance (restart) seeds hour 3 from the DB -> no repeat alert.
    det2 = ActiveHoursDetector(config=config, db=db, baseline=baseline, device_tracker=device_tracker)
    with clock.use_clock(_at_hour(3)):
        assert det2.process_event(_conn()) == []
