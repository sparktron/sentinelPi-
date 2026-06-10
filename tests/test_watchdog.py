from __future__ import annotations

import queue
import threading
from datetime import datetime, timedelta, timezone

from sentinelpi.models import AlertCategory, Severity
from sentinelpi.ui.dashboard import create_app
from sentinelpi.utils import clock
from sentinelpi.utils.watchdog import OperationalWatchdog


def _watchdog(config, capture_queue=None, threads=None):
    return OperationalWatchdog(config, capture_queue or queue.Queue(maxsize=10), threads or [])


def test_watchdog_alerts_on_dead_managed_thread(config):
    thread = threading.Thread(target=lambda: None, name="DeadWorker")
    watchdog = _watchdog(config, threads=[thread])

    alerts = watchdog.check()

    assert len(alerts) == 1
    assert alerts[0].category == AlertCategory.SYSTEM
    assert alerts[0].severity == Severity.HIGH
    assert alerts[0].dedup_key == "watchdog:thread:DeadWorker"


def test_watchdog_alerts_on_high_capture_queue(config):
    q = queue.Queue(maxsize=10)
    for item in range(8):
        q.put_nowait(item)
    config.monitoring.self_monitoring_queue_warn_ratio = 0.75
    watchdog = _watchdog(config, capture_queue=q)

    alerts = watchdog.check()

    assert [a.dedup_key for a in alerts] == ["watchdog:capture_queue_high"]
    assert alerts[0].extra["watchdog"]["usage_ratio"] == 0.8


def test_watchdog_alerts_on_low_disk_threshold(config, tmp_path):
    config.storage.db_path = str(tmp_path / "sentinelpi.db")
    config.monitoring.self_monitoring_disk_free_min_mb = 10**12
    watchdog = _watchdog(config)

    alerts = watchdog.check()

    assert [a.dedup_key for a in alerts] == ["watchdog:disk_low"]
    assert alerts[0].severity == Severity.HIGH


def test_watchdog_status_reports_healthy_snapshot(config, tmp_path):
    config.storage.db_path = str(tmp_path / "sentinelpi.db")
    watchdog = _watchdog(config)

    status = watchdog.get_status()

    assert status["enabled"] is True
    assert status["healthy"] is True
    assert status["capture_queue"]["size"] == 0
    assert status["dead_threads"] == []
    assert status["disk"]["path"] == str(tmp_path)
    assert status["capture"]["stale"] is False
    assert status["threat_intel"]["enabled"] is False


def test_watchdog_alerts_on_stale_capture_stream(config):
    start = datetime(2026, 6, 10, 12, 0, tzinfo=timezone.utc)
    config.monitoring.self_monitoring_capture_stale_seconds = 60
    with clock.use_clock(clock.FixedClock(start)):
        watchdog = _watchdog(config)
        watchdog.set_event_sources_active(True)

    with clock.use_clock(clock.FixedClock(start + timedelta(seconds=61))):
        alerts = watchdog.check()

    assert [a.dedup_key for a in alerts] == ["watchdog:capture_stale"]
    assert alerts[0].extra["watchdog"]["seconds_since_last_event"] == 61.0


def test_watchdog_event_resets_capture_staleness(config):
    start = datetime(2026, 6, 10, 12, 0, tzinfo=timezone.utc)
    config.monitoring.self_monitoring_capture_stale_seconds = 60
    with clock.use_clock(clock.FixedClock(start)):
        watchdog = _watchdog(config)
        watchdog.set_event_sources_active(True)

    with clock.use_clock(clock.FixedClock(start + timedelta(seconds=50))):
        watchdog.record_event()

    with clock.use_clock(clock.FixedClock(start + timedelta(seconds=90))):
        alerts = watchdog.check()

    assert "watchdog:capture_stale" not in {a.dedup_key for a in alerts}


def test_watchdog_alerts_on_threat_intel_refresh_error(config):
    config.threat_intel.enabled = True
    watchdog = _watchdog(config)
    watchdog.record_threat_intel_refresh(success=False, error="timeout")

    alerts = watchdog.check()

    assert [a.dedup_key for a in alerts] == ["watchdog:threat_intel_refresh_failed"]
    assert alerts[0].extra["watchdog"]["last_error"] == "timeout"


def test_watchdog_alerts_on_stale_threat_intel(config):
    start = datetime(2026, 6, 10, 12, 0, tzinfo=timezone.utc)
    config.threat_intel.enabled = True
    config.threat_intel.refresh_interval_hours = 1
    config.monitoring.self_monitoring_threat_intel_stale_multiplier = 2.0
    with clock.use_clock(clock.FixedClock(start)):
        watchdog = _watchdog(config)
        watchdog.record_threat_intel_refresh(success=True)

    with clock.use_clock(clock.FixedClock(start + timedelta(hours=3))):
        alerts = watchdog.check()

    assert [a.dedup_key for a in alerts] == ["watchdog:threat_intel_stale"]
    assert alerts[0].extra["watchdog"]["seconds_since_success"] == 10800.0


def test_dashboard_status_includes_watchdog(
    config, db, device_tracker, baseline, alert_manager, tmp_path
):
    config.dashboard.access_token = "tok"
    config.storage.db_path = str(tmp_path / "sentinelpi.db")
    watchdog = _watchdog(config)
    app = create_app(config, db, device_tracker, baseline, alert_manager, watchdog=watchdog)

    resp = app.test_client().get("/api/status", headers={"Authorization": "Bearer tok"})

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["watchdog"]["enabled"] is True
    assert "capture_queue" in data["watchdog"]
