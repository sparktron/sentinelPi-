from __future__ import annotations

import queue
import threading

from sentinelpi.main import SentinelPi


class _Watchdog:
    def __init__(self):
        self.events = 0
        self.refreshes = []
        self.event_sources_active = False

    def set_event_sources_active(self, active):
        self.event_sources_active = active

    def record_event(self):
        self.events += 1

    def record_threat_intel_refresh(self, *, success, error=""):
        self.refreshes.append((success, error))


class _Detector:
    name = "Detector"

    def process_event(self, event):
        return []


def test_event_router_records_watchdog_activity():
    app = SentinelPi.__new__(SentinelPi)
    app._event_router_started = False
    app._stop_event = threading.Event()
    app._capture_queue = queue.Queue()
    app._threads = []
    app._watchdog = _Watchdog()
    app._alert_manager = type("AM", (), {"process": lambda self, alerts: None})()
    app._build_event_detectors = lambda: [_Detector()]

    app._ensure_event_router()
    assert app._watchdog.event_sources_active is True
    app._capture_queue.put_nowait(object())

    try:
        assert app._watchdog.events == 1 or _wait_for(lambda: app._watchdog.events == 1)
    finally:
        app._stop_event.set()
        for thread in app._threads:
            thread.join(timeout=2)


def test_threat_intel_refresh_records_success_and_failure():
    app = SentinelPi.__new__(SentinelPi)
    app.config = type("Cfg", (), {
        "threat_intel": type("TI", (), {"refresh_interval_hours": 1})()
    })()
    app._stop_event = threading.Event()
    app._threads = []
    app._watchdog = _Watchdog()

    class _Intel:
        indicator_count = 0

        def __init__(self):
            self.calls = 0

        def refresh(self):
            self.calls += 1
            app._stop_event.set()

    app._intel_service = _Intel()
    app._start_threat_intel()
    app._threads[0].join(timeout=2)

    assert app._watchdog.refreshes == [(True, "")]

    app._stop_event = threading.Event()
    app._threads = []

    class _FailingIntel:
        indicator_count = 0

        def refresh(self):
            app._stop_event.set()
            raise RuntimeError("feed down")

    app._intel_service = _FailingIntel()
    app._start_threat_intel()
    app._threads[0].join(timeout=2)

    assert app._watchdog.refreshes[-1] == (False, "feed down")


def _wait_for(predicate):
    import time

    deadline = time.time() + 2
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False
