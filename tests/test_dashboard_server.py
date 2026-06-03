"""
tests/test_dashboard_server.py - Regression tests for CODE_REVIEW H3.

H3: the dashboard ran on the Flask/Werkzeug dev server with a no-op stop().
    It now prefers waitress (with a real graceful shutdown) and falls back to
    the dev server only when waitress is unavailable. stop() must actually shut
    the waitress server down and join its thread.

waitress may not be installed in CI, so the waitress path is exercised with an
injected fake server rather than a real socket bind.
"""

from __future__ import annotations

import threading

import pytest

from sentinelpi.ui import dashboard as dash

pytestmark = pytest.mark.skipif(not dash.FLASK_AVAILABLE, reason="Flask not installed")


class _FakeWaitressServer:
    """Stands in for a waitress server: run() blocks until close() is called."""

    def __init__(self):
        self.run_called = threading.Event()
        self._stop = threading.Event()
        self.closed = False

    def run(self):
        self.run_called.set()
        # Block like a real serve loop until close() releases us.
        self._stop.wait(timeout=5)

    def close(self):
        self.closed = True
        self._stop.set()


def _make_server(config, db, device_tracker, baseline, alert_manager):
    config.dashboard.host = "127.0.0.1"
    config.dashboard.port = 0
    app = dash.create_app(config, db, device_tracker, baseline, alert_manager)
    return dash.DashboardServer(app, config)


def test_waitress_path_starts_and_stops_gracefully(
    monkeypatch, config, db, device_tracker, baseline, alert_manager
):
    fake = _FakeWaitressServer()
    monkeypatch.setattr(dash, "WAITRESS_AVAILABLE", True)
    # waitress may be absent in CI, so the name may not exist yet — raising=False.
    monkeypatch.setattr(
        dash, "_create_waitress_server", lambda app, host, port: fake, raising=False
    )

    server = _make_server(config, db, device_tracker, baseline, alert_manager)
    server.start()

    assert fake.run_called.wait(timeout=2), "waitress server.run() should be invoked"
    assert server._server is fake
    assert server._thread.is_alive()

    server.stop(timeout=2)

    assert fake.closed, "stop() must close the waitress server"
    assert not server._thread.is_alive(), "stop() must join the server thread"
    assert server._server is None


def test_falls_back_to_dev_server_without_waitress(
    monkeypatch, config, db, device_tracker, baseline, alert_manager
):
    monkeypatch.setattr(dash, "WAITRESS_AVAILABLE", False)
    started = {}

    def fake_dev_start(self, host, port):
        started["host"], started["port"] = host, port

    monkeypatch.setattr(dash.DashboardServer, "_start_dev_server", fake_dev_start)

    server = _make_server(config, db, device_tracker, baseline, alert_manager)
    server.start()

    assert started == {"host": "127.0.0.1", "port": 0}
    assert server._server is None  # no graceful-shutdown handle on the dev path
    # stop() on the dev path must not raise even with no server handle.
    server.stop()


def test_stop_is_safe_before_start(config, db, device_tracker, baseline, alert_manager):
    server = _make_server(config, db, device_tracker, baseline, alert_manager)
    server.stop()  # must not raise
