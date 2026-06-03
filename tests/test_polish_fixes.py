"""
tests/test_polish_fixes.py - Regression tests for CODE_REVIEW M3, M6, L1, L2.

M3: build_detector_thread takes the alert manager explicitly (no dead
    detector.config no-op, no dynamically-attached _alert_manager attribute).
M6: PacketCapture validates configured interfaces at startup instead of
    IndexError-ing on an empty list.
L1/L2: dashboard /api/alerts validates int and enum query params, returning 400
    rather than 500 on bad input.
"""

from __future__ import annotations

import threading
from unittest.mock import MagicMock

import pytest


# --------------------------------------------------------------------------- M3
def test_build_detector_thread_uses_explicit_alert_manager():
    from sentinelpi.main import build_detector_thread

    sentinel_alerts = ["a1", "a2"]
    stop_event = threading.Event()

    detector = MagicMock()
    detector.name = "FakeDetector"
    # Return alerts once, then stop the loop so the thread exits promptly.
    def _poll():
        stop_event.set()
        return sentinel_alerts
    detector.poll.side_effect = _poll

    alert_manager = MagicMock()

    thread = build_detector_thread(detector, alert_manager, stop_event, poll_interval=0)
    thread.start()
    thread.join(timeout=5)

    assert not thread.is_alive()
    alert_manager.process.assert_called_once_with(sentinel_alerts)


# --------------------------------------------------------------------------- M6
def test_packet_capture_rejects_empty_interfaces(monkeypatch):
    import sentinelpi.capture.packet_capture as pc

    monkeypatch.setattr(pc, "SCAPY_AVAILABLE", True)
    cap = pc.PacketCapture(interfaces=[], event_queue=MagicMock())
    assert cap.start() is False
    assert cap._running is False


def test_packet_capture_rejects_all_unknown_interfaces(monkeypatch):
    import sentinelpi.capture.packet_capture as pc

    monkeypatch.setattr(pc, "SCAPY_AVAILABLE", True)
    import psutil
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: {"eth0": [], "lo": []})

    cap = pc.PacketCapture(interfaces=["does-not-exist0"], event_queue=MagicMock())
    assert cap.start() is False


def test_packet_capture_prunes_unknown_keeps_known(monkeypatch):
    import sentinelpi.capture.packet_capture as pc

    monkeypatch.setattr(pc, "SCAPY_AVAILABLE", True)
    import psutil
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: {"eth0": [], "lo": []})
    # Don't actually spawn the sniffer thread.
    monkeypatch.setattr(pc.threading, "Thread", MagicMock())

    cap = pc.PacketCapture(interfaces=["eth0", "ghost0"], event_queue=MagicMock())
    assert cap.start() is True
    assert cap.interfaces == ["eth0"]  # unknown pruned, known kept


# ----------------------------------------------------------------------- L1/L2
@pytest.fixture
def client(config, db, device_tracker, baseline, alert_manager):
    from sentinelpi.ui.dashboard import FLASK_AVAILABLE, create_app

    if not FLASK_AVAILABLE:
        pytest.skip("Flask not installed")
    config.dashboard.access_token = ""
    app = create_app(config, db, device_tracker, baseline, alert_manager)
    app.config.update(TESTING=True)
    token = config.dashboard.access_token
    return app.test_client(), {"Authorization": f"Bearer {token}"}


def test_alerts_valid_params_ok(client):
    c, headers = client
    assert c.get("/api/alerts?limit=10&hours=6", headers=headers).status_code == 200


def test_alerts_non_numeric_limit_is_400(client):
    c, headers = client
    resp = c.get("/api/alerts?limit=abc", headers=headers)
    assert resp.status_code == 400
    assert "Invalid query parameter" in resp.get_json()["error"]


def test_alerts_invalid_severity_is_400(client):
    c, headers = client
    resp = c.get("/api/alerts?severity=purple", headers=headers)
    assert resp.status_code == 400
    assert "valid_severity" in resp.get_json()


def test_alerts_limit_is_clamped(client):
    c, headers = client
    # Over-max limit must not error — it clamps and returns 200.
    assert c.get("/api/alerts?limit=99999", headers=headers).status_code == 200


# ----------------------------------------------------------------------- L4
def test_capabilities_banner_warns_when_degraded(monkeypatch, caplog):
    """_log_capabilities logs a degraded-mode warning when an optional dep is off."""
    import logging
    import sentinelpi.capture.packet_capture as pc
    from sentinelpi.main import SentinelPi

    monkeypatch.setattr(pc, "SCAPY_AVAILABLE", False)
    with caplog.at_level(logging.WARNING):
        # The method ignores self, so a bare object is a fine stand-in.
        SentinelPi._log_capabilities(object())

    assert any("degraded mode" in r.message.lower() for r in caplog.records)
