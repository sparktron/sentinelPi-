"""
tests/test_honeypot.py - Tests for the honeypot / canary ports (Phase 2).

Covers the alert built on a hit (unit) and an end-to-end real-socket bind +
connect on an ephemeral localhost port (integration).
"""

from __future__ import annotations

import socket
import time

import pytest

from sentinelpi.capture.honeypot import HoneypotService
from sentinelpi.models import AlertCategory, Severity


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ----------------------------------------------------------------------- unit
def test_handle_hit_builds_high_alert(config):
    captured = []
    hp = HoneypotService(config, on_alert=captured.append)
    hp._handle_hit("192.168.1.66", 23)

    assert len(captured) == 1
    alert = captured[0]
    assert alert.severity == Severity.HIGH
    assert alert.category == AlertCategory.HONEYPOT
    assert alert.affected_host == "192.168.1.66"
    assert alert.extra["canary_port"] == 23


def test_callback_errors_are_swallowed(config):
    def boom(_alert):
        raise RuntimeError("downstream broke")
    hp = HoneypotService(config, on_alert=boom)
    hp._handle_hit("10.0.0.5", 3389)  # must not raise


# ---------------------------------------------------------------- integration
def test_real_connection_triggers_alert(config):
    port = _free_port()
    config.monitoring.honeypot_bind_host = "127.0.0.1"
    config.monitoring.honeypot_ports = [port]

    captured = []
    hp = HoneypotService(config, on_alert=captured.append)
    assert hp.start() is True
    try:
        # Connect to the canary port like a scanner would.
        c = socket.create_connection(("127.0.0.1", port), timeout=2)
        c.close()

        # Give the accept loop a moment to handle it.
        deadline = time.time() + 3
        while not captured and time.time() < deadline:
            time.sleep(0.02)
    finally:
        hp.stop()

    assert len(captured) >= 1
    assert captured[0].category == AlertCategory.HONEYPOT
    assert captured[0].extra["canary_port"] == port


def test_unbindable_port_is_skipped_not_fatal(config):
    # Bind a port ourselves, then ask the honeypot for the same one.
    taken = socket.socket()
    taken.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    taken.bind(("127.0.0.1", 0))
    taken.listen(1)
    port = taken.getsockname()[1]

    good = _free_port()
    config.monitoring.honeypot_bind_host = "127.0.0.1"
    config.monitoring.honeypot_ports = [port, good]

    hp = HoneypotService(config, on_alert=lambda a: None)
    try:
        # The taken port fails to bind but the good one still comes up.
        assert hp.start() is True
    finally:
        hp.stop()
        taken.close()
