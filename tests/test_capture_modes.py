"""
tests/test_capture_modes.py - Span/mirror-port capture mode (Phase 3).

Mirror mode is a config flag plus explicit promiscuous capture (required to see
other hosts' unicast on a switch SPAN port). These pin the config default and
that PacketCapture carries the promisc setting through to the sniffer.
"""

from __future__ import annotations

import queue

from sentinelpi.config.manager import NetworkConfig
from sentinelpi.capture.packet_capture import PacketCapture


def test_mirror_mode_defaults_off():
    assert NetworkConfig().mirror_mode is False


def test_packet_capture_promisc_default_on():
    cap = PacketCapture(interfaces=["eth0"], event_queue=queue.Queue())
    assert cap.promisc is True


def test_packet_capture_promisc_configurable():
    cap = PacketCapture(interfaces=["eth0"], event_queue=queue.Queue(), promisc=False)
    assert cap.promisc is False
