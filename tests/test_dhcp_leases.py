"""
tests/test_dhcp_leases.py - DHCP-lease device identity (Phase 3).

Covers the dnsmasq + ISC parsers, the caching source, and DeviceTracker using a
lease hostname as authoritative (over reverse DNS).
"""

from __future__ import annotations

import pytest

from sentinelpi.inventory.dhcp_leases import (
    parse_dnsmasq, parse_isc, DHCPLeaseSource,
)


DNSMASQ = """\
1718000000 de:ad:be:ef:00:11 192.168.1.50 johns-laptop 01:de:ad:be:ef:00:11
1718000100 AA:BB:CC:00:00:22 192.168.1.51 * *
1718000200 aa:bb:cc:00:00:33 192.168.1.52 nas-box *
"""

ISC = """\
lease 192.168.1.50 {
  starts 4 2026/06/01 10:00:00;
  hardware ethernet de:ad:be:ef:00:11;
  client-hostname "johns-laptop";
}
lease 192.168.1.52 {
  hardware ethernet aa:bb:cc:00:00:33;
  client-hostname "nas-box";
}
"""


# ------------------------------------------------------------------- parsers
def test_parse_dnsmasq():
    leases = parse_dnsmasq(DNSMASQ)
    assert leases["de:ad:be:ef:00:11"].hostname == "johns-laptop"
    assert leases["de:ad:be:ef:00:11"].ip == "192.168.1.50"
    # '*' hostname becomes empty
    assert leases["aa:bb:cc:00:00:22"].hostname == ""
    # MAC normalization (uppercase input keyed lowercase)
    assert "aa:bb:cc:00:00:22" in leases


def test_parse_isc():
    leases = parse_isc(ISC)
    assert leases["de:ad:be:ef:00:11"].hostname == "johns-laptop"
    assert leases["aa:bb:cc:00:00:33"].ip == "192.168.1.52"


def test_parse_dnsmasq_ignores_short_lines():
    assert parse_dnsmasq("garbage\n\n123 only-two\n") == {}


# -------------------------------------------------------------------- source
def test_source_reads_and_looks_up(tmp_path):
    f = tmp_path / "dnsmasq.leases"
    f.write_text(DNSMASQ)
    src = DHCPLeaseSource(str(f), "dnsmasq")
    assert src.refresh() == 3
    assert src.hostname_for("de:ad:be:ef:00:11") == "johns-laptop"
    assert src.hostname_for("00:00:00:00:00:00") == ""


def test_source_missing_file_is_empty(tmp_path):
    src = DHCPLeaseSource(str(tmp_path / "nope.leases"), "dnsmasq")
    assert src.refresh() == 0
    assert src.hostname_for("de:ad:be:ef:00:11") == ""


# ----------------------------------------------------------------- integration
def test_device_tracker_prefers_dhcp_hostname(config, db, tmp_path, monkeypatch):
    from sentinelpi.inventory.device_tracker import DeviceTracker
    import sentinelpi.inventory.device_tracker as dt
    from sentinelpi.capture.proc_reader import ARPEntry
    from sentinelpi.utils import clock

    f = tmp_path / "dnsmasq.leases"
    f.write_text(DNSMASQ)
    config.monitoring.dhcp_leases_enabled = True
    config.monitoring.dhcp_leases_path = str(f)
    config.monitoring.dhcp_leases_format = "dnsmasq"

    # reverse DNS would say something else; DHCP must win.
    monkeypatch.setattr(dt, "reverse_dns", lambda ip, timeout=0.5: "ptr-name")

    tracker = DeviceTracker(config, db)
    entry = ARPEntry(ip="192.168.1.50", mac="de:ad:be:ef:00:11", interface="eth0", flags="0x2")
    device = tracker._create_device(entry, clock.now())

    assert device.hostname == "johns-laptop"
    assert device.extra["identity_source"] == "dhcp"


def test_device_tracker_falls_back_to_reverse_dns(config, db, tmp_path, monkeypatch):
    from sentinelpi.inventory.device_tracker import DeviceTracker
    import sentinelpi.inventory.device_tracker as dt
    from sentinelpi.capture.proc_reader import ARPEntry
    from sentinelpi.utils import clock

    f = tmp_path / "dnsmasq.leases"
    f.write_text(DNSMASQ)
    config.monitoring.dhcp_leases_enabled = True
    config.monitoring.dhcp_leases_path = str(f)

    monkeypatch.setattr(dt, "reverse_dns", lambda ip, timeout=0.5: "ptr-name")

    tracker = DeviceTracker(config, db)
    # MAC not in the lease file -> reverse DNS fallback.
    entry = ARPEntry(ip="192.168.1.99", mac="ff:ff:ee:ee:dd:dd", interface="eth0", flags="0x2")
    device = tracker._create_device(entry, clock.now())

    assert device.hostname == "ptr-name"
    assert device.extra["identity_source"] == "reverse_dns"
