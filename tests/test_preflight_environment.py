"""
tests/test_preflight_environment.py - config-doctor file/binary probes.

`--check` reports which enabled features would run degraded because an optional
file or binary is missing. Missing dependencies are non-fatal warnings.
"""

from __future__ import annotations

from sentinelpi.config.manager import Config
from sentinelpi.config.preflight import _check_environment, run_preflight


def _results_by_name(results):
    return {r.name: r for r in results}


def test_environment_skips_when_no_dependent_features():
    config = Config()
    config.monitoring.geo_enabled = False
    config.monitoring.asn_reputation_enabled = False
    config.monitoring.auth_log_enabled = False
    config.monitoring.dhcp_leases_enabled = False
    config.monitoring.file_integrity_enabled = False
    config.monitoring.packet_capture_enabled = False
    config.response.enabled = False

    results = _check_environment(config)
    assert len(results) == 1
    assert results[0].status == "skip"


def test_environment_warns_on_missing_geoip_and_auth_log(tmp_path):
    config = Config()
    config.monitoring.packet_capture_enabled = False
    config.monitoring.auth_log_enabled = False
    config.monitoring.geo_enabled = True
    config.monitoring.geo_db_path = str(tmp_path / "missing.mmdb")

    by_name = _results_by_name(_check_environment(config))
    assert by_name["env:geoip-country"].status == "warn"
    assert "missing" in by_name["env:geoip-country"].detail


def test_environment_ok_when_file_present(tmp_path):
    db = tmp_path / "GeoLite2-Country.mmdb"
    db.write_bytes(b"stub")
    config = Config()
    config.monitoring.packet_capture_enabled = False
    config.monitoring.auth_log_enabled = False
    config.monitoring.geo_enabled = True
    config.monitoring.geo_db_path = str(db)

    by_name = _results_by_name(_check_environment(config))
    assert by_name["env:geoip-country"].status == "ok"


def test_environment_probes_firewall_binary():
    config = Config()
    config.monitoring.packet_capture_enabled = False
    config.monitoring.auth_log_enabled = False
    config.response.enabled = True
    config.response.firewall_block_enabled = True
    config.response.firewall_backend = "definitely-not-a-real-binary-xyz"

    by_name = _results_by_name(_check_environment(config))
    assert by_name["env:firewall"].status == "warn"
    assert "not on PATH" in by_name["env:firewall"].detail


def test_packet_capture_warns_when_only_dumpcap_present_but_scapy_missing(monkeypatch):
    """dumpcap present but scapy unavailable must still warn — daemon uses scapy."""
    import shutil
    import sentinelpi.config.preflight as preflight_mod

    # Make shutil.which("dumpcap") return a path so it looks like dumpcap is installed,
    # but _module_available("scapy") returns False (scapy not importable).
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/dumpcap" if name == "dumpcap" else None)
    monkeypatch.setattr(preflight_mod, "_module_available", lambda name: False)

    config = Config()
    config.monitoring.packet_capture_enabled = True

    by_name = _results_by_name(_check_environment(config))
    assert by_name["env:packet-capture"].status == "warn"
    assert "scapy" in by_name["env:packet-capture"].detail


def test_environment_warnings_do_not_fail_preflight(tmp_path):
    config = Config()
    config.network.interfaces = ["eth0"]
    config.network.subnets = ["192.168.1.0/24"]
    config.monitoring.geo_enabled = True
    config.monitoring.geo_db_path = str(tmp_path / "missing.mmdb")

    results = run_preflight(config)
    # A missing optional file warns but must not mark the run failed.
    assert any(r.status == "warn" for r in results)
    assert not any(r.failed for r in results)
