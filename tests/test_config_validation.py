from __future__ import annotations

import subprocess
import sys
import os

from sentinelpi.config.manager import Config, validate_config
from sentinelpi.config.preflight import run_preflight


def _issue_paths(config: Config) -> set[str]:
    return {issue.path for issue in validate_config(config)}


def test_validate_config_accepts_defaults():
    assert validate_config(Config()) == []


def test_validate_config_rejects_invalid_network_values():
    config = Config()
    config.network.subnets = ["not-a-cidr"]
    config.network.gateway_ip = "999.999.999.999"
    config.network.gateway_mac = "not-a-mac"

    paths = _issue_paths(config)

    assert "network.subnets[0]" in paths
    assert "network.gateway_ip" in paths
    assert "network.gateway_mac" in paths


def test_validate_config_rejects_invalid_ports_and_enums():
    config = Config()
    config.dashboard.port = "nope"
    config.monitoring.sensitivity_profile = "maximum"
    config.monitoring.self_monitoring_queue_warn_ratio = 1.5
    config.notifications.webhook_min_severity = "urgent"
    config.response.firewall_backend = "pf"

    paths = _issue_paths(config)

    assert "dashboard.port" in paths
    assert "monitoring.sensitivity_profile" in paths
    assert "monitoring.self_monitoring_queue_warn_ratio" in paths
    assert "notifications.webhook_min_severity" in paths
    assert "response.firewall_backend" in paths


def test_validate_config_rejects_invalid_siem_settings():
    config = Config()
    n = config.notifications
    n.siem_enabled = True
    n.siem_host = ""
    n.siem_format = "logstash"
    n.siem_transport = "carrier-pigeon"
    n.siem_facility = "local99"
    n.siem_port = 70000
    n.siem_min_severity = "urgent"

    paths = _issue_paths(config)

    assert "notifications.siem_host" in paths
    assert "notifications.siem_format" in paths
    assert "notifications.siem_transport" in paths
    assert "notifications.siem_facility" in paths
    assert "notifications.siem_port" in paths
    assert "notifications.siem_min_severity" in paths


def test_validate_config_accepts_valid_siem_settings():
    config = Config()
    n = config.notifications
    n.siem_enabled = True
    n.siem_format = "cef"
    n.siem_transport = "tcp"
    n.siem_facility = "local4"
    n.siem_host = "10.0.0.5"
    n.siem_port = 6514
    n.siem_min_severity = "medium"

    assert validate_config(config) == []


def test_validate_config_rejects_incomplete_sms_settings():
    config = Config()
    config.notifications.sms_enabled = True

    paths = _issue_paths(config)

    assert "notifications.sms_account_sid" in paths
    assert "notifications.sms_auth_token" in paths
    assert "notifications.sms_from" in paths
    assert "notifications.sms_to" in paths


def test_validate_config_accepts_sms_api_key_and_messaging_service():
    config = Config()
    n = config.notifications
    n.sms_enabled = True
    n.sms_account_sid = "AC123"
    n.sms_api_key_sid = "SK123"
    n.sms_api_key_secret = "secret"
    n.sms_messaging_service_sid = "MG123"
    n.sms_to = ["+15557654321"]

    paths = _issue_paths(config)

    assert "notifications.sms_account_sid" not in paths
    assert "notifications.sms_auth_token" not in paths
    assert "notifications.sms_from" not in paths
    assert "notifications.sms_to" not in paths


def test_check_config_exits_nonzero_for_invalid_yaml(tmp_path):
    config_path = tmp_path / "bad.yaml"
    config_path.write_text(
        "\n".join([
            "network:",
            "  subnets:",
            "    - not-a-cidr",
            "dashboard:",
            "  port: nope",
            "monitoring:",
            "  sensitivity_profile: bananas",
        ]),
        encoding="utf-8",
    )

    env = os.environ.copy()
    env["PYTHONPATH"] = "src"
    result = subprocess.run(
        [sys.executable, "-m", "sentinelpi.main", "--config", str(config_path), "--check-config"],
        capture_output=True,
        env=env,
        text=True,
        timeout=10,
    )

    assert result.returncode == 2
    assert "Configuration INVALID" in result.stdout
    assert "network.subnets[0]" in result.stdout
    assert "dashboard.port" in result.stdout
    assert "monitoring.sensitivity_profile" in result.stdout


def test_preflight_skips_when_outputs_are_disabled():
    results = run_preflight(Config())

    assert ("notifiers", "skip", "no network notifiers enabled") in [
        (r.name, r.status, r.detail) for r in results
    ]
    assert ("responders", "skip", "response.enabled is false") in [
        (r.name, r.status, r.detail) for r in results
    ]


def test_preflight_plans_enabled_responder_without_executing():
    config = Config()
    config.response.enabled = True
    config.response.firewall_block_enabled = True
    config.response.auto_block_categories = ["threat_intel"]

    results = run_preflight(config)

    firewall = next(r for r in results if r.name == "responder:firewall")
    assert firewall.status == "ok"
    assert "[dry-run] would: Block 203.0.113.10" in firewall.detail


def test_check_runs_preflight_and_returns_probe_failure(tmp_path):
    config_path = tmp_path / "sentinelpi.yaml"
    config_path.write_text(
        "\n".join([
            "notifications:",
            "  webhook_enabled: true",
            "  webhook_url: http://127.0.0.1:9/sentinelpi",
        ]),
        encoding="utf-8",
    )

    env = os.environ.copy()
    env["PYTHONPATH"] = "src"
    result = subprocess.run(
        [sys.executable, "-m", "sentinelpi.main", "--config", str(config_path), "--check"],
        capture_output=True,
        env=env,
        text=True,
        timeout=10,
    )

    assert result.returncode == 3
    assert "Configuration OK" in result.stdout
    assert "Preflight checks:" in result.stdout
    assert "[FAIL] notifier:webhook: POST http://127.0.0.1:9/sentinelpi" in result.stdout
