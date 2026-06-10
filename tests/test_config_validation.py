from __future__ import annotations

import subprocess
import sys
import os

from sentinelpi.config.manager import Config, validate_config


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
    config.notifications.webhook_min_severity = "urgent"
    config.response.firewall_backend = "pf"

    paths = _issue_paths(config)

    assert "dashboard.port" in paths
    assert "monitoring.sensitivity_profile" in paths
    assert "notifications.webhook_min_severity" in paths
    assert "response.firewall_backend" in paths


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
