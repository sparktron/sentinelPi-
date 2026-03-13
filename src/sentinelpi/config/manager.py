"""
config/manager.py - Configuration loading, validation, and access.

Reads sentinelpi.yaml and exposes a typed Config object. Any missing
keys fall back to safe defaults so the tool runs out of the box.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any

import yaml

logger = logging.getLogger(__name__)

# Default configuration file locations searched in order
DEFAULT_CONFIG_PATHS = [
    Path("/etc/sentinelpi/sentinelpi.yaml"),
    Path.home() / ".config" / "sentinelpi" / "sentinelpi.yaml",
    Path("config/sentinelpi.yaml"),
    Path("sentinelpi.yaml"),
]


@dataclass
class NetworkConfig:
    interfaces: List[str] = field(default_factory=lambda: ["eth0"])
    subnets: List[str] = field(default_factory=lambda: ["192.168.1.0/24"])
    gateway_ip: str = ""
    gateway_mac: str = ""


@dataclass
class TrustedDevice:
    ip: str = ""
    mac: str = ""
    name: str = ""
    notes: str = ""


@dataclass
class AlertThresholds:
    # Port scan: how many distinct ports to a single host before flagging
    port_scan_ports_per_minute: int = 15
    # Connection spike: multiplier above hourly baseline
    connection_spike_factor: float = 3.0
    # Beacon detection: coefficient of variation threshold (lower = more regular)
    beacon_cv_threshold: float = 0.15
    # Minimum intervals to analyze for beacon detection
    beacon_min_intervals: int = 8
    # SSH brute force: failures within window
    ssh_failures_threshold: int = 10
    ssh_failures_window_seconds: int = 120
    # ARP: MAC changes for the same IP within this window = suspicious
    arp_mac_change_window_seconds: int = 300
    # Traffic spike: bytes per minute multiplier above baseline
    traffic_spike_factor: float = 5.0
    # DNS: entropy threshold for DGA detection
    dns_entropy_threshold: float = 3.8
    # Lateral movement: unique internal destinations from one host per minute
    lateral_movement_dest_threshold: int = 5


@dataclass
class NotificationConfig:
    email_enabled: bool = False
    email_smtp_host: str = "localhost"
    email_smtp_port: int = 25
    email_smtp_tls: bool = False
    email_username: str = ""
    email_password: str = ""
    email_from: str = "sentinelpi@localhost"
    email_to: List[str] = field(default_factory=list)
    email_min_severity: str = "high"

    webhook_enabled: bool = False
    webhook_url: str = ""
    webhook_min_severity: str = "medium"
    webhook_secret: str = ""


@dataclass
class DashboardConfig:
    enabled: bool = True
    host: str = "127.0.0.1"   # localhost-only by default for safety
    port: int = 8888
    debug: bool = False
    # Require a simple token for dashboard access (empty = no auth)
    access_token: str = ""


@dataclass
class StorageConfig:
    db_path: str = "/var/lib/sentinelpi/sentinelpi.db"
    retention_days: int = 30
    # How often (seconds) to rotate/vacuum the database
    vacuum_interval_seconds: int = 86400


@dataclass
class LoggingConfig:
    level: str = "INFO"
    log_dir: str = "/var/log/sentinelpi"
    max_bytes: int = 10_485_760   # 10 MB
    backup_count: int = 5
    json_alerts_file: str = "/var/log/sentinelpi/alerts.json"


@dataclass
class MonitoringConfig:
    # Active device discovery (low-rate ARP ping) — disabled by default
    active_discovery_enabled: bool = False
    active_discovery_interval_seconds: int = 300

    # DNS monitoring (requires packet capture or system resolver hook)
    dns_monitoring_enabled: bool = True

    # Auth log monitoring
    auth_log_enabled: bool = True
    auth_log_path: str = "/var/log/auth.log"

    # File integrity monitoring
    file_integrity_enabled: bool = False
    file_integrity_paths: List[str] = field(default_factory=lambda: [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/etc/hosts",
    ])

    # Geolocation lookups (offline GeoIP database)
    geo_enabled: bool = False
    geo_db_path: str = "/var/lib/sentinelpi/GeoLite2-Country.mmdb"

    # Packet capture (requires root/CAP_NET_RAW)
    packet_capture_enabled: bool = True

    # Sensitivity profile affects multiple thresholds
    # Options: conservative | balanced | aggressive
    sensitivity_profile: str = "balanced"

    # Quiet hours: suppress non-critical alerts during these hours (24h format)
    quiet_hours_enabled: bool = False
    quiet_hours_start: int = 23   # 11 PM
    quiet_hours_end: int = 7      # 7 AM

    # Baseline learning period before anomaly detection activates
    baseline_learning_hours: int = 24


@dataclass
class ReportingConfig:
    daily_report_enabled: bool = True
    daily_report_hour: int = 7    # 7 AM
    weekly_report_enabled: bool = True
    weekly_report_day: int = 1    # Monday


@dataclass
class Config:
    """Root configuration object. All subconfigs have safe defaults."""
    network: NetworkConfig = field(default_factory=NetworkConfig)
    trusted_devices: List[TrustedDevice] = field(default_factory=list)
    thresholds: AlertThresholds = field(default_factory=AlertThresholds)
    notifications: NotificationConfig = field(default_factory=NotificationConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)

    # Domains/IPs/ports to never alert on
    whitelist_domains: List[str] = field(default_factory=list)
    whitelist_ips: List[str] = field(default_factory=list)
    whitelist_ports: List[int] = field(default_factory=list)

    # Path this config was loaded from (for display purposes)
    _source_path: str = ""


def _merge_dataclass_from_dict(dc_instance: Any, data: Dict[str, Any]) -> None:
    """
    Recursively populate a dataclass instance from a dict.
    Unknown keys are ignored. Nested dataclasses are handled recursively.
    """
    import dataclasses
    if not dataclasses.is_dataclass(dc_instance):
        return
    for f in dataclasses.fields(dc_instance):
        if f.name.startswith("_"):
            continue
        if f.name not in data:
            continue
        val = data[f.name]
        current = getattr(dc_instance, f.name)
        if dataclasses.is_dataclass(current) and isinstance(val, dict):
            _merge_dataclass_from_dict(current, val)
        else:
            setattr(dc_instance, f.name, val)


def load_config(path: Optional[str] = None) -> Config:
    """
    Load configuration from a YAML file.

    Search order:
      1. Explicit path argument
      2. SENTINELPI_CONFIG environment variable
      3. DEFAULT_CONFIG_PATHS list

    Falls back to all-defaults Config if no file is found.
    """
    config = Config()

    # Determine file to load
    candidate: Optional[Path] = None
    if path:
        candidate = Path(path)
    elif "SENTINELPI_CONFIG" in os.environ:
        candidate = Path(os.environ["SENTINELPI_CONFIG"])
    else:
        for p in DEFAULT_CONFIG_PATHS:
            if p.exists():
                candidate = p
                break

    if candidate is None:
        logger.warning("No config file found; using built-in defaults.")
        return config

    if not candidate.exists():
        logger.warning("Config file %s not found; using defaults.", candidate)
        return config

    try:
        with open(candidate, "r") as fh:
            raw = yaml.safe_load(fh)
        if not isinstance(raw, dict):
            logger.warning("Config file %s is empty or invalid; using defaults.", candidate)
            return config

        # Populate trusted_devices list specially
        if "trusted_devices" in raw:
            config.trusted_devices = [
                TrustedDevice(**d) for d in raw.pop("trusted_devices", [])
            ]

        _merge_dataclass_from_dict(config, raw)
        config._source_path = str(candidate)
        logger.info("Loaded config from %s", candidate)

    except yaml.YAMLError as exc:
        logger.error("Failed to parse config file %s: %s", candidate, exc)
    except Exception as exc:
        logger.error("Unexpected error loading config %s: %s", candidate, exc)

    # Apply sensitivity profile multipliers
    _apply_sensitivity_profile(config)

    return config


def _apply_sensitivity_profile(config: Config) -> None:
    """
    Adjust thresholds based on the chosen sensitivity profile.

    conservative: fewer alerts, higher bar — reduces false positives on busy nets
    balanced: defaults as written in AlertThresholds
    aggressive: lower bar — catches more but may produce more noise
    """
    profile = config.monitoring.sensitivity_profile
    t = config.thresholds

    if profile == "conservative":
        t.port_scan_ports_per_minute = 30
        t.connection_spike_factor = 5.0
        t.beacon_cv_threshold = 0.10
        t.ssh_failures_threshold = 20
        t.traffic_spike_factor = 8.0
        t.lateral_movement_dest_threshold = 10
    elif profile == "aggressive":
        t.port_scan_ports_per_minute = 8
        t.connection_spike_factor = 2.0
        t.beacon_cv_threshold = 0.20
        t.ssh_failures_threshold = 5
        t.traffic_spike_factor = 3.0
        t.lateral_movement_dest_threshold = 3
    # "balanced" uses the dataclass defaults


def get_trusted_ips(config: Config) -> set:
    """Return set of IP addresses explicitly trusted by the user."""
    return {d.ip for d in config.trusted_devices if d.ip}


def get_trusted_macs(config: Config) -> set:
    """Return set of MAC addresses explicitly trusted by the user."""
    return {d.mac.lower() for d in config.trusted_devices if d.mac}
