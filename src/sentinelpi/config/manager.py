"""
config/manager.py - Configuration loading, validation, and access.

Reads sentinelpi.yaml and exposes a typed Config object. Any missing
keys fall back to safe defaults so the tool runs out of the box.
"""

from __future__ import annotations

import logging
import os
import ipaddress
import re
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
    # Switch SPAN/mirror-port mode: the capture interface is fed a copy of all
    # subnet traffic, not just this host's. Forces promiscuous capture so other
    # hosts' unicast is seen. (Capture is promiscuous by default; this makes the
    # intent explicit and surfaces it in the startup log.)
    mirror_mode: bool = False


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

    # Encrypted-DNS (DoH/DoT) bypass detection — flag local clients talking
    # DoH/DoT to public resolvers instead of your configured DNS.
    doh_detection_enabled: bool = True
    # Destination IPs allowed to serve encrypted DNS (e.g. your own DoH server).
    doh_sanctioned_resolvers: List[str] = field(default_factory=list)

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

    # IP→ASN reputation (offline GeoLite2-ASN database). Flags connections to
    # hosting/anonymization providers commonly abused for malware/C2.
    asn_reputation_enabled: bool = False
    asn_db_path: str = "/var/lib/sentinelpi/GeoLite2-ASN.mmdb"
    # Specific ASNs to always flag, and org-name substrings (case-insensitive).
    suspicious_asns: List[int] = field(default_factory=list)
    suspicious_asn_keywords: List[str] = field(default_factory=list)

    # Packet capture (requires root/CAP_NET_RAW)
    packet_capture_enabled: bool = True

    # Honeypot / canary ports: open fake services; any connection is high-fidelity
    # evidence of internal scanning. Ports < 1024 need root to bind.
    honeypot_enabled: bool = False
    honeypot_bind_host: str = "0.0.0.0"
    honeypot_ports: List[int] = field(default_factory=lambda: [23, 2323, 3389, 8081, 5555])

    # Per-host active-hours profiling: flag a host active at an hour it has never
    # been active before (e.g. a daytime laptop beaconing at 3am).
    active_hours_detection_enabled: bool = True
    # Only flag once a host has an established profile (this many distinct hours).
    active_hours_min_known: int = 6

    # DHCP lease ingestion for authoritative device identity (names from the
    # router/DHCP server beat ARP-inferred / reverse-DNS guesses).
    dhcp_leases_enabled: bool = False
    dhcp_leases_path: str = "/var/lib/misc/dnsmasq.leases"
    dhcp_leases_format: str = "dnsmasq"         # "dnsmasq" | "isc"

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
class ThreatIntelConfig:
    # Opt-in: enabling adds a periodic network fetch of public blocklists and
    # matches every external destination IP/domain against them.
    enabled: bool = False
    cache_dir: str = "/var/lib/sentinelpi/threatintel"
    refresh_interval_hours: int = 24
    fetch_timeout_seconds: int = 30
    # Which feeds to load (see intel/threat_feeds.py FEEDS for the catalog).
    feeds: List[str] = field(default_factory=lambda: ["feodo", "urlhaus", "spamhaus_drop"])


@dataclass
class ResponseConfig:
    """
    Active-response settings. Safe by construction: nothing executes unless
    BOTH `enabled` is true AND `dry_run` is false, and then only for the
    explicitly opted-in responders/categories.
    """
    enabled: bool = False        # master switch — no responder runs unless true
    dry_run: bool = True         # even when enabled, only log intended actions

    # Human-in-the-loop: when armed (enabled & not dry_run), actions are held as
    # PENDING for one-click approval, EXCEPT for categories the user explicitly
    # trusts to auto-execute. Default: approve everything by hand.
    require_approval: bool = True
    auto_execute_categories: List[str] = field(default_factory=list)

    # Firewall-block responder (per-action opt-in).
    firewall_block_enabled: bool = False
    firewall_backend: str = "iptables"          # "iptables" | "nftables"
    # Only auto-block on these alert categories / at/above this severity.
    auto_block_categories: List[str] = field(default_factory=lambda: ["threat_intel"])
    auto_block_min_severity: str = "high"
    block_duration_seconds: int = 3600          # 0 = permanent (until restart/manual)

    # DNS sinkhole responder (domain-level block; per-action opt-in).
    dns_sinkhole_enabled: bool = False
    dns_sinkhole_backend: str = "hosts"         # "hosts" | "pihole" | "unbound"
    dns_sinkhole_hosts_file: str = "/etc/sentinelpi/sinkhole.hosts"
    sinkhole_categories: List[str] = field(default_factory=lambda: ["threat_intel", "dns_anomaly"])
    sinkhole_min_severity: str = "high"

    # ARP-spoof auto-restore responder (pins the trusted gateway MAC on poisoning).
    arp_restore_enabled: bool = False
    arp_restore_backend: str = "arp"            # "arp" | "ip"
    arp_restore_min_severity: str = "high"

    # Kill switch: run an operator-supplied command on confirmed compromise
    # (e.g. hostapd de-auth, router API, switch-port ACL). Placeholders in the
    # command are substituted: {ip} {mac} {related} {category} {severity}.
    # Empty command or categories => never fires. Default gate is CRITICAL only.
    killswitch_enabled: bool = False
    killswitch_command: List[str] = field(default_factory=list)
    killswitch_categories: List[str] = field(default_factory=list)
    killswitch_min_severity: str = "critical"


@dataclass
class ClusterConfig:
    """
    Multi-host sensor/collector settings (Phase 3).

    - standalone (default): no forwarding, no ingest — single host.
    - sensor:   forwards its alerts to a central collector.
    - collector: exposes an ingest endpoint that accepts sensors' alerts.

    The ingest endpoint is active whenever ``collector_key`` is set, regardless
    of role, so a collector is simply a host with a key (and usually the dash).
    """
    role: str = "standalone"          # standalone | sensor | collector
    sensor_id: str = ""               # id this sensor stamps on forwarded alerts
    collector_url: str = ""           # sensor: e.g. https://collector:8888/api/ingest
    collector_key: str = ""           # shared secret (sensor sends; collector requires)
    forward_min_severity: str = "low"

    # --- mTLS (optional, layered on top of the shared key) ---
    # Sensor side: present a client certificate and verify the collector's cert.
    # Terminate mTLS at a reverse proxy in front of the collector (waitress
    # doesn't do client-cert auth itself); see docs/systemd_setup.md.
    tls_client_cert: str = ""         # path to client cert (PEM); may include the key
    tls_client_key: str = ""          # path to client key (PEM); omit if in the cert
    tls_ca_cert: str = ""             # CA bundle used to verify the collector's cert
    tls_verify: bool = True           # set False only for throwaway/self-signed testing
    # Collector side: require the fronting proxy to have verified the client cert
    # (proxy sets X-SentinelPi-Client-Verified: SUCCESS from $ssl_client_verify).
    ingest_require_verified_header: bool = False


@dataclass
class CorrelationConfig:
    """
    Incident correlation: group an actor's alerts seen across multiple sensors
    or against many targets within a window into one escalated INCIDENT alert.
    Runs on whichever node sees the alerts — most useful on a collector.
    """
    enabled: bool = False
    window_seconds: int = 300
    min_sensors: int = 2        # actor seen by >= this many sensors -> incident
    min_targets: int = 5        # OR actor hit >= this many distinct targets -> incident
    cooldown_seconds: int = 600


@dataclass
class FlowIngestConfig:
    """
    Router/firewall flow ingestion (Phase 3). Lets SentinelPi see connections
    that never cross the Pi's own segment by ingesting flow data from the
    gateway instead of (or alongside) passive packet capture. All sources are
    off by default; each emits the same CapturedConnection events the
    packet-capture pipeline produces, so every connection detector works on
    them unchanged.
    """
    # Linux conntrack table polling (Pi-as-gateway, or any host worth tracking).
    conntrack_enabled: bool = False
    conntrack_interval_seconds: int = 10
    conntrack_command: str = "conntrack"   # falls back to /proc/net/nf_conntrack
    # NetFlow / IPFIX UDP collector for router/managed-switch flow exports.
    netflow_enabled: bool = False
    netflow_bind_host: str = "0.0.0.0"
    netflow_port: int = 2055
    # pfSense/OPNsense filterlog tailing (point at a file the Pi can read —
    # usually the firewall's syslog forwarded to and written by the Pi's rsyslog).
    filterlog_enabled: bool = False
    filterlog_path: str = "/var/log/filter.log"
    filterlog_interval_seconds: int = 5


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
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)
    response: ResponseConfig = field(default_factory=ResponseConfig)
    cluster: ClusterConfig = field(default_factory=ClusterConfig)
    correlation: CorrelationConfig = field(default_factory=CorrelationConfig)
    flow: FlowIngestConfig = field(default_factory=FlowIngestConfig)

    # Domains/IPs/ports to never alert on
    whitelist_domains: List[str] = field(default_factory=list)
    whitelist_ips: List[str] = field(default_factory=list)
    whitelist_ports: List[int] = field(default_factory=list)

    # Path this config was loaded from (for display purposes)
    _source_path: str = ""


@dataclass(frozen=True)
class ConfigIssue:
    """A single operator-facing configuration validation problem."""

    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


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


def validate_config(config: Config) -> List[ConfigIssue]:
    """Return all validation issues that should block daemon startup."""
    issues: List[ConfigIssue] = []

    def add(path: str, message: str) -> None:
        issues.append(ConfigIssue(path, message))

    def is_int(value: Any) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    def check_port(path: str, value: Any, *, allow_zero: bool = False) -> None:
        if not is_int(value):
            add(path, "must be an integer")
            return
        lo = 0 if allow_zero else 1
        if value < lo or value > 65535:
            add(path, f"must be between {lo} and 65535")

    def check_non_negative_int(path: str, value: Any) -> None:
        if not is_int(value) or value < 0:
            add(path, "must be a non-negative integer")

    def check_positive_number(path: str, value: Any) -> None:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            add(path, "must be a positive number")

    def check_severity(path: str, value: Any) -> None:
        valid = {"info", "low", "medium", "high", "critical"}
        if value not in valid:
            add(path, f"must be one of: {', '.join(sorted(valid))}")

    def check_category_list(path: str, values: Any) -> None:
        valid = {
            "arp_anomaly", "new_device", "port_scan", "beacon", "connection_anomaly",
            "dns_anomaly", "lateral_movement", "auth_anomaly", "traffic_spike",
            "process_anomaly", "threat_intel", "honeypot", "incident", "system",
        }
        if not isinstance(values, list):
            add(path, "must be a list")
            return
        for idx, value in enumerate(values):
            if value not in valid:
                add(f"{path}[{idx}]", f"must be one of: {', '.join(sorted(valid))}")

    mac_re = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")

    if not isinstance(config.network.interfaces, list) or not config.network.interfaces:
        add("network.interfaces", "must be a non-empty list")
    else:
        for idx, iface in enumerate(config.network.interfaces):
            if not isinstance(iface, str) or not iface.strip():
                add(f"network.interfaces[{idx}]", "must be a non-empty string")

    if not isinstance(config.network.subnets, list) or not config.network.subnets:
        add("network.subnets", "must be a non-empty list of CIDR networks")
    else:
        for idx, subnet in enumerate(config.network.subnets):
            try:
                ipaddress.ip_network(subnet, strict=False)
            except (TypeError, ValueError):
                add(f"network.subnets[{idx}]", "must be a valid CIDR network")

    for path, ip in (
        ("network.gateway_ip", config.network.gateway_ip),
    ):
        if ip:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                add(path, "must be a valid IP address")

    if config.network.gateway_mac and not mac_re.match(config.network.gateway_mac):
        add("network.gateway_mac", "must be a MAC address like aa:bb:cc:dd:ee:ff")

    for idx, device in enumerate(config.trusted_devices):
        if device.ip:
            try:
                ipaddress.ip_address(device.ip)
            except ValueError:
                add(f"trusted_devices[{idx}].ip", "must be a valid IP address")
        if device.mac and not mac_re.match(device.mac):
            add(f"trusted_devices[{idx}].mac", "must be a MAC address like aa:bb:cc:dd:ee:ff")

    if not isinstance(config.dashboard.host, str) or not config.dashboard.host:
        add("dashboard.host", "must be a non-empty string")
    check_port("dashboard.port", config.dashboard.port)

    if config.monitoring.sensitivity_profile not in {"conservative", "balanced", "aggressive"}:
        add("monitoring.sensitivity_profile", "must be one of: conservative, balanced, aggressive")
    check_non_negative_int("monitoring.active_discovery_interval_seconds",
                           config.monitoring.active_discovery_interval_seconds)
    check_non_negative_int("monitoring.baseline_learning_hours", config.monitoring.baseline_learning_hours)
    check_non_negative_int("monitoring.active_hours_min_known", config.monitoring.active_hours_min_known)
    for path, hour in (
        ("monitoring.quiet_hours_start", config.monitoring.quiet_hours_start),
        ("monitoring.quiet_hours_end", config.monitoring.quiet_hours_end),
    ):
        if not is_int(hour) or hour < 0 or hour > 23:
            add(path, "must be an hour from 0 to 23")
    if config.monitoring.dhcp_leases_format not in {"dnsmasq", "isc"}:
        add("monitoring.dhcp_leases_format", "must be one of: dnsmasq, isc")
    if not isinstance(config.monitoring.honeypot_ports, list):
        add("monitoring.honeypot_ports", "must be a list")
    else:
        for idx, port in enumerate(config.monitoring.honeypot_ports):
            check_port(f"monitoring.honeypot_ports[{idx}]", port)

    t = config.thresholds
    check_positive_number("thresholds.port_scan_ports_per_minute", t.port_scan_ports_per_minute)
    check_positive_number("thresholds.connection_spike_factor", t.connection_spike_factor)
    check_positive_number("thresholds.beacon_cv_threshold", t.beacon_cv_threshold)
    check_positive_number("thresholds.beacon_min_intervals", t.beacon_min_intervals)
    check_positive_number("thresholds.ssh_failures_threshold", t.ssh_failures_threshold)
    check_positive_number("thresholds.ssh_failures_window_seconds", t.ssh_failures_window_seconds)
    check_positive_number("thresholds.arp_mac_change_window_seconds", t.arp_mac_change_window_seconds)
    check_positive_number("thresholds.traffic_spike_factor", t.traffic_spike_factor)
    check_positive_number("thresholds.dns_entropy_threshold", t.dns_entropy_threshold)
    check_positive_number("thresholds.lateral_movement_dest_threshold", t.lateral_movement_dest_threshold)

    check_severity("notifications.email_min_severity", config.notifications.email_min_severity)
    check_severity("notifications.webhook_min_severity", config.notifications.webhook_min_severity)
    check_port("notifications.email_smtp_port", config.notifications.email_smtp_port)

    check_non_negative_int("storage.retention_days", config.storage.retention_days)
    check_non_negative_int("storage.vacuum_interval_seconds", config.storage.vacuum_interval_seconds)

    check_non_negative_int("threat_intel.refresh_interval_hours", config.threat_intel.refresh_interval_hours)
    check_non_negative_int("threat_intel.fetch_timeout_seconds", config.threat_intel.fetch_timeout_seconds)

    if config.response.firewall_backend not in {"iptables", "nftables"}:
        add("response.firewall_backend", "must be one of: iptables, nftables")
    if config.response.dns_sinkhole_backend not in {"hosts", "pihole", "unbound"}:
        add("response.dns_sinkhole_backend", "must be one of: hosts, pihole, unbound")
    if config.response.arp_restore_backend not in {"arp", "ip"}:
        add("response.arp_restore_backend", "must be one of: arp, ip")
    check_severity("response.auto_block_min_severity", config.response.auto_block_min_severity)
    check_severity("response.sinkhole_min_severity", config.response.sinkhole_min_severity)
    check_severity("response.arp_restore_min_severity", config.response.arp_restore_min_severity)
    check_severity("response.killswitch_min_severity", config.response.killswitch_min_severity)
    check_non_negative_int("response.block_duration_seconds", config.response.block_duration_seconds)
    check_category_list("response.auto_execute_categories", config.response.auto_execute_categories)
    check_category_list("response.auto_block_categories", config.response.auto_block_categories)
    check_category_list("response.sinkhole_categories", config.response.sinkhole_categories)
    check_category_list("response.killswitch_categories", config.response.killswitch_categories)

    if config.cluster.role not in {"standalone", "sensor", "collector"}:
        add("cluster.role", "must be one of: standalone, sensor, collector")
    check_severity("cluster.forward_min_severity", config.cluster.forward_min_severity)

    check_non_negative_int("correlation.window_seconds", config.correlation.window_seconds)
    check_non_negative_int("correlation.min_sensors", config.correlation.min_sensors)
    check_non_negative_int("correlation.min_targets", config.correlation.min_targets)
    check_non_negative_int("correlation.cooldown_seconds", config.correlation.cooldown_seconds)

    check_non_negative_int("flow.conntrack_interval_seconds", config.flow.conntrack_interval_seconds)
    check_port("flow.netflow_port", config.flow.netflow_port)
    check_non_negative_int("flow.filterlog_interval_seconds", config.flow.filterlog_interval_seconds)

    for idx, ip in enumerate(config.whitelist_ips):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            add(f"whitelist_ips[{idx}]", "must be a valid IP address")
    if not isinstance(config.whitelist_ports, list):
        add("whitelist_ports", "must be a list")
    else:
        for idx, port in enumerate(config.whitelist_ports):
            check_port(f"whitelist_ports[{idx}]", port)

    return issues


def get_trusted_ips(config: Config) -> set:
    """Return set of IP addresses explicitly trusted by the user."""
    return {d.ip for d in config.trusted_devices if d.ip}


def get_trusted_macs(config: Config) -> set:
    """Return set of MAC addresses explicitly trusted by the user."""
    return {d.mac.lower() for d in config.trusted_devices if d.mac}
