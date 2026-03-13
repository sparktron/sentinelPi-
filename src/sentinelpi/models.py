"""
models.py - Core data models for SentinelPi.

All shared dataclasses and enums used across modules live here to avoid
circular imports and keep the type system centralized.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    """Alert severity levels, ordered from least to most severe."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other: "Severity") -> bool:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)


class AlertCategory(str, Enum):
    """Broad categories for classification and filtering."""
    ARP_ANOMALY = "arp_anomaly"
    NEW_DEVICE = "new_device"
    PORT_SCAN = "port_scan"
    BEACON = "beacon"
    CONNECTION_ANOMALY = "connection_anomaly"
    DNS_ANOMALY = "dns_anomaly"
    LATERAL_MOVEMENT = "lateral_movement"
    AUTH_ANOMALY = "auth_anomaly"
    TRAFFIC_SPIKE = "traffic_spike"
    PROCESS_ANOMALY = "process_anomaly"
    SYSTEM = "system"


class AlertStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    MUTED = "muted"
    RESOLVED = "resolved"


@dataclass
class Alert:
    """
    A single anomaly detection event.

    Every alert must carry enough context for a technical user to understand
    what happened without needing to dig into logs.
    """
    # Unique identifier for this alert (auto-generated)
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # When this was detected
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # Classification
    severity: Severity = Severity.INFO
    category: AlertCategory = AlertCategory.SYSTEM

    # What host/device is involved
    affected_host: str = ""           # IP or hostname
    affected_mac: str = ""            # MAC address if known
    related_host: str = ""            # Secondary host (e.g., scanner → target)

    # Human-readable explanation
    title: str = ""                   # Short one-line summary
    description: str = ""             # Detailed explanation of why it was flagged
    recommended_action: str = ""      # What the user should consider doing

    # Confidence: 0.0–1.0 score or a text rationale
    confidence: float = 1.0
    confidence_rationale: str = ""

    # Deduplication key — alerts with the same key within the cooldown window are suppressed
    dedup_key: str = ""

    # Lifecycle
    status: AlertStatus = AlertStatus.NEW

    # Arbitrary extra context (JSON-serializable dict)
    extra: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Auto-generate a dedup key if not provided
        if not self.dedup_key:
            self.dedup_key = f"{self.category.value}:{self.affected_host}:{self.title}"


@dataclass
class Device:
    """
    A network device observed on the local LAN.

    The combination of (ip, mac) is what we track; changes to either
    are themselves anomaly signals.
    """
    ip: str
    mac: str
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    hostname: str = ""
    vendor: str = ""               # OUI lookup result
    is_trusted: bool = False       # User explicitly trusts this device
    is_gateway: bool = False
    alert_count: int = 0
    # Running score: higher = more suspicious activity observed
    suspicion_score: float = 0.0
    extra: dict = field(default_factory=dict)


@dataclass
class Connection:
    """
    A single observed network connection (from /proc/net/tcp or packet capture).
    """
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str           # "tcp" | "udp" | "icmp"
    state: str = ""         # e.g., "ESTABLISHED", "SYN_SENT"
    timestamp: datetime = field(default_factory=datetime.utcnow)
    pid: Optional[int] = None
    process_name: str = ""
    bytes_sent: int = 0
    bytes_recv: int = 0


@dataclass
class PacketSummary:
    """
    Aggregated packet statistics for a (src, dst, port) tuple over a time window.
    Used by the baseline engine and detectors without storing every raw packet.
    """
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    packet_count: int = 0
    byte_count: int = 0
    window_start: datetime = field(default_factory=datetime.utcnow)
    window_seconds: int = 60


@dataclass
class DNSQuery:
    """A single DNS query observed on the network."""
    timestamp: datetime
    src_ip: str
    query_name: str
    query_type: str     # A, AAAA, MX, TXT, etc.
    response_ip: str = ""
    ttl: int = 0
    is_nxdomain: bool = False


@dataclass
class AuthEvent:
    """Parsed entry from /var/log/auth.log or similar."""
    timestamp: datetime
    event_type: str     # "ssh_failure", "ssh_success", "sudo", "service_crash"
    user: str = ""
    src_ip: str = ""
    service: str = ""
    raw_line: str = ""
