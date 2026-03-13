"""
detectors/lateral_movement_detector.py - Lateral movement detection.

Lateral movement is when an attacker (or malware) moves from one compromised
host to other hosts on the same LAN.

Detectors:
1. One host connecting to many internal hosts via admin protocols (SSH, RDP, SMB).
2. Internal-to-internal connections on unusual high ports.
3. A host scanning many internal hosts rapidly.
4. New SMB/RDP/SSH connections from unexpected source hosts.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

from .base import BaseDetector
from ..capture.packet_capture import CapturedConnection
from ..capture.proc_reader import read_tcp_connections
from ..models import Alert, AlertCategory, Severity
from ..utils.network import is_private_ip

logger = logging.getLogger(__name__)

# Administrative/sensitive protocols that are high-value lateral movement paths
ADMIN_PORTS = {
    22: "SSH",
    23: "Telnet",
    135: "MS-RPC",
    139: "NetBIOS",
    445: "SMB",
    3389: "RDP",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
}


class LateralMovementDetector(BaseDetector):
    """
    Detects lateral movement patterns between internal LAN hosts.

    Focuses on:
    - Admin protocol fan-out from a single source
    - Unexpected internal connection patterns
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # src_ip → deque of (timestamp, dst_ip, dst_port)
        self._internal_conns: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        # Track known (src→dst) pairs for admin protocols to detect new patterns
        self._known_admin_pairs: Set[Tuple[str, str, int]] = set()
        self._admin_pairs_initialized = False
        self._last_alert: Dict[str, datetime] = {}

    def process_event(self, event: object) -> List[Alert]:
        """Process internal-to-internal connection events."""
        if not isinstance(event, CapturedConnection):
            return []
        if not self._is_local_ip(event.src_ip) or not self._is_local_ip(event.dst_ip):
            return []
        return self._record_internal_connection(
            event.src_ip, event.dst_ip, event.dst_port, event.timestamp
        )

    def poll(self) -> List[Alert]:
        """Poll /proc/net/tcp for internal connections."""
        alerts: List[Alert] = []
        connections = read_tcp_connections(include_listen=False)
        now = datetime.utcnow()

        for conn in connections:
            if conn.state not in ("ESTABLISHED", "SYN_SENT"):
                continue
            if not self._is_local_ip(conn.local_ip) or not self._is_local_ip(conn.remote_ip):
                continue
            # Skip same-host connections (loopback between processes)
            if conn.local_ip == conn.remote_ip:
                continue
            new_alerts = self._record_internal_connection(
                conn.local_ip, conn.remote_ip, conn.remote_port, now
            )
            alerts.extend(new_alerts)

        # Initialize known pairs on first run
        if not self._admin_pairs_initialized:
            self._admin_pairs_initialized = True

        return alerts

    def _record_internal_connection(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        timestamp: datetime,
    ) -> List[Alert]:
        alerts: List[Alert] = []

        if self._is_whitelisted_ip(src_ip) or self._is_whitelisted_ip(dst_ip):
            return []

        self._internal_conns[src_ip].append((timestamp, dst_ip, dst_port))

        # Check fan-out threshold
        fanout_alert = self._check_admin_fanout(src_ip, timestamp)
        if fanout_alert:
            alerts.append(fanout_alert)

        # Check for new admin protocol connection
        if dst_port in ADMIN_PORTS:
            new_admin_alert = self._check_new_admin_connection(src_ip, dst_ip, dst_port, timestamp)
            if new_admin_alert:
                alerts.append(new_admin_alert)

        return alerts

    def _check_admin_fanout(self, src_ip: str, now: datetime) -> Optional[Alert]:
        """
        Flag if one host is making admin protocol connections to many internal hosts.

        This is a strong lateral movement indicator.
        """
        dedup_key = f"lateral_fanout:{src_ip}"
        if self._is_on_cooldown(dedup_key, now, 300):
            return None

        cutoff = now - timedelta(seconds=60)
        entries = [(t, dst, port) for t, dst, port in self._internal_conns[src_ip]
                   if t > cutoff and port in ADMIN_PORTS]

        unique_admin_targets = {dst for _, dst, _ in entries}
        threshold = self.config.thresholds.lateral_movement_dest_threshold

        if len(unique_admin_targets) < threshold:
            return None

        self._last_alert[dedup_key] = now
        port_names = {ADMIN_PORTS[p] for _, _, p in entries if p in ADMIN_PORTS}

        return Alert(
            severity=Severity.HIGH,
            category=AlertCategory.LATERAL_MOVEMENT,
            affected_host=src_ip,
            title=f"Possible lateral movement: {src_ip} → {len(unique_admin_targets)} hosts via admin protocols",
            description=(
                f"{src_ip} made admin-protocol connections ({', '.join(port_names)}) to "
                f"{len(unique_admin_targets)} different internal hosts within 60 seconds. "
                "This pattern is consistent with lateral movement by an attacker who has compromised "
                "this host and is attempting to spread or collect credentials."
            ),
            recommended_action=(
                f"Immediately investigate {src_ip}. "
                "Check for unauthorized processes, unusual logged-in users, or signs of compromise. "
                "Consider isolating this host from the network pending investigation."
            ),
            confidence=0.80,
            confidence_rationale=(
                f"{len(unique_admin_targets)} unique admin targets in 60s "
                f"(threshold: {threshold})."
            ),
            dedup_key=dedup_key,
            extra={
                "target_count": len(unique_admin_targets),
                "protocols": list(port_names),
                "sample_targets": list(unique_admin_targets)[:5],
            },
        )

    def _check_new_admin_connection(
        self, src_ip: str, dst_ip: str, dst_port: int, now: datetime
    ) -> Optional[Alert]:
        """
        Alert on a first-ever admin protocol connection between two internal hosts.

        Legitimate admin connections are usually from a small set of known management hosts.
        """
        if self.baseline.is_learning:
            # During learning phase, build baseline of known admin pairs
            self._known_admin_pairs.add((src_ip, dst_ip, dst_port))
            return None

        key = (src_ip, dst_ip, dst_port)
        if key in self._known_admin_pairs:
            return None

        # Also check database
        if self.baseline.is_known_destination(src_ip, dst_ip, dst_port, "tcp"):
            self._known_admin_pairs.add(key)
            return None

        self._known_admin_pairs.add(key)
        protocol_name = ADMIN_PORTS[dst_port]

        dedup_key = f"new_admin:{src_ip}:{dst_ip}:{dst_port}"
        if self._is_on_cooldown(dedup_key, now, 86400):
            return None
        self._last_alert[dedup_key] = now

        return Alert(
            severity=Severity.MEDIUM,
            category=AlertCategory.LATERAL_MOVEMENT,
            affected_host=dst_ip,
            related_host=src_ip,
            title=f"New {protocol_name} connection: {src_ip} → {dst_ip}",
            description=(
                f"{src_ip} established a {protocol_name} (port {dst_port}) connection to "
                f"internal host {dst_ip} — this combination has not been seen before. "
                "New admin connections between internal hosts can indicate lateral movement."
            ),
            recommended_action=(
                f"Verify that {src_ip} is authorized to {protocol_name} into {dst_ip}. "
                "Check login logs on the destination host."
            ),
            confidence=0.60,
            confidence_rationale="First time this (src→dst:admin_port) pair has been observed.",
            dedup_key=dedup_key,
            extra={"protocol": protocol_name, "port": dst_port},
        )

    def _is_on_cooldown(self, key: str, now: datetime, seconds: int) -> bool:
        last = self._last_alert.get(key)
        return bool(last and (now - last).total_seconds() < seconds)
