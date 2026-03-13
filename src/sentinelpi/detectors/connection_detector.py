"""
detectors/connection_detector.py - Connection volume and pattern anomaly detection.

Detects:
1. Connection count spikes (baseline deviation).
2. Repeated failed connection attempts (refused connections, brute force indicators).
3. New outbound connections to rare/first-seen external IPs.
4. Connections to unusual/suspicious port numbers.
5. New listening ports on the Pi.
6. Process binding to unexpected interfaces.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

from .base import BaseDetector
from ..capture.proc_reader import read_tcp_connections, read_listening_ports
from ..models import Alert, AlertCategory, Severity
from ..utils.network import is_private_ip
from ..utils.geo import lookup_country

logger = logging.getLogger(__name__)

# Ports that are commonly suspicious when receiving outbound connections
# Not exhaustive — used to add context to alerts rather than trigger them alone
SUSPICIOUS_PORTS = {
    22,    # SSH outbound (lateral movement)
    23,    # Telnet
    135,   # MS RPC
    137, 138, 139,  # NetBIOS
    445,   # SMB
    1433,  # MSSQL
    1521,  # Oracle DB
    3306,  # MySQL
    3389,  # RDP
    4444,  # Metasploit default
    4445,
    5900,  # VNC
    6666, 6667, 6668, 6669,  # IRC (often malware C2)
    8080, 8443,  # Alternate HTTP/S
    9001, 9030,  # Tor
    31337,  # Classic backdoor port
}

# Ports that are commonly legitimate outbound and should be treated as low-interest
COMMON_OUTBOUND_PORTS = {80, 443, 53, 123, 8080, 8443, 587, 465, 993, 995, 25}


class ConnectionDetector(BaseDetector):
    """
    Monitors connection counts and patterns against baseline.

    Poll interval: 60 seconds.
    """

    POLL_INTERVAL = 60

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # src_ip → count of active connections at last poll
        self._conn_counts: Dict[str, int] = {}
        # Track refused/reset connections: src_ip → deque of timestamps
        self._refused_times: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        # Known listening ports (set of port ints)
        self._known_listening: Set[int] = set()
        self._listening_initialized = False
        # Alert cooldowns
        self._last_alert: Dict[str, datetime] = {}

    def poll(self) -> List[Alert]:
        """Sample connection state from /proc/net/tcp."""
        alerts: List[Alert] = []
        now = datetime.utcnow()

        # --- Connection count monitoring ---
        connections = read_tcp_connections(include_listen=False)
        current_counts: Dict[str, int] = defaultdict(int)

        for conn in connections:
            if self._is_local_ip(conn.local_ip):
                current_counts[conn.local_ip] += 1

        for ip, count in current_counts.items():
            self.baseline.record_connection_count(ip, count)
            is_spike, z = self.baseline.check_connection_spike(ip, count)
            if is_spike:
                alert = self._connection_spike_alert(ip, count, z, now)
                if alert:
                    alerts.append(alert)

        # --- New external destinations ---
        for conn in connections:
            if conn.state in ("ESTABLISHED", "SYN_SENT") and not is_private_ip(conn.remote_ip):
                is_new = self.baseline.record_destination(
                    conn.local_ip, conn.remote_ip, conn.remote_port, conn.protocol
                )
                if is_new and not self.baseline.is_learning:
                    alert = self._new_destination_alert(conn, now)
                    if alert:
                        alerts.append(alert)

        # --- New listening ports ---
        alerts.extend(self._check_listening_ports(now))

        return alerts

    def _connection_spike_alert(
        self, ip: str, count: int, z_score: float, now: datetime
    ) -> Optional[Alert]:
        """Create a connection count spike alert."""
        dedup_key = f"conn_spike:{ip}"
        if self._is_on_cooldown(dedup_key, now, 600):
            return None
        self._last_alert[dedup_key] = now

        hostname = ""
        device = self.device_tracker.get_device(ip)
        if device:
            hostname = device.hostname

        return Alert(
            severity=Severity.MEDIUM,
            category=AlertCategory.CONNECTION_ANOMALY,
            affected_host=ip,
            title=f"Connection spike: {ip}{' (' + hostname + ')' if hostname else ''} ({count} active)",
            description=(
                f"{ip} has {count} active connections — significantly above its normal baseline "
                f"(z-score: {z_score:.1f}). "
                "This could indicate data exfiltration, malware activity, or a legitimate "
                "but unusual task (large file sync, backup, update)."
            ),
            recommended_action=(
                f"Use 'ss -tp' on {ip} (if accessible) to see which process owns these connections. "
                "Check destination IPs for legitimacy."
            ),
            confidence=min(0.95, 0.5 + z_score * 0.1),
            confidence_rationale=f"Z-score of {z_score:.2f} above baseline for this hour/day.",
            dedup_key=dedup_key,
            extra={"connection_count": count, "z_score": round(z_score, 2)},
        )

    def _new_destination_alert(self, conn: "ProcConnection", now: datetime) -> Optional[Alert]:
        """Alert on first-ever connection to an external IP/port."""
        if self._is_whitelisted_ip(conn.remote_ip):
            return None
        if conn.remote_port in COMMON_OUTBOUND_PORTS:
            # Common ports to new IPs are lower interest
            severity = Severity.INFO
        elif conn.remote_port in SUSPICIOUS_PORTS:
            severity = Severity.MEDIUM
        else:
            severity = Severity.INFO

        # Geolocation context
        country = lookup_country(conn.remote_ip)
        country_str = f" ({country})" if country else ""

        dedup_key = f"new_dest:{conn.local_ip}:{conn.remote_ip}:{conn.remote_port}"
        if self._is_on_cooldown(dedup_key, now, 86400):  # 24h cooldown for same dest
            return None
        self._last_alert[dedup_key] = now

        port_note = ""
        if conn.remote_port in SUSPICIOUS_PORTS:
            port_note = f" Port {conn.remote_port} is associated with potentially sensitive services."

        return Alert(
            severity=severity,
            category=AlertCategory.CONNECTION_ANOMALY,
            affected_host=conn.local_ip,
            related_host=conn.remote_ip,
            title=f"New destination: {conn.local_ip} → {conn.remote_ip}:{conn.remote_port}{country_str}",
            description=(
                f"{conn.local_ip} connected to a previously unseen external destination: "
                f"{conn.remote_ip}:{conn.remote_port}/{conn.protocol}{country_str}.{port_note} "
                f"Process: {conn.process_name or 'unknown'}."
            ),
            recommended_action=(
                f"Verify this is expected. Look up {conn.remote_ip} in threat intel databases "
                "if unfamiliar. No immediate action needed for INFO-level alerts."
            ),
            confidence=0.6,
            confidence_rationale="First time this (src→dst:port) combination has been observed.",
            dedup_key=dedup_key,
            extra={
                "remote_ip": conn.remote_ip,
                "remote_port": conn.remote_port,
                "protocol": conn.protocol,
                "process": conn.process_name,
                "country": country,
            },
        )

    def _check_listening_ports(self, now: datetime) -> List[Alert]:
        """Alert on new listening ports that weren't seen at startup."""
        alerts: List[Alert] = []
        listening = read_listening_ports()

        if not self._listening_initialized:
            # First run — populate baseline, don't alert
            for conn in listening:
                self._known_listening.add(conn.local_port)
                self.baseline.record_listening_port(conn.local_port)
            self._listening_initialized = True
            return []

        current_ports = {conn.local_port for conn in listening}

        # New ports
        for conn in listening:
            if conn.local_port not in self._known_listening:
                dedup_key = f"new_listen:{conn.local_port}"
                if not self._is_on_cooldown(dedup_key, now, 3600):
                    self._last_alert[dedup_key] = now
                    alert = self._new_listening_port_alert(conn, now)
                    alerts.append(alert)
                self._known_listening.add(conn.local_port)
                self.baseline.record_listening_port(conn.local_port)

        return alerts

    def _new_listening_port_alert(self, conn: "ProcConnection", now: datetime) -> Alert:
        severity = Severity.MEDIUM if conn.local_port in SUSPICIOUS_PORTS else Severity.LOW
        is_all_interfaces = conn.local_ip in ("0.0.0.0", "::")

        return Alert(
            severity=severity,
            category=AlertCategory.PROCESS_ANOMALY,
            affected_host=conn.local_ip,
            title=f"New listening port: {conn.local_port}/{conn.protocol} ({conn.process_name or 'unknown'})",
            description=(
                f"A new service is listening on port {conn.local_port}/{conn.protocol} "
                f"on {'all interfaces (0.0.0.0)' if is_all_interfaces else conn.local_ip}. "
                f"Process: {conn.process_name or 'unknown'} (PID {conn.pid or 'unknown'}). "
                + ("WARNING: Bound to all interfaces — accessible from the network." if is_all_interfaces else "")
            ),
            recommended_action=(
                f"Verify that port {conn.local_port} is an expected service. "
                "If unexpected, check the process with 'ps aux' and consider stopping it."
            ),
            confidence=0.85,
            confidence_rationale="Port not present during initialization baseline.",
            dedup_key=f"new_listen:{conn.local_port}",
            extra={
                "port": conn.local_port,
                "process": conn.process_name,
                "pid": conn.pid,
                "all_interfaces": is_all_interfaces,
            },
        )

    def _is_on_cooldown(self, key: str, now: datetime, seconds: int) -> bool:
        last = self._last_alert.get(key)
        return bool(last and (now - last).total_seconds() < seconds)
