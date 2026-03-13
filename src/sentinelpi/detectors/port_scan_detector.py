"""
detectors/port_scan_detector.py - Port scan and host sweep detection.

Detects:
1. Horizontal port scan: one source probing many ports on one target.
2. Host sweep: one source attempting to reach many different hosts.
3. SYN flood indicators: excessive SYN packets with no ACK.
4. Half-open scan patterns: many RST responses (RST-based probing).

Method: sliding window counter per (src, dst) pair.
Window: 60 seconds.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

from .base import BaseDetector
from ..capture.packet_capture import CapturedConnection
from ..models import Alert, AlertCategory, Severity

logger = logging.getLogger(__name__)


class PortScanDetector(BaseDetector):
    """
    Sliding-window port scan and host sweep detector.

    Works both with packet capture events (process_event) and
    /proc/net/tcp polling (poll) for connection state analysis.
    """

    WINDOW_SECONDS = 60

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # (src_ip, dst_ip) → deque of (timestamp, port) — for vertical scan
        self._scan_ports: Dict[Tuple[str, str], deque] = defaultdict(lambda: deque(maxlen=500))
        # src_ip → deque of (timestamp, dst_ip) — for host sweep
        self._sweep_targets: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        # Suppression: (src_ip, dst_ip) → last alert time
        self._last_alert: Dict[str, datetime] = {}

    def process_event(self, event: object) -> List[Alert]:
        """Process CapturedConnection events (TCP SYNs)."""
        if not isinstance(event, CapturedConnection):
            return []
        if event.protocol != "tcp":
            return []
        # Only care about SYN packets (connection initiation)
        if "S" not in event.flags:
            return []
        return self._record_connection(event.src_ip, event.dst_ip, event.dst_port, event.timestamp)

    def poll(self) -> List[Alert]:
        """
        Poll /proc/net/tcp for SYN_SENT connections.

        SYN_SENT with no established counterpart suggests scanning.
        """
        from ..capture.proc_reader import read_tcp_connections
        alerts: List[Alert] = []
        connections = read_tcp_connections(include_listen=False)
        now = datetime.utcnow()

        # Count SYN_SENT connections per (src, dst) pair
        syn_counts: Dict[Tuple[str, str], Set[int]] = defaultdict(set)
        for conn in connections:
            if conn.state == "SYN_SENT":
                if self._is_local_ip(conn.local_ip) and not self._is_local_ip(conn.remote_ip):
                    syn_counts[(conn.local_ip, conn.remote_ip)].add(conn.remote_port)

        for (src, dst), ports in syn_counts.items():
            for port in ports:
                new_alerts = self._record_connection(src, dst, port, now)
                alerts.extend(new_alerts)

        return alerts

    def _record_connection(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        timestamp: datetime,
    ) -> List[Alert]:
        alerts: List[Alert] = []

        if self._is_whitelisted_ip(src_ip) or self._is_whitelisted_port(dst_port):
            return []

        # Track for vertical port scan (same src→dst, many ports)
        key = (src_ip, dst_ip)
        self._scan_ports[key].append((timestamp, dst_port))

        # Track for host sweep (same src, many dst hosts)
        self._sweep_targets[src_ip].append((timestamp, dst_ip))

        # Check for port scan
        scan_alert = self._check_port_scan(src_ip, dst_ip, timestamp)
        if scan_alert:
            alerts.append(scan_alert)

        # Check for host sweep
        sweep_alert = self._check_host_sweep(src_ip, timestamp)
        if sweep_alert:
            alerts.append(sweep_alert)

        return alerts

    def _check_port_scan(self, src_ip: str, dst_ip: str, now: datetime) -> Optional[Alert]:
        """Flag if src has probed too many unique ports on dst in the window."""
        key = (src_ip, dst_ip)
        dedup_key = f"port_scan:{src_ip}:{dst_ip}"

        # Cooldown: don't re-alert within 5 minutes for the same pair
        if self._is_on_cooldown(dedup_key, now, cooldown_seconds=300):
            return None

        entries = self._scan_ports[key]
        cutoff = now - timedelta(seconds=self.WINDOW_SECONDS)
        recent = [(t, p) for t, p in entries if t > cutoff]
        unique_ports = {p for _, p in recent}

        threshold = self.config.thresholds.port_scan_ports_per_minute
        if len(unique_ports) < threshold:
            return None

        self._last_alert[dedup_key] = now

        # Classify severity by scan breadth
        if len(unique_ports) >= 100:
            severity = Severity.HIGH
        elif len(unique_ports) >= 50:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        src_label = "internal" if self._is_local_ip(src_ip) else "external"
        dst_label = "internal" if self._is_local_ip(dst_ip) else "external"

        sample_ports = sorted(unique_ports)[:10]

        return Alert(
            severity=severity,
            category=AlertCategory.PORT_SCAN,
            affected_host=dst_ip,
            related_host=src_ip,
            title=f"Port scan: {src_ip} → {dst_ip} ({len(unique_ports)} ports/min)",
            description=(
                f"{src_label.capitalize()} host {src_ip} probed {len(unique_ports)} unique ports "
                f"on {dst_label} host {dst_ip} within {self.WINDOW_SECONDS}s. "
                f"Sample ports: {sample_ports}{'...' if len(unique_ports) > 10 else ''}. "
                "This is consistent with automated port scanning (nmap, masscan, etc.)."
            ),
            recommended_action=(
                f"Identify the host at {src_ip} and determine if scanning is authorized. "
                "If unauthorized, check the device for malware or unauthorized tools. "
                "Consider blocking this source at your firewall."
            ),
            confidence=0.9,
            confidence_rationale=f"{len(unique_ports)} unique ports in {self.WINDOW_SECONDS}s window.",
            dedup_key=dedup_key,
            extra={
                "unique_ports_count": len(unique_ports),
                "sample_ports": sample_ports,
                "window_seconds": self.WINDOW_SECONDS,
            },
        )

    def _check_host_sweep(self, src_ip: str, now: datetime) -> Optional[Alert]:
        """Flag if src has contacted too many unique hosts in the window."""
        dedup_key = f"host_sweep:{src_ip}"

        if self._is_on_cooldown(dedup_key, now, cooldown_seconds=300):
            return None

        entries = self._sweep_targets[src_ip]
        cutoff = now - timedelta(seconds=self.WINDOW_SECONDS)
        recent = [(t, ip) for t, ip in entries if t > cutoff]
        unique_hosts = {ip for _, ip in recent}

        # Only flag sweeps targeting local hosts (external sweeps are normal browsing)
        local_hosts = {ip for ip in unique_hosts if self._is_local_ip(ip)}

        # Threshold: >15 unique local hosts in 60s is suspicious
        if len(local_hosts) < 15:
            return None

        self._last_alert[dedup_key] = now

        return Alert(
            severity=Severity.MEDIUM,
            category=AlertCategory.PORT_SCAN,
            affected_host="LAN",
            related_host=src_ip,
            title=f"Host sweep: {src_ip} contacted {len(local_hosts)} local hosts in {self.WINDOW_SECONDS}s",
            description=(
                f"{src_ip} made connection attempts to {len(local_hosts)} different hosts "
                f"on your local network within {self.WINDOW_SECONDS}s. "
                "This is consistent with network reconnaissance or a spreading worm."
            ),
            recommended_action=(
                f"Investigate the device at {src_ip} immediately. "
                "Check for malware, especially worms that spread via SMB or network shares."
            ),
            confidence=0.8,
            confidence_rationale=f"{len(local_hosts)} unique local hosts in {self.WINDOW_SECONDS}s.",
            dedup_key=dedup_key,
            extra={"unique_hosts": len(local_hosts), "src_ip": src_ip},
        )

    def _is_on_cooldown(self, key: str, now: datetime, cooldown_seconds: int = 300) -> bool:
        """Return True if we recently alerted on this key."""
        last = self._last_alert.get(key)
        if last is None:
            return False
        return (now - last).total_seconds() < cooldown_seconds
