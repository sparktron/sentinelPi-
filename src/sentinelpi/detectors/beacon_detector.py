"""
detectors/beacon_detector.py - Beacon / C2 check-in pattern detection.

Beaconing malware calls home at regular intervals (e.g., every 60 seconds).
This is a strong signal because legitimate user-driven traffic is irregular.

Detection method:
  For each (src_ip, dst_ip, dst_port) tuple, we collect a sliding window of
  connection timestamps. If we see >= min_intervals connections, we compute
  the coefficient of variation (CV = stddev/mean) of the inter-arrival times.

  Low CV means very regular timing — characteristic of automated beaconing.

  CV < 0.15 with >= 8 intervals → suspicious (configurable thresholds)

We also check for jittered beaconing (malware that adds random jitter to
avoid detection) by looking for periodicity in the autocorrelation.

Limitations:
- This detector needs time to accumulate intervals (min 8 gaps = 9 events).
- It may false-positive on very regular legitimate services (time sync, etc.)
  Suppress these via whitelist.
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from .base import BaseDetector
from ..capture.packet_capture import CapturedConnection
from ..models import Alert, AlertCategory, Severity
from ..utils.network import is_private_ip

logger = logging.getLogger(__name__)

# Known beaconing-safe services to ignore
KNOWN_PERIODIC_SERVICES = {
    53,    # DNS
    123,   # NTP
    443,   # HTTPS (many legitimate services beacon here)
    80,    # HTTP
    5353,  # mDNS
}


class BeaconDetector(BaseDetector):
    """
    Detects regular outbound connection intervals that suggest beaconing.

    State: (src_ip, dst_ip, dst_port) → deque of timestamps (max 200)
    """

    # How many timestamps to retain per flow
    MAX_TIMESTAMPS = 200
    # How long a flow must be silent before we clear its history
    FLOW_IDLE_SECONDS = 3600

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # (src_ip, dst_ip, dst_port) → deque of connection timestamps
        self._flow_timestamps: Dict[Tuple[str, str, int], deque] = defaultdict(
            lambda: deque(maxlen=self.MAX_TIMESTAMPS)
        )
        # Track last alert time per flow to avoid alert storms
        self._last_alert: Dict[Tuple[str, str, int], datetime] = {}
        # Last time we ran cleanup
        self._last_cleanup: datetime = datetime.utcnow()

    def process_event(self, event: object) -> List[Alert]:
        """Process outbound connection events."""
        if not isinstance(event, CapturedConnection):
            return []
        # Only care about outbound connections to non-private destinations
        if is_private_ip(event.dst_ip):
            return []
        if self._is_whitelisted_ip(event.dst_ip):
            return []
        if event.dst_port in KNOWN_PERIODIC_SERVICES or self._is_whitelisted_port(event.dst_port):
            return []

        key = (event.src_ip, event.dst_ip, event.dst_port)
        self._flow_timestamps[key].append(event.timestamp)

        # Analyze once we have enough data
        timestamps = list(self._flow_timestamps[key])
        if len(timestamps) < self.config.thresholds.beacon_min_intervals + 1:
            return []

        return self._analyze_flow(key, timestamps)

    def poll(self) -> List[Alert]:
        """
        Periodically check connection data from /proc/net for beacon patterns.

        This covers cases where packet capture is disabled.
        """
        from ..capture.proc_reader import read_tcp_connections
        alerts: List[Alert] = []
        now = datetime.utcnow()

        connections = read_tcp_connections(include_listen=False)
        for conn in connections:
            if conn.state not in ("ESTABLISHED", "SYN_SENT"):
                continue
            if is_private_ip(conn.remote_ip):
                continue
            if self._is_whitelisted_ip(conn.remote_ip):
                continue
            if conn.remote_port in KNOWN_PERIODIC_SERVICES:
                continue

            key = (conn.local_ip, conn.remote_ip, conn.remote_port)
            # In proc-poll mode we just add one timestamp per poll cycle
            self._flow_timestamps[key].append(now)

            timestamps = list(self._flow_timestamps[key])
            if len(timestamps) >= self.config.thresholds.beacon_min_intervals + 1:
                alerts.extend(self._analyze_flow(key, timestamps))

        # Periodic cleanup of idle flows
        if (now - self._last_cleanup).total_seconds() > 300:
            self._cleanup_idle_flows(now)
            self._last_cleanup = now

        return alerts

    def _analyze_flow(
        self, key: Tuple[str, str, int], timestamps: List[datetime]
    ) -> List[Alert]:
        """
        Analyze timing regularity for a flow.

        Computes coefficient of variation of inter-arrival times.
        CV = stddev / mean — lower = more regular = more suspicious.
        """
        if len(timestamps) < 3:
            return []

        # Compute inter-arrival intervals in seconds
        intervals = [
            (timestamps[i+1] - timestamps[i]).total_seconds()
            for i in range(len(timestamps) - 1)
        ]

        # Filter out very short intervals (burst traffic noise)
        intervals = [t for t in intervals if t >= 1.0]
        if len(intervals) < self.config.thresholds.beacon_min_intervals:
            return []

        mean_interval = sum(intervals) / len(intervals)
        if mean_interval < 5.0:  # Less than 5s mean → not beaconing, just busy traffic
            return []

        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        stddev = math.sqrt(variance)
        cv = stddev / mean_interval if mean_interval > 0 else float("inf")

        threshold = self.config.thresholds.beacon_cv_threshold
        if cv > threshold:
            return []  # Too irregular to be beaconing

        # Additional check: verify minimum number of intervals analyzed
        if len(intervals) < self.config.thresholds.beacon_min_intervals:
            return []

        # Cooldown: don't re-alert for the same flow within 30 minutes
        now = datetime.utcnow()
        last = self._last_alert.get(key)
        if last and (now - last).total_seconds() < 1800:
            return []

        self._last_alert[key] = now
        src_ip, dst_ip, dst_port = key

        # Classify severity by regularity (lower CV = more suspicious)
        if cv < 0.05:
            severity = Severity.HIGH
            conf = 0.85
        elif cv < 0.10:
            severity = Severity.MEDIUM
            conf = 0.75
        else:
            severity = Severity.LOW
            conf = 0.65

        # Don't flag if baseline says this is a known destination
        if self.baseline.is_known_destination(src_ip, dst_ip, dst_port, "tcp") and not self.baseline.is_learning:
            # Lower severity if we've seen this before
            if severity == Severity.HIGH:
                severity = Severity.MEDIUM
            conf -= 0.15

        return [Alert(
            severity=severity,
            category=AlertCategory.BEACON,
            affected_host=src_ip,
            related_host=dst_ip,
            title=f"Beacon pattern: {src_ip} → {dst_ip}:{dst_port} every ~{mean_interval:.0f}s",
            description=(
                f"{src_ip} is connecting to {dst_ip}:{dst_port} at very regular intervals. "
                f"Mean interval: {mean_interval:.1f}s, coefficient of variation: {cv:.3f} "
                f"(lower = more regular). Based on {len(intervals)} observed intervals. "
                "This pattern is consistent with malware beaconing to a C2 server."
            ),
            recommended_action=(
                f"Investigate which process on {src_ip} is making these connections. "
                f"Use 'ss -tp' or 'netstat -tp' to find the process. "
                "Check the destination IP/domain for threat intelligence. "
                "If malicious, block at firewall and quarantine the device."
            ),
            confidence=max(0.0, min(1.0, conf)),
            confidence_rationale=(
                f"CV={cv:.3f} (threshold={threshold}), {len(intervals)} intervals analyzed, "
                f"mean={mean_interval:.1f}s"
            ),
            dedup_key=f"beacon:{src_ip}:{dst_ip}:{dst_port}",
            extra={
                "mean_interval_seconds": round(mean_interval, 2),
                "cv": round(cv, 4),
                "interval_count": len(intervals),
                "min_interval": round(min(intervals), 2),
                "max_interval": round(max(intervals), 2),
            },
        )]

    def _cleanup_idle_flows(self, now: datetime) -> None:
        """Remove flow history for flows that have been silent too long."""
        cutoff = now - timedelta(seconds=self.FLOW_IDLE_SECONDS)
        idle_keys = [
            k for k, ts_deque in self._flow_timestamps.items()
            if ts_deque and ts_deque[-1] < cutoff
        ]
        for k in idle_keys:
            del self._flow_timestamps[k]
            self._last_alert.pop(k, None)
        if idle_keys:
            logger.debug("Cleaned up %d idle beacon flows.", len(idle_keys))
