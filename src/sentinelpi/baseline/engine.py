"""
baseline/engine.py - Behavioral baseline tracking and anomaly scoring.

The baseline engine observes normal behavior over time and provides
z-score-based anomaly detection for deviations.

Key baselines tracked:
1. Hourly connection counts per source IP (per day-of-week + hour)
2. Known (src, dst, port) destination tuples
3. Known DNS domains
4. Traffic volume per interface (bytes/minute)
5. Listening ports on the Pi itself

The engine has two phases:
  LEARNING: First N hours (configurable) — collect data, no anomaly alerts.
  ACTIVE:   After learning phase — flag deviations from established baseline.

Statistical method: Welford's online algorithm for running mean and stddev.
Anomaly threshold: mean + (z_factor * stddev), where z_factor is configurable.
For Raspberry Pi: this is lightweight — only aggregate counters are stored,
never individual packets.
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

from ..config.manager import Config
from ..storage.database import Database

logger = logging.getLogger(__name__)

# Default z-score thresholds for anomaly detection
Z_THRESHOLD_MEDIUM = 2.5   # 2.5 standard deviations above mean
Z_THRESHOLD_HIGH   = 4.0   # 4.0 standard deviations above mean


class RunningStats:
    """
    Welford's online algorithm for computing running mean and variance.

    Memory: O(1) — no raw samples stored.
    Thread safety: NOT thread-safe — callers hold the lock.
    """

    def __init__(self) -> None:
        self.n: int = 0
        self.mean: float = 0.0
        self._M2: float = 0.0    # sum of squared deviations

    def update(self, value: float) -> None:
        self.n += 1
        delta = value - self.mean
        self.mean += delta / self.n
        delta2 = value - self.mean
        self._M2 += delta * delta2

    @property
    def variance(self) -> float:
        return self._M2 / self.n if self.n >= 2 else 0.0

    @property
    def stddev(self) -> float:
        return self.variance ** 0.5

    def z_score(self, value: float) -> float:
        """Return how many standard deviations `value` is from the mean."""
        if self.stddev < 1e-9:
            # Flat baseline — any deviation is significant
            return abs(value - self.mean)
        return (value - self.mean) / self.stddev

    def is_anomalous(self, value: float, z_threshold: float = Z_THRESHOLD_MEDIUM) -> bool:
        """Return True if value is `z_threshold` stddevs above the mean."""
        if self.n < 5:  # Not enough samples to make reliable judgement
            return False
        return self.z_score(value) > z_threshold

    def __repr__(self) -> str:
        return f"RunningStats(n={self.n}, mean={self.mean:.2f}, stddev={self.stddev:.2f})"


class BaselineEngine:
    """
    Tracks and queries behavioral baselines for all monitored hosts.

    Usage:
      engine = BaselineEngine(config, db)
      engine.record_connection_count(ip, count)
      is_spike, z = engine.check_connection_spike(ip, current_count)
    """

    def __init__(self, config: Config, db: Database) -> None:
        self.config = config
        self.db = db
        self._lock = threading.RLock()

        # In-memory stats: (ip, hour_of_day, day_of_week) → RunningStats
        self._conn_stats: Dict[Tuple[str, int, int], RunningStats] = {}

        # Traffic bytes per minute per interface: iface → RunningStats
        self._traffic_stats: Dict[str, RunningStats] = {}

        # Known listening ports on the Pi: set of port numbers
        self._known_listening_ports: Set[int] = set()

        # DNS baseline: domain → first_seen timestamp
        # (We rely on db.is_known_dns_domain for persistence; this is in-memory fast path)
        self._known_domains: Set[str] = set()

        # Destination baseline: (src_ip, dst_ip, dst_port, proto) → seen count
        self._known_destinations: Set[Tuple[str, str, int, str]] = set()

        # Service start time — used to determine if we're still in learning phase
        self._start_time: datetime = datetime.utcnow()

        # Load from database on startup
        self._load_from_db()

        logger.info(
            "BaselineEngine initialized. Learning phase: %d hours.",
            config.monitoring.baseline_learning_hours,
        )

    def _load_from_db(self) -> None:
        """Pre-populate in-memory caches from database."""
        # Load top DNS domains
        top_domains = self.db.get_top_dns_domains(limit=5000)
        with self._lock:
            for row in top_domains:
                self._known_domains.add(row["domain"])
        logger.debug("Loaded %d known DNS domains from baseline.", len(self._known_domains))

    @property
    def is_learning(self) -> bool:
        """True if we're still in the initial learning phase."""
        elapsed_hours = (datetime.utcnow() - self._start_time).total_seconds() / 3600
        return elapsed_hours < self.config.monitoring.baseline_learning_hours

    # ------------------------------------------------------------------
    # Connection count baseline
    # ------------------------------------------------------------------

    def record_connection_count(self, ip: str, count: int) -> None:
        """
        Record an observed connection count for an IP at the current time.

        Call this once per polling interval (e.g., every minute) per source IP.
        """
        now = datetime.utcnow()
        hour = now.hour
        dow = now.weekday()
        key = (ip, hour, dow)

        with self._lock:
            if key not in self._conn_stats:
                self._conn_stats[key] = RunningStats()
            self._conn_stats[key].update(float(count))

        # Persist to database periodically (every 10 updates)
        stats = self._conn_stats.get(key)
        if stats and stats.n % 10 == 0:
            self.db.update_hourly_baseline(ip, hour, dow, float(count))

    def check_connection_spike(self, ip: str, current_count: int) -> Tuple[bool, float]:
        """
        Check if current_count is anomalously high for this IP/hour.

        Returns (is_spike, z_score).
        """
        if self.is_learning:
            return False, 0.0

        now = datetime.utcnow()
        key = (ip, now.hour, now.weekday())

        with self._lock:
            stats = self._conn_stats.get(key)

        if stats is None or stats.n < 5:
            return False, 0.0

        z = stats.z_score(float(current_count))
        threshold = self.config.thresholds.connection_spike_factor
        # Convert factor to z-score approximation: if current > mean * factor, flag
        if stats.mean > 0 and current_count > stats.mean * threshold:
            return True, z
        if stats.is_anomalous(float(current_count), Z_THRESHOLD_HIGH):
            return True, z

        return False, z

    # ------------------------------------------------------------------
    # Traffic volume baseline (bytes per minute per interface)
    # ------------------------------------------------------------------

    def record_traffic(self, interface: str, bytes_per_minute: float) -> None:
        """Record observed bytes/minute for an interface."""
        with self._lock:
            if interface not in self._traffic_stats:
                self._traffic_stats[interface] = RunningStats()
            self._traffic_stats[interface].update(bytes_per_minute)

    def check_traffic_spike(self, interface: str, current_bpm: float) -> Tuple[bool, float]:
        """
        Check if current bytes/min is anomalously high for this interface.

        Returns (is_spike, z_score).
        """
        if self.is_learning:
            return False, 0.0

        with self._lock:
            stats = self._traffic_stats.get(interface)

        if stats is None or stats.n < 5:
            return False, 0.0

        z = stats.z_score(current_bpm)
        factor = self.config.thresholds.traffic_spike_factor
        if stats.mean > 0 and current_bpm > stats.mean * factor:
            return True, z
        return stats.is_anomalous(current_bpm, Z_THRESHOLD_HIGH), z

    # ------------------------------------------------------------------
    # DNS domain baseline
    # ------------------------------------------------------------------

    def record_dns_domain(self, domain: str) -> bool:
        """
        Record a DNS domain as observed.

        Returns True if this is the first time this domain has been seen.
        """
        domain = domain.lower().strip(".")
        with self._lock:
            is_new = domain not in self._known_domains
            if is_new:
                self._known_domains.add(domain)
        self.db.record_dns_domain(domain)
        return is_new

    def is_known_domain(self, domain: str) -> bool:
        domain = domain.lower().strip(".")
        with self._lock:
            if domain in self._known_domains:
                return True
        return self.db.is_known_dns_domain(domain)

    def get_domain_count(self) -> int:
        with self._lock:
            return len(self._known_domains)

    # ------------------------------------------------------------------
    # Network destination baseline
    # ------------------------------------------------------------------

    def record_destination(self, src_ip: str, dst_ip: str, dst_port: int, protocol: str) -> bool:
        """
        Record a (src, dst, port, proto) tuple as observed.

        Returns True if this is the first time this destination has been seen.
        """
        key = (src_ip, dst_ip, dst_port, protocol)
        with self._lock:
            is_new = key not in self._known_destinations
            if is_new:
                self._known_destinations.add(key)
        self.db.record_destination(src_ip, dst_ip, dst_port, protocol)
        return is_new

    def is_known_destination(self, src_ip: str, dst_ip: str, dst_port: int, protocol: str) -> bool:
        key = (src_ip, dst_ip, dst_port, protocol)
        with self._lock:
            if key in self._known_destinations:
                return True
        return self.db.is_known_destination(src_ip, dst_ip, dst_port, protocol)

    # ------------------------------------------------------------------
    # Listening ports baseline
    # ------------------------------------------------------------------

    def record_listening_port(self, port: int) -> bool:
        """Record a listening port as known. Returns True if newly discovered."""
        with self._lock:
            is_new = port not in self._known_listening_ports
            self._known_listening_ports.add(port)
        return is_new

    def is_known_listening_port(self, port: int) -> bool:
        with self._lock:
            return port in self._known_listening_ports

    def get_known_listening_ports(self) -> Set[int]:
        with self._lock:
            return set(self._known_listening_ports)

    # ------------------------------------------------------------------
    # Baseline summary for dashboard/reports
    # ------------------------------------------------------------------

    def get_summary(self) -> dict:
        with self._lock:
            return {
                "is_learning": self.is_learning,
                "learning_hours_remaining": max(
                    0,
                    self.config.monitoring.baseline_learning_hours
                    - (datetime.utcnow() - self._start_time).total_seconds() / 3600
                ),
                "known_domains": len(self._known_domains),
                "known_destinations": len(self._known_destinations),
                "known_listening_ports": sorted(self._known_listening_ports),
                "tracked_hosts": len(set(ip for (ip, _, _) in self._conn_stats)),
            }
