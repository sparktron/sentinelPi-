"""
detectors/base.py - Abstract base class for all anomaly detectors.

Each detector is a self-contained module that:
1. Receives relevant events or runs on a polling interval.
2. Uses the baseline engine and/or rule-based logic to detect anomalies.
3. Returns Alert objects for the alert manager.

Convention:
- poll() is called periodically by the service runner.
- process_event() is called for real-time events (packet capture).
- All detectors must be safe to instantiate and run without elevated privileges
  (gracefully degrade if data is unavailable).
"""

from __future__ import annotations

import logging
import threading
from abc import ABC
from datetime import datetime, timedelta
from ..utils import clock
from typing import Dict, List, TYPE_CHECKING

if TYPE_CHECKING:
    from ..models import Alert
    from ..config.manager import Config
    from ..baseline.engine import BaselineEngine
    from ..storage.database import Database
    from ..inventory.device_tracker import DeviceTracker

logger = logging.getLogger(__name__)


class BaseDetector(ABC):
    """
    Abstract base for all SentinelPi detectors.

    Subclasses implement _poll() and/or _process_event().

    Thread safety: a single detector instance is driven from two threads —
    the event-router thread (process_event) and a per-detector polling thread
    (poll). Detector state is plain dict/deque, so both entry points are
    serialized through a per-instance reentrant lock. Subclasses override the
    protected _poll/_process_event hooks and never need to lock themselves.
    """

    def __init__(
        self,
        config: "Config",
        db: "Database",
        baseline: "BaselineEngine",
        device_tracker: "DeviceTracker",
    ) -> None:
        self.config = config
        self.db = db
        self.baseline = baseline
        self.device_tracker = device_tracker
        self.logger = logging.getLogger(self.__class__.__module__ + "." + self.__class__.__name__)
        # Serializes process_event() and poll() so detector state is never
        # mutated from two threads at once. Reentrant so a hook may call the
        # other public entry point without deadlocking.
        self._lock = threading.RLock()

    def poll(self) -> List["Alert"]:
        """Periodic entry point — locks and delegates to _poll(). Do not override."""
        with self._lock:
            return self._poll()

    def process_event(self, event: object) -> List["Alert"]:
        """Real-time entry point — locks and delegates to _process_event(). Do not override."""
        with self._lock:
            return self._process_event(event)

    def _poll(self) -> List["Alert"]:
        """
        Called periodically by the service runner (under the detector lock).

        Override in detectors that need to sample system state at an interval.
        Default implementation does nothing.
        """
        return []

    def _process_event(self, event: object) -> List["Alert"]:
        """
        Called for each incoming real-time event (under the detector lock).

        Override in detectors that need to react to streaming events.
        Default implementation does nothing.
        """
        return []

    @property
    def name(self) -> str:
        return self.__class__.__name__

    # ------------------------------------------------------------------
    # Shared state-eviction helpers (call from _poll, under the lock)
    # ------------------------------------------------------------------
    #
    # Detector activity/suppression maps are keyed per src_ip / flow / dedup_key.
    # The deques inside them are maxlen-bounded, but the *number of keys* is not,
    # so on a busy network they grow for the life of the daemon. These helpers
    # drop keys that can no longer affect detection, keeping memory bounded.

    @staticmethod
    def _evict_expired_times(time_map: Dict[object, datetime], max_age_seconds: float) -> int:
        """
        Drop keys from a {key: datetime} map whose value is older than max_age.

        Used for suppression/cooldown maps (e.g. _last_alert). Returns the number
        of keys evicted. Caller must hold the detector lock.
        """
        cutoff = clock.now() - timedelta(seconds=max_age_seconds)
        stale = [key for key, ts in time_map.items() if ts < cutoff]
        for key in stale:
            del time_map[key]
        return len(stale)

    @staticmethod
    def _evict_idle_deques(deque_map: Dict[object, "deque"], max_age_seconds: float) -> int:
        """
        Drop keys from a {key: deque} map that are empty or whose newest entry is
        older than max_age (the flow/scan went idle).

        Each deque entry is either a bare datetime or a tuple whose first element
        is the datetime (e.g. (timestamp, port)); both forms are supported.
        Returns the number of keys evicted. Caller must hold the detector lock.
        """
        cutoff = clock.now() - timedelta(seconds=max_age_seconds)

        def _newest(dq) -> datetime:
            entry = dq[-1]
            return entry[0] if isinstance(entry, tuple) else entry

        stale = [key for key, dq in deque_map.items() if not dq or _newest(dq) < cutoff]
        for key in stale:
            del deque_map[key]
        return len(stale)

    def _is_whitelisted_ip(self, ip: str) -> bool:
        """Check if an IP is in the user's whitelist."""
        return ip in self.config.whitelist_ips

    def _is_whitelisted_port(self, port: int) -> bool:
        """Check if a port is in the user's whitelist."""
        return port in self.config.whitelist_ports

    def _is_local_ip(self, ip: str) -> bool:
        """Check if IP belongs to the configured local subnets."""
        from ..utils.network import ip_in_any_subnet
        return ip_in_any_subnet(ip, self.config.network.subnets)
