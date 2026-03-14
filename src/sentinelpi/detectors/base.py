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
from abc import ABC, abstractmethod
from typing import List, TYPE_CHECKING

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

    Subclasses implement poll() and/or process_event().
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

    def poll(self) -> List["Alert"]:
        """
        Called periodically by the service runner.

        Override in detectors that need to sample system state at an interval.
        Default implementation does nothing.
        """
        return []

    def process_event(self, event: object) -> List["Alert"]:
        """
        Called for each incoming real-time event (e.g., captured packet).

        Override in detectors that need to react to streaming events.
        Default implementation does nothing.
        """
        return []

    @property
    def name(self) -> str:
        return self.__class__.__name__

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
