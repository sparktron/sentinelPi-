"""
detectors/active_hours_detector.py - Unusual activity-hour detection.

The temporal analogue of new-country detection: learn each local host's normal
*hours of activity*, then flag the first time it acts during an hour it has never
been active before. A laptop that's only ever busy 8am-11pm suddenly opening
connections at 3am is a classic beaconing / compromised-host tell.

To avoid noise while a host's profile is still forming, it only fires once the
host has been seen across ``active_hours_min_known`` distinct hours (and never
during the global learning phase). State is persisted per host so the profile
survives restarts.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Set

from .base import BaseDetector
from ..capture.packet_capture import CapturedConnection
from ..models import Alert, AlertCategory, Severity
from ..utils import clock

logger = logging.getLogger(__name__)


class ActiveHoursDetector(BaseDetector):
    """Flags a local host active during an hour outside its learned profile."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._min_known = self.config.monitoring.active_hours_min_known
        # ip -> set of hours-of-day seen; seeded lazily from the DB.
        self._seen: Dict[str, Set[int]] = {}

    def _process_event(self, event: object) -> List[Alert]:
        if not isinstance(event, CapturedConnection):
            return []
        src = event.src_ip
        if not src or not self._is_local_ip(src):
            return []

        hour = clock.now().hour
        seen = self._seen.get(src)
        if seen is None:
            seen = self.db.get_host_hours(src)
            self._seen[src] = seen

        if hour in seen:
            return []  # already a known-active hour for this host

        # New hour for this host: persist it, then decide whether to alert.
        established = len(seen) >= self._min_known
        seen.add(hour)
        self.db.record_host_hour(src, hour)

        # Quiet while the host's profile is still forming or during global
        # learning — otherwise every first-of-its-kind hour would alert.
        if not established or self.baseline.is_learning:
            return []

        return self._build_alert(src, hour, len(seen) - 1)

    def _build_alert(self, src: str, hour: int, known_hours: int) -> List[Alert]:
        hostname = ""
        device = self.device_tracker.get_device(src)
        if device:
            hostname = device.hostname
        return [Alert(
            severity=Severity.MEDIUM,
            category=AlertCategory.CONNECTION_ANOMALY,
            affected_host=src,
            title=f"Unusual activity hour for {src}{' (' + hostname + ')' if hostname else ''}: {hour:02d}:00",
            description=(
                f"{src} opened a connection around {hour:02d}:00 UTC — an hour it has never been "
                f"active before (its profile spans {known_hours} other hours). Off-profile activity, "
                "especially overnight, can indicate malware beaconing or a compromised host."
            ),
            recommended_action=(
                f"Check what on {src} is active at this hour and whether it's expected "
                "(a scheduled backup/update is benign; unexplained traffic is not)."
            ),
            confidence=0.5,
            confidence_rationale=f"First observed activity from {src} during hour {hour:02d}:00.",
            dedup_key=f"activehour:{src}:{hour}",
            extra={"hour": hour, "known_hours": known_hours},
        )]
