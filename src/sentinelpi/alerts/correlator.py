"""
alerts/correlator.py - Group related alerts into one escalated incident.

A single host sweep that spans VLANs shows up as a flurry of separate alerts —
on different sensors, against different targets. The correlator watches the
alert stream, buckets alerts by their *actor* (the host doing the thing), and
when an actor lights up across enough sensors or hits enough distinct targets
inside a time window, raises one INCIDENT alert that tells the story.

It runs wherever alerts are seen; on a collector (which ingests every sensor's
alerts) it gives true cross-sensor correlation. INCIDENT alerts are ignored by
the correlator itself, so there's no feedback loop.
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict, deque
from datetime import timedelta
from typing import Deque, Dict, Optional, Tuple

from ..models import Alert, AlertCategory, Severity
from ..utils import clock

logger = logging.getLogger(__name__)


class IncidentCorrelator:
    """Sliding-window correlation of alerts by actor across sensors/targets."""

    def __init__(self, config) -> None:
        self.config = config.correlation
        self._lock = threading.Lock()
        # actor -> deque of (timestamp, sensor, target, category_value)
        self._events: Dict[str, Deque[Tuple[object, str, str, str]]] = defaultdict(
            lambda: deque(maxlen=500)
        )
        # actor -> last incident time (cooldown)
        self._last_incident: Dict[str, object] = {}

    def observe(self, alert: Alert) -> Optional[Alert]:
        """
        Record ``alert`` and return an INCIDENT alert if its actor now crosses
        the correlation thresholds, else None. Caller processes the returned
        alert normally (it won't re-correlate — INCIDENT is skipped).
        """
        if alert.category == AlertCategory.INCIDENT:
            return None
        actor = alert.affected_host or alert.related_host
        if not actor:
            return None

        sensor = str(alert.extra.get("sensor", "local"))
        target = alert.related_host if alert.related_host and alert.related_host != actor else ""
        now = clock.now()
        cutoff = now - timedelta(seconds=self.config.window_seconds)

        with self._lock:
            events = self._events[actor]
            events.append((now, sensor, target, alert.category.value))
            # Prune outside the window.
            while events and events[0][0] < cutoff:
                events.popleft()

            sensors = {e[1] for e in events}
            targets = {e[2] for e in events if e[2]}
            categories = {e[3] for e in events}

            triggered = (
                len(sensors) >= self.config.min_sensors
                or len(targets) >= self.config.min_targets
            )
            if not triggered:
                return None

            last = self._last_incident.get(actor)
            if last is not None and (now - last).total_seconds() < self.config.cooldown_seconds:
                return None
            self._last_incident[actor] = now

            return self._build_incident(actor, sensors, targets, categories, len(events))

    def _build_incident(self, actor, sensors, targets, categories, event_count) -> Alert:
        n_sensors, n_targets = len(sensors), len(targets)
        severity = Severity.CRITICAL if (n_sensors >= 3 or n_targets >= 20) else Severity.HIGH
        logger.warning(
            "Correlated incident: %s — %d events, %d sensors, %d targets.",
            actor, event_count, n_sensors, n_targets,
        )
        return Alert(
            severity=severity,
            category=AlertCategory.INCIDENT,
            affected_host=actor,
            title=f"Correlated incident: {actor} active across {n_sensors} sensor(s), {n_targets} target(s)",
            description=(
                f"{actor} generated {event_count} alerts within "
                f"{self.config.window_seconds}s, spanning sensors {sorted(sensors)} and "
                f"{n_targets} distinct target(s). Alert types involved: {sorted(categories)}. "
                "Correlating these into one incident points to a coordinated action "
                "(e.g. a network-wide scan or lateral movement) rather than isolated noise."
            ),
            recommended_action=(
                f"Treat {actor} as the focus of an active incident: investigate and consider "
                "isolating it. Review the contributing alerts for scope."
            ),
            confidence=0.8,
            confidence_rationale=(
                f"{event_count} correlated alerts from {actor} across {n_sensors} sensor(s) "
                f"and {n_targets} target(s) within the window."
            ),
            dedup_key=f"incident:{actor}",
            extra={
                "actor": actor,
                "sensors": sorted(sensors),
                "target_count": n_targets,
                "event_count": event_count,
                "categories": sorted(categories),
            },
        )
