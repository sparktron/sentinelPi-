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
from datetime import datetime, timedelta
from typing import Deque, Dict, Iterable, NamedTuple, Optional

from ..models import Alert, AlertCategory, Severity
from ..utils import clock

logger = logging.getLogger(__name__)


class _CorrelationEvent(NamedTuple):
    timestamp: datetime
    sensor: str
    target: str
    category: str
    severity: str
    title: str
    affected_host: str
    related_host: str


class IncidentCorrelator:
    """Sliding-window correlation of alerts by actor across sensors/targets."""

    _SINGLE_HOST_SEQUENCE = (
        AlertCategory.NEW_DEVICE.value,
        AlertCategory.PORT_SCAN.value,
        AlertCategory.LATERAL_MOVEMENT.value,
    )

    def __init__(self, config) -> None:
        self.config = config.correlation
        self._lock = threading.Lock()
        self._events: Dict[str, Deque[_CorrelationEvent]] = defaultdict(
            lambda: deque(maxlen=500)
        )
        # actor -> last incident time (cooldown)
        self._last_incident: Dict[str, datetime] = {}

    def observe(self, alert: Alert) -> Optional[Alert]:
        """
        Record ``alert`` and return an INCIDENT alert if its actor now crosses
        the correlation thresholds, else None. Caller processes the returned
        alert normally (it won't re-correlate — INCIDENT is skipped).
        """
        if alert.category == AlertCategory.INCIDENT:
            return None
        actor = self._actor_for_alert(alert)
        if not actor:
            return None

        sensor = str(alert.extra.get("sensor", "local"))
        target = self._target_for_alert(alert, actor)
        now = clock.now()
        cutoff = now - timedelta(seconds=self.config.window_seconds)

        with self._lock:
            events = self._events[actor]
            events.append(
                _CorrelationEvent(
                    timestamp=now,
                    sensor=sensor,
                    target=target,
                    category=alert.category.value,
                    severity=alert.severity.value,
                    title=alert.title,
                    affected_host=alert.affected_host,
                    related_host=alert.related_host,
                )
            )
            # Prune outside the window.
            while events and events[0].timestamp < cutoff:
                events.popleft()

            sensors = {e.sensor for e in events}
            targets = {e.target for e in events if e.target}

            triggered = (
                len(sensors) >= self.config.min_sensors
                or len(targets) >= self.config.min_targets
            )
            sequence = self._matched_single_host_sequence(events)
            if not triggered and not sequence:
                return None

            if self._is_on_cooldown(actor, now):
                return None
            self._last_incident[actor] = now

            if sequence and not triggered:
                return self._build_sequence_incident(actor, sequence)
            return self._build_incident(actor, list(events))

    def _is_on_cooldown(self, actor: str, now) -> bool:
        last = self._last_incident.get(actor)
        return last is not None and (now - last).total_seconds() < self.config.cooldown_seconds

    def _actor_for_alert(self, alert: Alert) -> str:
        if alert.category in (AlertCategory.PORT_SCAN, AlertCategory.LATERAL_MOVEMENT):
            return alert.related_host or alert.affected_host
        if alert.category == AlertCategory.AUTH_ANOMALY:
            return str(alert.extra.get("src_ip") or alert.related_host or alert.affected_host)
        return alert.affected_host or alert.related_host

    def _target_for_alert(self, alert: Alert, actor: str) -> str:
        if alert.category in (AlertCategory.PORT_SCAN, AlertCategory.LATERAL_MOVEMENT):
            target = alert.affected_host
        else:
            target = alert.related_host
        return target if target and target != actor else ""

    def _matched_single_host_sequence(
        self, events: Iterable[_CorrelationEvent]
    ) -> Optional[list[_CorrelationEvent]]:
        matched: list[_CorrelationEvent] = []
        next_index = 0
        for event in events:
            if event.category == self._SINGLE_HOST_SEQUENCE[next_index]:
                matched.append(event)
                next_index += 1
                if next_index == len(self._SINGLE_HOST_SEQUENCE):
                    return matched
        return None

    @staticmethod
    def _timeline_from_events(events: Iterable[_CorrelationEvent]) -> list[dict]:
        """Render events (time-ordered) into the dashboard's incident-timeline shape."""
        return [
            {
                "timestamp": event.timestamp.isoformat(),
                "category": event.category,
                "severity": event.severity,
                "title": event.title,
                "affected_host": event.affected_host,
                "related_host": event.related_host,
            }
            for event in events
        ]

    @staticmethod
    def _peak_severity(events: Iterable[_CorrelationEvent]) -> str:
        """Highest severity seen among the contributing alerts (escalation high-water mark)."""
        peak = Severity.INFO
        for event in events:
            try:
                sev = Severity(event.severity)
            except ValueError:
                continue
            if peak < sev:
                peak = sev
        return peak.value

    def _build_incident(self, actor, events: list[_CorrelationEvent]) -> Alert:
        sensors = sorted({e.sensor for e in events})
        targets = sorted({e.target for e in events if e.target})
        categories = sorted({e.category for e in events})
        affected_hosts = sorted({e.affected_host for e in events if e.affected_host})
        n_sensors, n_targets = len(sensors), len(targets)
        event_count = len(events)
        first_seen = events[0].timestamp if events else clock.now()
        peak_severity = self._peak_severity(events)
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
                f"{actor} generated {event_count} alerts since {first_seen.isoformat()} "
                f"(within {self.config.window_seconds}s), spanning sensors {sensors} and "
                f"{n_targets} distinct target(s), peaking at {peak_severity.upper()} severity. "
                f"Alert types involved: {categories}. "
                "Correlating these into one incident points to a coordinated action "
                "(e.g. a network-wide scan or lateral movement) rather than isolated noise."
            ),
            recommended_action=(
                f"Treat {actor} as the focus of an active incident: investigate and consider "
                "isolating it. Review the timeline below for scope and the affected hosts."
            ),
            confidence=0.8,
            confidence_rationale=(
                f"{event_count} correlated alerts from {actor} across {n_sensors} sensor(s) "
                f"and {n_targets} target(s) within the window."
            ),
            dedup_key=f"incident:{actor}",
            extra={
                "actor": actor,
                "sensors": sensors,
                "target_count": n_targets,
                "affected_hosts": affected_hosts,
                "event_count": event_count,
                "categories": categories,
                "first_seen": first_seen.isoformat(),
                "peak_severity": peak_severity,
                "timeline": self._timeline_from_events(events),
            },
        )

    def _build_sequence_incident(self, actor: str, sequence: list[_CorrelationEvent]) -> Alert:
        timeline = self._timeline_from_events(sequence)
        logger.warning(
            "Correlated single-host incident: %s — %s.",
            actor,
            " -> ".join(event.category for event in sequence),
        )
        return Alert(
            severity=Severity.HIGH,
            category=AlertCategory.INCIDENT,
            affected_host=actor,
            title=f"Possible intrusion sequence: {actor}",
            description=(
                f"{actor} followed a suspicious sequence within {self.config.window_seconds}s: "
                "new device, reconnaissance, then lateral movement/admin access. "
                "Correlating these events into one incident preserves the raw alerts while making "
                "the likely attack story visible."
            ),
            recommended_action=(
                f"Treat {actor} as a likely compromised or unauthorized host. Review the timeline, "
                "confirm whether the device is expected, and consider isolating it pending investigation."
            ),
            confidence=0.85,
            confidence_rationale=(
                "Observed ordered NEW_DEVICE -> PORT_SCAN -> LATERAL_MOVEMENT alerts "
                f"for {actor} inside the configured correlation window."
            ),
            dedup_key=f"incident:sequence:{actor}",
            extra={
                "actor": actor,
                "sequence": [event.category for event in sequence],
                "timeline": timeline,
                "event_count": len(sequence),
            },
        )
