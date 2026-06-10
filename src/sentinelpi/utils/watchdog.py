"""
utils/watchdog.py - SentinelPi self-monitoring checks.

The watchdog turns SentinelPi's own degradation into normal SYSTEM alerts so an
operator can tell when the monitor itself needs attention.
"""

from __future__ import annotations

import logging
import queue
import shutil
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Sequence

from ..config.manager import Config
from ..models import Alert, AlertCategory, Severity
from . import clock

logger = logging.getLogger(__name__)


class OperationalWatchdog:
    """Checks core runtime health and emits SYSTEM alerts for degradation."""

    def __init__(
        self,
        config: Config,
        capture_queue: "queue.Queue",
        threads: Sequence[threading.Thread],
    ) -> None:
        self.config = config
        self.capture_queue = capture_queue
        self.threads = threads
        self._started_at = clock.now()
        self._event_sources_active = False
        self._event_sources_active_since: datetime | None = None
        self._last_event_at: datetime | None = None
        self._last_threat_intel_success_at: datetime | None = None
        self._last_threat_intel_error_at: datetime | None = None
        self._last_threat_intel_error = ""
        self._last_status = self.snapshot()

    def set_event_sources_active(self, active: bool) -> None:
        """Record whether packet/flow event sources are expected to feed the router."""
        if active and not self._event_sources_active:
            self._event_sources_active_since = clock.now()
        if not active:
            self._event_sources_active_since = None
            self._last_event_at = None
        self._event_sources_active = active

    def record_event(self, when: datetime | None = None) -> None:
        """Mark that the event router received a packet/flow event."""
        self._last_event_at = when or clock.now()

    def record_threat_intel_refresh(
        self, *, success: bool, error: str = "", when: datetime | None = None
    ) -> None:
        """Mark the outcome of a threat-intel refresh attempt."""
        ts = when or clock.now()
        if success:
            self._last_threat_intel_success_at = ts
            self._last_threat_intel_error_at = None
            self._last_threat_intel_error = ""
        else:
            self._last_threat_intel_error_at = ts
            self._last_threat_intel_error = error

    def check(self) -> List[Alert]:
        """Run health checks and return any SYSTEM alerts."""
        status = self.snapshot()
        self._last_status = status

        alerts: List[Alert] = []
        alerts.extend(self._thread_alerts(status))
        queue_alert = self._queue_alert(status)
        if queue_alert:
            alerts.append(queue_alert)
        disk_alert = self._disk_alert(status)
        if disk_alert:
            alerts.append(disk_alert)
        capture_alert = self._capture_stale_alert(status)
        if capture_alert:
            alerts.append(capture_alert)
        threat_alert = self._threat_intel_alert(status)
        if threat_alert:
            alerts.append(threat_alert)
        return alerts

    def get_status(self) -> dict:
        """Return the latest health snapshot for APIs/dashboard."""
        return dict(self._last_status)

    def snapshot(self) -> dict:
        dead_threads = sorted(t.name for t in self.threads if not t.is_alive())
        queue_size = self.capture_queue.qsize()
        queue_max = self.capture_queue.maxsize or 0
        queue_ratio = (queue_size / queue_max) if queue_max else 0.0
        disk = self._disk_status()
        capture = self._capture_status()
        threat_intel = self._threat_intel_status()

        return {
            "enabled": self.config.monitoring.self_monitoring_enabled,
            "healthy": not dead_threads
            and queue_ratio < self.config.monitoring.self_monitoring_queue_warn_ratio
            and disk["free_mb"] >= self.config.monitoring.self_monitoring_disk_free_min_mb
            and not capture["stale"]
            and not threat_intel["stale"]
            and not threat_intel["last_error"],
            "dead_threads": dead_threads,
            "capture_queue": {
                "size": queue_size,
                "max_size": queue_max,
                "usage_ratio": round(queue_ratio, 4),
                "warn_ratio": self.config.monitoring.self_monitoring_queue_warn_ratio,
            },
            "disk": disk,
            "capture": capture,
            "threat_intel": threat_intel,
        }

    def _capture_status(self) -> dict:
        now = clock.now()
        stale_after = self.config.monitoring.self_monitoring_capture_stale_seconds
        reference = self._last_event_at or self._event_sources_active_since
        age = (now - reference).total_seconds() if reference else None
        stale = bool(self._event_sources_active and age is not None and age >= stale_after)
        return {
            "event_sources_active": self._event_sources_active,
            "last_event_at": self._last_event_at.isoformat() if self._last_event_at else None,
            "seconds_since_last_event": round(age, 1) if age is not None else None,
            "stale_after_seconds": stale_after,
            "stale": stale,
        }

    def _threat_intel_status(self) -> dict:
        if not self.config.threat_intel.enabled:
            return {
                "enabled": False,
                "last_success_at": None,
                "seconds_since_success": None,
                "stale_after_seconds": None,
                "stale": False,
                "last_error": "",
                "last_error_at": None,
            }

        now = clock.now()
        interval = max(1, self.config.threat_intel.refresh_interval_hours) * 3600
        stale_after = interval * self.config.monitoring.self_monitoring_threat_intel_stale_multiplier
        reference = self._last_threat_intel_success_at or self._started_at
        age = (now - reference).total_seconds()
        return {
            "enabled": True,
            "last_success_at": (
                self._last_threat_intel_success_at.isoformat()
                if self._last_threat_intel_success_at else None
            ),
            "seconds_since_success": round(age, 1),
            "stale_after_seconds": round(stale_after, 1),
            "stale": age >= stale_after,
            "last_error": self._last_threat_intel_error,
            "last_error_at": (
                self._last_threat_intel_error_at.isoformat()
                if self._last_threat_intel_error_at else None
            ),
        }

    def _disk_status(self) -> dict:
        path = Path(self.config.storage.db_path).expanduser()
        target = path.parent if path.suffix else path
        try:
            target.mkdir(parents=True, exist_ok=True)
            usage = shutil.disk_usage(target)
        except OSError as exc:
            logger.debug("Watchdog disk check failed for %s: %s", target, exc)
            return {
                "path": str(target),
                "free_mb": 0,
                "total_mb": 0,
                "used_percent": 100.0,
                "error": str(exc),
            }

        total_mb = usage.total / (1024 * 1024)
        free_mb = usage.free / (1024 * 1024)
        used_percent = ((usage.total - usage.free) / usage.total * 100.0) if usage.total else 100.0
        return {
            "path": str(target),
            "free_mb": round(free_mb, 1),
            "total_mb": round(total_mb, 1),
            "used_percent": round(used_percent, 1),
            "min_free_mb": self.config.monitoring.self_monitoring_disk_free_min_mb,
        }

    def _thread_alerts(self, status: dict) -> List[Alert]:
        alerts = []
        for name in status["dead_threads"]:
            alerts.append(Alert(
                severity=Severity.HIGH,
                category=AlertCategory.SYSTEM,
                affected_host="localhost",
                title=f"SentinelPi worker thread stopped: {name}",
                description=(
                    f"The managed worker thread '{name}' is no longer alive. SentinelPi may be "
                    "missing capture, detector, forwarding, or dashboard work until restarted."
                ),
                recommended_action="Check logs for the thread failure and restart the service if needed.",
                confidence=1.0,
                dedup_key=f"watchdog:thread:{name}",
                extra={"watchdog": {"kind": "dead_thread", "thread": name}},
            ))
        return alerts

    def _queue_alert(self, status: dict) -> Alert | None:
        q = status["capture_queue"]
        if not q["max_size"] or q["usage_ratio"] < q["warn_ratio"]:
            return None
        return Alert(
            severity=Severity.MEDIUM,
            category=AlertCategory.SYSTEM,
            affected_host="localhost",
            title=f"SentinelPi capture queue high water mark: {q['size']}/{q['max_size']}",
            description=(
                f"The capture queue is {q['usage_ratio']:.0%} full. If it reaches capacity, "
                "packet or flow events will be dropped before detectors can process them."
            ),
            recommended_action=(
                "Reduce capture volume, disable noisy sources, or investigate slow detector/notifier work."
            ),
            confidence=0.9,
            dedup_key="watchdog:capture_queue_high",
            extra={"watchdog": {"kind": "capture_queue", **q}},
        )

    def _disk_alert(self, status: dict) -> Alert | None:
        disk = status["disk"]
        if disk["free_mb"] >= disk["min_free_mb"] and "error" not in disk:
            return None
        if "error" in disk:
            title = "SentinelPi disk health check failed"
            description = f"Could not inspect storage path {disk['path']}: {disk['error']}."
        else:
            title = f"SentinelPi low disk space: {disk['free_mb']} MB free"
            description = (
                f"Storage path {disk['path']} has {disk['free_mb']} MB free "
                f"({disk['used_percent']}% used), below the configured minimum of "
                f"{disk['min_free_mb']} MB."
            )
        return Alert(
            severity=Severity.HIGH,
            category=AlertCategory.SYSTEM,
            affected_host="localhost",
            title=title,
            description=description,
            recommended_action="Free disk space or move SentinelPi storage to a larger volume.",
            confidence=1.0,
            dedup_key="watchdog:disk_low",
            extra={"watchdog": {"kind": "disk", **disk}},
        )

    def _capture_stale_alert(self, status: dict) -> Alert | None:
        capture = status["capture"]
        if not capture["stale"]:
            return None
        return Alert(
            severity=Severity.HIGH,
            category=AlertCategory.SYSTEM,
            affected_host="localhost",
            title="SentinelPi capture event stream is stale",
            description=(
                "Packet or flow event sources are active, but the event router has not received "
                f"an event for {capture['seconds_since_last_event']} seconds "
                f"(threshold: {capture['stale_after_seconds']} seconds)."
            ),
            recommended_action=(
                "Check packet capture permissions, flow source health, interface configuration, "
                "and event-router logs."
            ),
            confidence=0.9,
            dedup_key="watchdog:capture_stale",
            extra={"watchdog": {"kind": "capture_stale", **capture}},
        )

    def _threat_intel_alert(self, status: dict) -> Alert | None:
        ti = status["threat_intel"]
        if not ti["enabled"]:
            return None
        if ti["last_error"]:
            return Alert(
                severity=Severity.MEDIUM,
                category=AlertCategory.SYSTEM,
                affected_host="localhost",
                title="SentinelPi threat-intel refresh failed",
                description=f"The most recent threat-intel refresh failed: {ti['last_error']}",
                recommended_action="Check network connectivity and threat-intel feed availability.",
                confidence=0.9,
                dedup_key="watchdog:threat_intel_refresh_failed",
                extra={"watchdog": {"kind": "threat_intel_error", **ti}},
            )
        if not ti["stale"]:
            return None
        return Alert(
            severity=Severity.MEDIUM,
            category=AlertCategory.SYSTEM,
            affected_host="localhost",
            title="SentinelPi threat-intel feeds are stale",
            description=(
                f"Threat-intel feeds have not refreshed successfully for "
                f"{ti['seconds_since_success']} seconds (threshold: {ti['stale_after_seconds']} seconds)."
            ),
            recommended_action="Check the threat-intel refresh thread and feed cache logs.",
            confidence=0.9,
            dedup_key="watchdog:threat_intel_stale",
            extra={"watchdog": {"kind": "threat_intel_stale", **ti}},
        )
