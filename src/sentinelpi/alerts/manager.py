"""
alerts/manager.py - Alert deduplication, cooldown, and routing.

The AlertManager is the single funnel through which all detector-generated
alerts pass before reaching storage and notifiers.

Responsibilities:
1. Deduplication: suppress repeat alerts with the same dedup_key within the cooldown window.
2. Cooldown: enforce per-category minimum alert intervals to prevent alert fatigue.
3. Quiet hours: suppress non-critical alerts during configured quiet hours.
4. Severity filtering: allow notifiers to filter by minimum severity.
5. Persistence: save all non-suppressed alerts to the database.
6. Fan-out: route alerts to registered notifiers.
7. Suspicion scoring: update device scores based on alert events.

Thread safety: the process() method is safe to call from multiple threads.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta
from ..utils import clock
from typing import Callable, Dict, List, Optional

from ..models import Alert, AlertCategory, AlertStatus, Severity
from ..storage.database import Database
from ..inventory.device_tracker import DeviceTracker
from ..config.manager import Config
from ..utils.network import is_private_ip, is_valid_ip
from ..utils.geo import lookup_country, lookup_country_name
from ..utils.asn import lookup_asn
from .notifiers import BaseNotifier

logger = logging.getLogger(__name__)

# Per-category default cooldown in seconds (prevents alert storms for the same class of event)
CATEGORY_COOLDOWNS: Dict[AlertCategory, int] = {
    AlertCategory.ARP_ANOMALY:        300,    # 5 min
    AlertCategory.NEW_DEVICE:         3600,   # 1 hour
    AlertCategory.PORT_SCAN:          300,    # 5 min
    AlertCategory.BEACON:             1800,   # 30 min
    AlertCategory.CONNECTION_ANOMALY: 600,    # 10 min
    AlertCategory.DNS_ANOMALY:        600,    # 10 min
    AlertCategory.LATERAL_MOVEMENT:   300,    # 5 min
    AlertCategory.AUTH_ANOMALY:       300,    # 5 min
    AlertCategory.TRAFFIC_SPIKE:      600,    # 10 min
    AlertCategory.PROCESS_ANOMALY:    1800,   # 30 min
    AlertCategory.THREAT_INTEL:       3600,   # 1 hour — same bad dest, don't spam
    AlertCategory.HONEYPOT:           300,    # 5 min per scanning source
    AlertCategory.SYSTEM:             300,
}

# Longest cooldown any category uses — a dedup entry older than this can never
# suppress a future alert, so it is safe to evict.
_MAX_COOLDOWN_SECONDS = max(CATEGORY_COOLDOWNS.values())

# When the in-memory dedup cache grows past this, sweep expired keys. Keeps the
# map bounded on a busy network (per-domain / per-host / per-flow keys would
# otherwise accumulate for the life of the daemon). Mutes store a far-future
# timestamp and are intentionally retained.
_DEDUP_PRUNE_THRESHOLD = 2048


class AlertManager:
    """
    Central alert processing, deduplication, and routing hub.

    Notifiers are registered via add_notifier() and called synchronously
    (use a thread-safe queue in a notifier if async dispatch is needed).
    """

    def __init__(self, config: Config, db: Database, device_tracker: DeviceTracker) -> None:
        self.config = config
        self.db = db
        self.device_tracker = device_tracker
        self._lock = threading.Lock()
        self._notifiers: List[BaseNotifier] = []
        # Optional active-response orchestrator (Phase 2); off unless wired up.
        self._responder_manager = None

        # dedup_key → last alert time (in-memory fast path; backed by DB)
        self._recent_dedup: Dict[str, datetime] = {}
        self._total_processed = 0
        self._total_suppressed = 0
        self._total_fired = 0

    def add_notifier(self, notifier: BaseNotifier) -> None:
        """Register a notifier to receive alerts."""
        with self._lock:
            self._notifiers.append(notifier)
        logger.debug("Registered notifier: %s", notifier.__class__.__name__)

    def set_responder_manager(self, responder_manager) -> None:
        """Wire in an active-response orchestrator (Phase 2). Optional."""
        self._responder_manager = responder_manager

    def process(self, alerts: List[Alert]) -> int:
        """
        Process a list of alerts from a detector.

        Returns the number of alerts that were not suppressed.
        """
        fired = 0
        for alert in alerts:
            if self._handle_alert(alert):
                fired += 1
        return fired

    def process_one(self, alert: Alert) -> bool:
        """Process a single alert. Returns True if it was not suppressed."""
        return self._handle_alert(alert)

    def _handle_alert(self, alert: Alert) -> bool:
        """
        Core alert processing pipeline.

        Returns True if the alert was persisted and dispatched.
        """
        with self._lock:
            self._total_processed += 1

            # 1. Quiet hours suppression (non-critical alerts only)
            if self._is_quiet_hours() and alert.severity not in (Severity.HIGH, Severity.CRITICAL):
                self._total_suppressed += 1
                logger.debug("Quiet hours: suppressed %s", alert.title)
                return False

            # 2. Deduplication check
            if self._is_duplicate(alert):
                self._total_suppressed += 1
                logger.debug("Dedup suppressed: %s", alert.dedup_key)
                return False

            # 3. Record this alert in dedup cache (and bound its growth)
            self._recent_dedup[alert.dedup_key] = alert.timestamp
            self._prune_dedup()

            self._total_fired += 1

        # Outside lock: DB write and notifier calls (may be slow)
        # 3b. Enrich with GeoIP country + ASN for the external IP (centralized
        #     so every detector's alerts get consistent context). No-op when the
        #     geo/asn databases aren't loaded.
        self._enrich_alert(alert)

        # 4. Persist to database
        try:
            self.db.save_alert(alert)
        except Exception as exc:
            logger.error("Failed to save alert to DB: %s", exc)

        # 5. Update device suspicion score
        if alert.affected_host:
            delta = self._suspicion_delta(alert)
            self.device_tracker.mark_device_suspicious(alert.affected_host, delta)

        # 6. Fan out to notifiers
        for notifier in self._notifiers:
            try:
                notifier.send(alert)
            except Exception as exc:
                logger.error("Notifier %s failed: %s", notifier.__class__.__name__, exc)

        # 7. Active response (Phase 2). Inert unless a responder manager is wired
        #    in and explicitly enabled; dry-run by default.
        if self._responder_manager is not None:
            try:
                self._responder_manager.handle(alert)
            except Exception as exc:
                logger.error("Responder manager failed: %s", exc)

        logger.info(
            "[%s] %s — %s (%s)",
            alert.severity.value.upper(),
            alert.category.value,
            alert.title,
            alert.affected_host,
        )
        return True

    def _is_duplicate(self, alert: Alert) -> bool:
        """
        Check if this alert should be suppressed as a duplicate.

        Uses the alert's dedup_key and the category cooldown period.
        Checks in-memory cache first, then the database.
        """
        if not alert.dedup_key:
            return False

        cooldown_seconds = CATEGORY_COOLDOWNS.get(alert.category, 300)
        # Critical alerts have a shorter cooldown (we want to be told repeatedly)
        if alert.severity == Severity.CRITICAL:
            cooldown_seconds = min(cooldown_seconds, 120)

        cutoff = alert.timestamp - timedelta(seconds=cooldown_seconds)

        # Fast path: in-memory cache
        last_seen = self._recent_dedup.get(alert.dedup_key)
        if last_seen and last_seen > cutoff:
            return True

        # Slow path: database (for cross-restart dedup)
        try:
            recent_keys = self.db.get_recent_dedup_keys(cutoff)
            if alert.dedup_key in recent_keys:
                # Populate in-memory cache
                self._recent_dedup[alert.dedup_key] = alert.timestamp
                return True
        except Exception as exc:
            logger.debug("Dedup DB check failed: %s", exc)

        return False

    def _prune_dedup(self) -> None:
        """
        Evict dedup entries older than the longest cooldown so the in-memory
        cache stays bounded. Caller must hold self._lock.

        Only sweeps once the cache exceeds a soft threshold (the sweep is O(n),
        and below the threshold the memory is negligible). Mute entries carry a
        far-future timestamp and are deliberately kept.
        """
        if len(self._recent_dedup) <= _DEDUP_PRUNE_THRESHOLD:
            return
        cutoff = clock.now() - timedelta(seconds=_MAX_COOLDOWN_SECONDS)
        expired = [key for key, ts in self._recent_dedup.items() if ts < cutoff]
        for key in expired:
            del self._recent_dedup[key]
        if expired:
            logger.debug("Pruned %d expired dedup entries", len(expired))

    def _is_quiet_hours(self) -> bool:
        """Check if the current time falls within configured quiet hours."""
        if not self.config.monitoring.quiet_hours_enabled:
            return False
        current_hour = datetime.now().hour
        start = self.config.monitoring.quiet_hours_start
        end = self.config.monitoring.quiet_hours_end

        if start <= end:
            return start <= current_hour < end
        else:
            # Wraps midnight: e.g., 23–7
            return current_hour >= start or current_hour < end

    def _enrich_alert(self, alert: Alert) -> None:
        """
        Attach GeoIP country + ASN context for the external IP in this alert.

        Looks at related_host first (usually the external destination), then
        affected_host, and enriches the first public IP found. Writes a structured
        ``extra["enrichment"]`` and appends a compact human-readable suffix to the
        description. A no-op when neither geo nor ASN data is available, so it is
        safe regardless of which optional databases are installed.
        """
        if alert.extra.get("enrichment"):
            return  # already enriched (idempotent)

        for ip in (alert.related_host, alert.affected_host):
            if not ip or not is_valid_ip(ip) or is_private_ip(ip):
                continue

            country = lookup_country(ip)
            country_name = lookup_country_name(ip)
            asn, org = lookup_asn(ip)
            if not country and not asn:
                continue  # geo/asn databases not loaded for this IP

            enrichment: Dict[str, object] = {"ip": ip}
            bits: List[str] = []
            if country:
                enrichment["country"] = country
                enrichment["country_name"] = country_name or country
                bits.append(country_name or country)
            if asn:
                enrichment["asn"] = asn
                enrichment["asn_org"] = org
                bits.append(f"AS{asn}{' ' + org if org else ''}")

            alert.extra["enrichment"] = enrichment
            if bits:
                alert.description = f"{alert.description} [{', '.join(bits)}]"
            return

    def _suspicion_delta(self, alert: Alert) -> float:
        """Return suspicion score increment based on alert severity."""
        return {
            Severity.INFO: 0.05,
            Severity.LOW: 0.1,
            Severity.MEDIUM: 0.2,
            Severity.HIGH: 0.4,
            Severity.CRITICAL: 0.8,
        }.get(alert.severity, 0.1)

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Mark an alert as acknowledged."""
        try:
            self.db.update_alert_status(alert_id, AlertStatus.ACKNOWLEDGED)
            return True
        except Exception as exc:
            logger.error("Failed to acknowledge alert %s: %s", alert_id, exc)
            return False

    def mute_alert(self, alert_id: str) -> bool:
        """Mute an alert (suppress future dedup matches too)."""
        try:
            self.db.update_alert_status(alert_id, AlertStatus.MUTED)
            alert = self.db.get_alert(alert_id)
            if alert:
                # Add to dedup cache with a long TTL
                with self._lock:
                    self._recent_dedup[alert.dedup_key] = clock.now() + timedelta(days=7)
            return True
        except Exception as exc:
            logger.error("Failed to mute alert %s: %s", alert_id, exc)
            return False

    def get_stats(self) -> dict:
        """Return manager statistics for dashboard."""
        with self._lock:
            return {
                "total_processed": self._total_processed,
                "total_suppressed": self._total_suppressed,
                "total_fired": self._total_fired,
                "suppression_rate": (
                    self._total_suppressed / self._total_processed
                    if self._total_processed > 0 else 0.0
                ),
            }
