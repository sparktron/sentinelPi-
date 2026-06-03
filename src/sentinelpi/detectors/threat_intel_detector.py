"""
detectors/threat_intel_detector.py - Match traffic against threat-intel feeds.

Unlike the heuristic detectors (which infer badness from behavior), this
detector reports *known* badness: a destination IP or queried domain that
appears on a public blocklist. A hit is high-confidence, so alerts are HIGH.

It consumes the same CapturedConnection / CapturedDNS events as the other
real-time detectors and queries a shared ThreatIntelService.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Dict, List

from .base import BaseDetector
from ..capture.packet_capture import CapturedConnection, CapturedDNS
from ..intel.threat_feeds import Indicator, ThreatIntelService
from ..models import Alert, AlertCategory, Severity
from ..utils import clock

logger = logging.getLogger(__name__)

# Same destination should not re-alert within this window.
_COOLDOWN_SECONDS = 3600


class ThreatIntelDetector(BaseDetector):
    """Flags connections/DNS lookups to indicators on loaded blocklists."""

    def __init__(self, config, db, baseline, device_tracker, intel: ThreatIntelService) -> None:
        super().__init__(config, db, baseline, device_tracker)
        self._intel = intel
        # indicator value → last alert time (bounded via base evictor).
        self._last_alert: Dict[str, datetime] = {}

    def _process_event(self, event: object) -> List[Alert]:
        if isinstance(event, CapturedConnection):
            return self._check_connection(event)
        if isinstance(event, CapturedDNS):
            return self._check_dns(event)
        return []

    # ------------------------------------------------------------------ checks
    def _check_connection(self, event: CapturedConnection) -> List[Alert]:
        dst = event.dst_ip
        if not dst or self._is_local_ip(dst) or self._is_whitelisted_ip(dst):
            return []
        indicator = self._intel.match_ip(dst)
        if indicator is None:
            return []
        return self._build_alert(
            host=event.src_ip,
            related=dst,
            indicator=indicator,
            what=f"connection to {dst}:{event.dst_port}",
        )

    def _check_dns(self, event: CapturedDNS) -> List[Alert]:
        alerts: List[Alert] = []
        domain = event.query_name
        if domain and not self._is_whitelisted_ip(domain):
            indicator = self._intel.match_domain(domain)
            if indicator is not None:
                alerts.extend(self._build_alert(
                    host=event.src_ip,
                    related=domain,
                    indicator=indicator,
                    what=f"DNS lookup of {domain}",
                ))
        # A resolved answer pointing at a known-bad IP is also worth flagging.
        if event.response_ip and not self._is_local_ip(event.response_ip):
            indicator = self._intel.match_ip(event.response_ip)
            if indicator is not None:
                alerts.extend(self._build_alert(
                    host=event.src_ip,
                    related=event.response_ip,
                    indicator=indicator,
                    what=f"{domain or 'a domain'} resolving to {event.response_ip}",
                ))
        return alerts

    # ------------------------------------------------------------------ alerts
    def _build_alert(self, host: str, related: str, indicator: Indicator, what: str) -> List[Alert]:
        if self._on_cooldown(indicator.value):
            return []
        self._last_alert[indicator.value] = clock.now()
        self._prune()

        return [Alert(
            severity=Severity.HIGH,
            category=AlertCategory.THREAT_INTEL,
            affected_host=host,
            related_host=related,
            title=f"Known-bad {indicator.kind}: {related}",
            description=(
                f"{host} had a {what}, which matches the '{indicator.source}' threat-intel "
                f"feed (category: {indicator.category}). This is a known-malicious indicator, "
                "not a heuristic guess."
            ),
            recommended_action=(
                f"Treat {host} as potentially compromised: isolate it, inspect its processes "
                f"and recent connections, and block {related} at the firewall/DNS."
            ),
            confidence=0.95,
            confidence_rationale=f"Exact match on the {indicator.source} blocklist.",
            dedup_key=f"threatintel:{indicator.value}",
            extra={
                "indicator": indicator.value,
                "indicator_kind": indicator.kind,
                "source": indicator.source,
                "category": indicator.category,
            },
        )]

    def _on_cooldown(self, value: str) -> bool:
        last = self._last_alert.get(value)
        if last is None:
            return False
        return (clock.now() - last).total_seconds() < _COOLDOWN_SECONDS

    def _prune(self) -> None:
        # Hits are rare so this map stays tiny; only sweep if it grows.
        if len(self._last_alert) > 256:
            self._evict_expired_times(self._last_alert, _COOLDOWN_SECONDS)
