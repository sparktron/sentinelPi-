"""
detectors/asn_detector.py - ASN / hosting-provider reputation.

Looks up the Autonomous System (the network operator) behind each external
destination and flags traffic to ASNs/operators commonly abused for malware,
C2, or anonymization. A hit raises the source host's suspicion (downstream, via
the alert manager) and surfaces a MEDIUM alert with the ASN/org for context.

This is heuristic — a flagged ASN also hosts plenty of legitimate services — so
matches are MEDIUM, not HIGH, and the operator can tune the lists in config.
Needs a GeoLite2-ASN database; without it lookups return (0, "") and the
detector stays silent, so it is only wired up when ASN reputation is enabled.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple

from .base import BaseDetector
from ..capture.packet_capture import CapturedConnection
from ..models import Alert, AlertCategory, Severity
from ..utils import clock, network
from ..utils.asn import lookup_asn

logger = logging.getLogger(__name__)

_COOLDOWN_SECONDS = 3600

# Conservative built-in seed of org-name substrings often associated with abuse.
# The real power is the operator-supplied lists in config; keep this minimal.
_DEFAULT_SUSPICIOUS_KEYWORDS = ["bulletproof"]


class ASNReputationDetector(BaseDetector):
    """Flags connections to suspicious ASNs / hosting providers."""

    def __init__(
        self,
        *args,
        asn_lookup: Optional[Callable[[str], Tuple[int, str]]] = None,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._asn_lookup = asn_lookup or lookup_asn
        mon = self.config.monitoring
        self._suspicious_asns = set(mon.suspicious_asns)
        self._keywords = [
            k.lower() for k in (_DEFAULT_SUSPICIOUS_KEYWORDS + list(mon.suspicious_asn_keywords))
        ]
        # (src_ip, asn) → last alert time (bounded via base evictor).
        self._last_alert: Dict[str, datetime] = {}

    def _process_event(self, event: object) -> List[Alert]:
        if not isinstance(event, CapturedConnection):
            return []
        src, dst = event.src_ip, event.dst_ip
        if not src or not dst:
            return []
        if not self._is_local_ip(src):
            return []
        if network.is_private_ip(dst) or self._is_whitelisted_ip(dst):
            return []

        asn, org = self._asn_lookup(dst)
        if not asn:
            return []

        reason = self._match_reason(asn, org)
        if reason is None:
            return []
        return self._build_alert(src, dst, asn, org, reason)

    def _match_reason(self, asn: int, org: str) -> Optional[str]:
        if asn in self._suspicious_asns:
            return f"AS{asn} is in the configured suspicious-ASN list"
        org_low = (org or "").lower()
        for keyword in self._keywords:
            if keyword and keyword in org_low:
                return f"operator '{org}' matches '{keyword}'"
        return None

    def _build_alert(self, src: str, dst: str, asn: int, org: str, reason: str) -> List[Alert]:
        key = f"{src}:{asn}"
        if self._on_cooldown(key):
            return []
        self._last_alert[key] = clock.now()
        self._prune()

        hostname = ""
        device = self.device_tracker.get_device(src)
        if device:
            hostname = device.hostname
        org_str = org or f"AS{asn}"

        return [Alert(
            severity=Severity.MEDIUM,
            category=AlertCategory.CONNECTION_ANOMALY,
            affected_host=src,
            related_host=dst,
            title=f"Connection to flagged network: {src}{' (' + hostname + ')' if hostname else ''} → {org_str} (AS{asn})",
            description=(
                f"{src} connected to {dst}, hosted by {org_str} (AS{asn}) — {reason}. "
                "Such networks host legitimate services too, but are also commonly used for "
                "malware hosting, C2, and anonymization, so it is worth a look."
            ),
            recommended_action=(
                f"Check what on {src} is talking to {dst} and whether {org_str} is expected. "
                "If legitimate, whitelist the destination or remove the ASN/keyword from config."
            ),
            confidence=0.55,
            confidence_rationale=reason,
            dedup_key=f"asn:{src}:{asn}",
            extra={"asn": asn, "org": org, "dst_ip": dst, "reason": reason},
        )]

    def _on_cooldown(self, key: str) -> bool:
        last = self._last_alert.get(key)
        if last is None:
            return False
        return (clock.now() - last).total_seconds() < _COOLDOWN_SECONDS

    def _prune(self) -> None:
        if len(self._last_alert) > 512:
            self._evict_expired_times(self._last_alert, _COOLDOWN_SECONDS)
