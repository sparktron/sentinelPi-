"""
detectors/geo_country_detector.py - First-connection-to-a-new-country detection.

For each local host we remember the set of countries it has ever connected to
(persisted in the host_countries table). The first time a host reaches a *new*
country we raise an alert. A laptop that has only ever talked to your own
country suddenly connecting to a far-off one is a classic exfil / C2 signal —
and benign causes (a new CDN edge, a VPN) are exactly the kind of context a
user wants surfaced once.

This needs a GeoIP database (maxminddb + GeoLite2). Without it country lookups
return "" and the detector stays silent, so it is only wired up when geo is
enabled. The GeoIP lookups are injected for testability.
"""

from __future__ import annotations

import logging
from typing import Callable, Dict, List, Optional, Set

from .base import BaseDetector
from ..capture.packet_capture import CapturedConnection
from ..models import Alert, AlertCategory, Severity
from ..utils import network
from ..utils.geo import lookup_country, lookup_country_name

logger = logging.getLogger(__name__)


class GeoCountryDetector(BaseDetector):
    """Alerts the first time a local host connects to a previously-unseen country."""

    def __init__(
        self,
        *args,
        geo_lookup: Optional[Callable[[str], str]] = None,
        name_lookup: Optional[Callable[[str], str]] = None,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._geo_lookup = geo_lookup or lookup_country
        self._name_lookup = name_lookup or lookup_country_name
        # src_ip → set of seen country codes; seeded lazily from the DB.
        self._seen: Dict[str, Set[str]] = {}

    def _process_event(self, event: object) -> List[Alert]:
        if not isinstance(event, CapturedConnection):
            return []

        src, dst = event.src_ip, event.dst_ip
        # Only outbound from a local host to a routable external address.
        if not src or not dst:
            return []
        if not self._is_local_ip(src):
            return []
        if network.is_private_ip(dst) or self._is_whitelisted_ip(dst):
            return []

        country = self._geo_lookup(dst)
        if not country:
            return []  # geo unavailable or unknown — nothing to compare

        seen = self._seen.get(src)
        if seen is None:
            seen = self.db.get_host_countries(src)
            self._seen[src] = seen

        if country in seen:
            return []  # already known for this host

        # New country for this host — record (persist) and maybe alert.
        seen.add(country)
        self.db.record_host_country(src, country)

        # Stay quiet during the learning phase: we're still establishing what's
        # normal, so every country looks "new".
        if self.baseline.is_learning:
            return []

        return self._build_alert(src, dst, country)

    def _build_alert(self, src: str, dst: str, country: str) -> List[Alert]:
        country_name = self._name_lookup(dst) or country
        hostname = ""
        device = self.device_tracker.get_device(src)
        if device:
            hostname = device.hostname

        return [Alert(
            severity=Severity.MEDIUM,
            category=AlertCategory.CONNECTION_ANOMALY,
            affected_host=src,
            related_host=dst,
            title=f"New country for {src}{' (' + hostname + ')' if hostname else ''}: {country_name}",
            description=(
                f"{src} connected to {dst}, the first time this host has reached {country_name} "
                f"({country}). Could be a new service/CDN or VPN — or data leaving to an "
                "unexpected place. Worth a glance, especially for a host that normally stays local."
            ),
            recommended_action=(
                f"Check what on {src} is talking to {dst} and whether {country_name} is expected "
                "for this device. Whitelist the destination if it's legitimate."
            ),
            confidence=0.5,
            confidence_rationale=f"First observed connection from {src} to {country}.",
            dedup_key=f"newcountry:{src}:{country}",
            extra={"country": country, "country_name": country_name, "dst_ip": dst},
        )]
