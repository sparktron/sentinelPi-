"""
detectors/doh_detector.py - Encrypted-DNS (DoH/DoT) bypass detection.

A client that resolves names over DoH (DNS-over-HTTPS, TCP 443 to a known
resolver) or DoT (DNS-over-TLS, TCP 853) is bypassing the network's own DNS.
That defeats DNS-based monitoring/filtering and is a common malware evasion and
data-exfiltration channel — so it is worth surfacing even when benign (e.g. a
browser with DoH enabled).

Detection is purely pattern-matching on CapturedConnection events, so it needs
no extra dependencies and complements the heuristic DNS detector:

- **DoT**: any connection to TCP port 853 (a dedicated port) → flagged.
- **DoH**: a connection to TCP port 443 whose destination is a *known public
  DoH resolver IP* → flagged. (Port 443 alone is just HTTPS, so we can only
  identify DoH by the well-known resolver address.)

Sanctioned resolvers (your own DoH server, say) are configurable and skipped.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Dict, List, Optional

from .base import BaseDetector
from ..capture.packet_capture import CapturedConnection
from ..models import Alert, AlertCategory, Severity
from ..utils import clock

logger = logging.getLogger(__name__)

# DoT has a dedicated port; DoH rides on HTTPS.
_DOT_PORT = 853
_DOH_PORT = 443

# Persistent behavior — report a given client→resolver pair at most this often.
_COOLDOWN_SECONDS = 6 * 3600

# Known public DoH/DoT resolver IPs → provider name. Not exhaustive (anycast
# providers like NextDNS use many addresses), but covers the common defaults
# that browsers and OSes ship with.
KNOWN_DOH_RESOLVERS: Dict[str, str] = {
    # Cloudflare
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare",
    "1.1.1.2": "Cloudflare", "1.0.0.2": "Cloudflare",
    "1.1.1.3": "Cloudflare", "1.0.0.3": "Cloudflare",
    # Google
    "8.8.8.8": "Google", "8.8.4.4": "Google",
    # Quad9
    "9.9.9.9": "Quad9", "149.112.112.112": "Quad9",
    "9.9.9.10": "Quad9", "9.9.9.11": "Quad9",
    # AdGuard
    "94.140.14.14": "AdGuard", "94.140.15.15": "AdGuard",
    "94.140.14.15": "AdGuard", "94.140.15.16": "AdGuard",
    # OpenDNS
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
    # CleanBrowsing
    "185.228.168.9": "CleanBrowsing", "185.228.169.9": "CleanBrowsing",
    # Mullvad / ControlD
    "194.242.2.2": "Mullvad",
    "76.76.2.0": "ControlD", "76.76.10.0": "ControlD",
}


class DoHDetector(BaseDetector):
    """Flags local clients using DoH/DoT to bypass the configured DNS."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # (src_ip, dst_ip) key → last alert time (bounded via base evictor).
        self._last_alert: Dict[str, datetime] = {}
        self._sanctioned = set(self.config.monitoring.doh_sanctioned_resolvers)

    def _process_event(self, event: object) -> List[Alert]:
        if not isinstance(event, CapturedConnection):
            return []
        if event.protocol != "tcp":
            return []

        src, dst, port = event.src_ip, event.dst_ip, event.dst_port

        # Only outbound from a local client to an external, non-sanctioned host.
        if not src or not dst:
            return []
        if not self._is_local_ip(src) or self._is_local_ip(dst):
            return []
        if self._is_whitelisted_ip(dst) or dst in self._sanctioned:
            return []

        if port == _DOT_PORT:
            provider = KNOWN_DOH_RESOLVERS.get(dst, "an external resolver")
            return self._build_alert(src, dst, "DoT", provider, port)
        if port == _DOH_PORT and dst in KNOWN_DOH_RESOLVERS:
            return self._build_alert(src, dst, "DoH", KNOWN_DOH_RESOLVERS[dst], port)
        return []

    def _build_alert(self, src: str, dst: str, mode: str, provider: str, port: int) -> List[Alert]:
        key = f"{src}->{dst}"
        if self._on_cooldown(key):
            return []
        self._last_alert[key] = clock.now()
        self._prune()

        hostname = ""
        device = self.device_tracker.get_device(src)
        if device:
            hostname = device.hostname

        return [Alert(
            severity=Severity.MEDIUM,
            category=AlertCategory.DNS_ANOMALY,
            affected_host=src,
            related_host=dst,
            title=f"Encrypted DNS bypass ({mode}): {src}{' (' + hostname + ')' if hostname else ''} → {provider}",
            description=(
                f"{src} opened a {mode} connection to {dst}:{port} ({provider}). This resolves "
                "names over encrypted DNS, bypassing the network's configured resolver — which "
                "hides lookups from local monitoring/filtering. Often a browser/OS default, but "
                "also a common malware evasion and exfiltration channel."
            ),
            recommended_action=(
                f"Confirm {src} is expected to use {provider} encrypted DNS. If not, disable DoH/DoT "
                "on the device or block the resolver, and route DNS through your monitored resolver. "
                "Add the IP to doh_sanctioned_resolvers to allow it."
            ),
            confidence=0.6 if mode == "DoH" else 0.75,
            confidence_rationale=(
                f"{mode} to {'a known resolver IP' if mode == 'DoH' else 'the dedicated DoT port 853'}."
            ),
            dedup_key=f"doh:{src}:{dst}",
            extra={"mode": mode, "provider": provider, "resolver_ip": dst, "port": port},
        )]

    def _on_cooldown(self, key: str) -> bool:
        last = self._last_alert.get(key)
        if last is None:
            return False
        return (clock.now() - last).total_seconds() < _COOLDOWN_SECONDS

    def _prune(self) -> None:
        if len(self._last_alert) > 512:
            self._evict_expired_times(self._last_alert, _COOLDOWN_SECONDS)
