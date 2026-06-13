"""
detectors/host_profile_detector.py - Per-host behavioural profiling.

The sibling of :class:`ActiveHoursDetector`: instead of *when* a host is active,
this learns *what a host normally does* and flags the first off-profile action.
Two dimensions, both keyed to the host's own history (not a global baseline):

- ``dst_port``: the destination ports a local host normally connects to. A
  daytime laptop that has only ever used 80/443/53 suddenly opening 445 (SMB)
  or 22 (SSH) outbound is a strong lateral-movement / compromise tell.
- ``peer``: the *internal* hosts a local host normally talks to. The first time
  a workstation connects to an internal server it has never contacted is the
  slow, deliberate cousin of the burst that :class:`LateralMovementDetector`
  catches.

External peers are deliberately not profiled — their cardinality is unbounded
(CDNs, ad networks) and carries little host-specific signal; destination *ports*
already capture the interesting external behaviour at low cardinality.

Like active-hours, each dimension stays quiet until the host has an established
profile (``host_profile_min_known_*`` distinct values) and during the global
learning phase, so a forming profile doesn't alert on every first-of-its-kind
value. State is persisted per host so the profile survives restarts.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Set, Tuple

from .base import BaseDetector
from ..capture.packet_capture import CapturedConnection
from ..models import Alert, AlertCategory, Severity

logger = logging.getLogger(__name__)

_DIM_PORT = "dst_port"
_DIM_PEER = "peer"


class HostProfileDetector(BaseDetector):
    """Flags a local host acting outside its own learned port / peer profile."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._min_known_ports = self.config.monitoring.host_profile_min_known_ports
        self._min_known_peers = self.config.monitoring.host_profile_min_known_peers
        # (ip, dimension) -> set of values seen; seeded lazily from the DB.
        self._seen: Dict[Tuple[str, str], Set[str]] = {}

    def _process_event(self, event: object) -> List[Alert]:
        if not isinstance(event, CapturedConnection):
            return []
        src = event.src_ip
        if not src or not self._is_local_ip(src):
            return []

        alerts: List[Alert] = []
        # Destination port (against any destination — low cardinality).
        if event.dst_port:
            alerts += self._observe(
                src, _DIM_PORT, str(event.dst_port), self._min_known_ports
            )
        # Internal peer only (bounded by LAN size, high lateral-movement signal).
        if event.dst_ip and self._is_local_ip(event.dst_ip) and event.dst_ip != src:
            alerts += self._observe(
                src, _DIM_PEER, event.dst_ip, self._min_known_peers
            )
        return alerts

    def _observe(self, src: str, dimension: str, value: str, min_known: int) -> List[Alert]:
        """Record one (host, dimension, value); alert if it's off an established profile."""
        cache_key = (src, dimension)
        seen = self._seen.get(cache_key)
        if seen is None:
            seen = self.db.get_host_profile_values(src, dimension)
            self._seen[cache_key] = seen

        if value in seen:
            return []  # already part of this host's profile

        established = len(seen) >= min_known
        seen.add(value)
        self.db.record_host_profile_value(src, dimension, value)

        # Quiet while the profile is still forming or during global learning.
        if not established or self.baseline.is_learning:
            return []

        return self._build_alert(src, dimension, value, len(seen) - 1)

    def _build_alert(self, src: str, dimension: str, value: str, known: int) -> List[Alert]:
        hostname = ""
        device = self.device_tracker.get_device(src)
        if device:
            hostname = device.hostname
        who = f"{src}{' (' + hostname + ')' if hostname else ''}"

        if dimension == _DIM_PORT:
            title = f"Off-profile destination port for {who}: {value}"
            description = (
                f"{src} opened a connection to destination port {value} — a port it has "
                f"never used before (its profile spans {known} other ports). A host suddenly "
                "using an unfamiliar service port (e.g. SMB/445, SSH/22, RDP/3389) can indicate "
                "lateral movement or a compromised process."
            )
            action = (
                f"Confirm what on {src} is connecting on port {value} and whether that service "
                "is expected for this device."
            )
            rationale = f"First connection from {src} to destination port {value}."
        else:  # _DIM_PEER
            peer_name = ""
            peer_device = self.device_tracker.get_device(value)
            if peer_device:
                peer_name = peer_device.hostname
            peer_who = f"{value}{' (' + peer_name + ')' if peer_name else ''}"
            title = f"Off-profile internal peer for {who}: {peer_who}"
            description = (
                f"{src} connected to internal host {peer_who} for the first time (its profile "
                f"spans {known} other internal peers). A device reaching a LAN peer it has never "
                "talked to is a classic slow lateral-movement signal."
            )
            action = (
                f"Confirm whether {src} is expected to talk to {value} (a new service or share "
                "is benign; unexplained internal traffic is not)."
            )
            rationale = f"First internal connection from {src} to peer {value}."

        return [Alert(
            severity=Severity.MEDIUM,
            category=AlertCategory.CONNECTION_ANOMALY,
            affected_host=src,
            related_host=value if dimension == _DIM_PEER else "",
            title=title,
            description=description,
            recommended_action=action,
            confidence=0.5,
            confidence_rationale=rationale,
            dedup_key=f"hostprofile:{dimension}:{src}:{value}",
            extra={"dimension": dimension, "value": value, "known": known},
        )]
