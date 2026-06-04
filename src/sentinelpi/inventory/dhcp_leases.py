"""
inventory/dhcp_leases.py - Authoritative device identity from DHCP leases.

ARP gives us IP↔MAC; reverse DNS often gives nothing. The DHCP server, though,
knows the name each device announced when it joined — the authoritative identity.
This module reads the lease file (dnsmasq or ISC dhcpd) and exposes a MAC→lease
map the DeviceTracker can consult to name devices properly.

Parsing is pure and the source caches the parsed map; a missing/unreadable file
yields an empty map (never raises), so the feature degrades cleanly.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict

from ..utils.network import normalize_mac

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DHCPLease:
    mac: str
    ip: str
    hostname: str


def parse_dnsmasq(text: str) -> Dict[str, DHCPLease]:
    """
    Parse a dnsmasq leases file.

    Each line: ``<expiry> <mac> <ip> <hostname> <client_id>``. A hostname of
    ``*`` means unknown. Keyed by normalized MAC.
    """
    out: Dict[str, DHCPLease] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        _expiry, mac, ip, hostname = parts[0], parts[1], parts[2], parts[3]
        host = "" if hostname == "*" else hostname
        norm = normalize_mac(mac)
        out[norm] = DHCPLease(mac=norm, ip=ip, hostname=host)
    return out


_ISC_LEASE_RE = re.compile(r"lease\s+(?P<ip>\S+)\s*\{(?P<body>.*?)\}", re.DOTALL)
_ISC_MAC_RE = re.compile(r"hardware\s+ethernet\s+([0-9a-fA-F:]+)\s*;")
_ISC_HOST_RE = re.compile(r'client-hostname\s+"([^"]*)"\s*;')


def parse_isc(text: str) -> Dict[str, DHCPLease]:
    """
    Parse an ISC dhcpd.leases file (block form). Later blocks for the same MAC
    win (the file appends, newest last). Keyed by normalized MAC.
    """
    out: Dict[str, DHCPLease] = {}
    for m in _ISC_LEASE_RE.finditer(text):
        ip = m.group("ip")
        body = m.group("body")
        mac_m = _ISC_MAC_RE.search(body)
        if not mac_m:
            continue
        norm = normalize_mac(mac_m.group(1))
        host_m = _ISC_HOST_RE.search(body)
        hostname = host_m.group(1) if host_m else ""
        out[norm] = DHCPLease(mac=norm, ip=ip, hostname=hostname)
    return out


_PARSERS = {"dnsmasq": parse_dnsmasq, "isc": parse_isc}


class DHCPLeaseSource:
    """Reads and caches the DHCP lease map; refresh() re-reads the file."""

    def __init__(self, path: str, fmt: str = "dnsmasq") -> None:
        self._path = Path(path)
        self._parser = _PARSERS.get(fmt, parse_dnsmasq)
        self._leases: Dict[str, DHCPLease] = {}

    def refresh(self) -> int:
        """Re-read the lease file. Returns the number of leases loaded."""
        try:
            text = self._path.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            logger.debug("DHCP lease file not found: %s", self._path)
            self._leases = {}
            return 0
        except OSError as exc:
            logger.warning("Could not read DHCP leases %s: %s", self._path, exc)
            return len(self._leases)  # keep last good map
        self._leases = self._parser(text)
        return len(self._leases)

    def lookup(self, mac: str) -> DHCPLease | None:
        return self._leases.get(normalize_mac(mac))

    def hostname_for(self, mac: str) -> str:
        lease = self.lookup(mac)
        return lease.hostname if lease else ""
