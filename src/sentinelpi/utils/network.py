"""
utils/network.py - Network utility helpers.

Small, dependency-free functions used across modules.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import struct
from typing import Optional

# RFC1918 private address ranges
_PRIVATE_NETWORKS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),   # link-local
    ipaddress.IPv4Network("224.0.0.0/4"),       # multicast
    ipaddress.IPv4Network("255.255.255.255/32"), # broadcast
]

# Well-known OUI prefix → vendor name (partial list for common home devices)
# Extend this or use a full OUI database for production.
_OUI_PREFIXES: dict[str, str] = {
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Foundation",
    "e4:5f:01": "Raspberry Pi Foundation",
    "d8:3a:dd": "Raspberry Pi Foundation",
    "28:cd:c1": "Apple",
    "a4:c3:f0": "Apple",
    "3c:22:fb": "Apple",
    "f0:18:98": "Apple",
    "70:56:81": "Apple",
    "60:f8:1d": "Google",
    "f4:f5:d8": "Google",
    "54:60:09": "Google",
    "00:1a:11": "Google",
    "30:fd:38": "Amazon",
    "f0:81:73": "Amazon",
    "74:c2:46": "Amazon",
    "18:74:2e": "Amazon",
    "cc:f9:54": "Amazon",
    "00:17:f2": "Apple Airport",
    "bc:30:d9": "Netgear",
    "a0:04:60": "Netgear",
    "c0:ff:d4": "TP-Link",
    "50:c7:bf": "TP-Link",
    "b0:be:76": "TP-Link",
    "14:cc:20": "TP-Link",
    "10:fe:ed": "TP-Link",
    "00:0d:0f": "Cisco Linksys",
    "00:25:9c": "Cisco",
    "00:1e:13": "Dell",
    "f8:db:88": "Dell",
    "14:18:77": "Dell",
}


def is_private_ip(ip: str) -> bool:
    """Return True if the IP is RFC1918 / link-local / loopback / multicast."""
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv6Address):
            return addr.is_private or addr.is_loopback or addr.is_link_local
        for net in _PRIVATE_NETWORKS:
            if addr in net:
                return True
        return False
    except ValueError:
        return False


def is_valid_ip(ip: str) -> bool:
    """Return True if the string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def ip_in_subnet(ip: str, subnet: str) -> bool:
    """Return True if `ip` is within `subnet` (CIDR notation)."""
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return False


def ip_in_any_subnet(ip: str, subnets: list[str]) -> bool:
    """Return True if `ip` belongs to any of the given subnets."""
    return any(ip_in_subnet(ip, s) for s in subnets)


def normalize_mac(mac: str) -> str:
    """Normalize a MAC address to lowercase colon-separated format."""
    # Strip separators and re-insert colons
    raw = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(raw) != 12:
        return mac.lower()
    return ":".join(raw[i:i+2] for i in range(0, 12, 2)).lower()


def mac_to_vendor(mac: str) -> str:
    """
    Look up vendor by OUI prefix.

    Returns vendor string or empty string if unknown.
    """
    norm = normalize_mac(mac)
    prefix6 = norm[:8]   # first 3 bytes "xx:xx:xx"
    return _OUI_PREFIXES.get(prefix6, "")


def reverse_dns(ip: str, timeout: float = 1.0) -> str:
    """
    Attempt a reverse DNS lookup with a short timeout.

    Returns hostname or empty string on failure. Uses a subprocess workaround
    since Python's socket.gethostbyaddr doesn't support per-call timeouts.
    """
    import signal

    def _handler(signum, frame):
        raise TimeoutError()

    old_handler = signal.signal(signal.SIGALRM, _handler)
    signal.setitimer(signal.ITIMER_REAL, timeout)
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError, TimeoutError):
        return ""
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)


def domain_entropy(domain: str) -> float:
    """
    Calculate Shannon entropy of the subdomain portion of a domain.

    Higher entropy (> ~3.8) can indicate DGA-generated domain names.
    Only considers the leftmost label (subdomain) for the calculation.
    """
    import math
    # Use just the leftmost label for entropy calculation
    parts = domain.lower().split(".")
    label = parts[0] if parts else domain

    if not label:
        return 0.0

    freq: dict[str, int] = {}
    for c in label:
        freq[c] = freq.get(c, 0) + 1

    entropy = 0.0
    length = len(label)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def count_subdomains(domain: str) -> int:
    """Return number of labels (dots) in a domain name."""
    return domain.count(".")


def is_suspicious_tld(domain: str) -> bool:
    """
    Flag domains using TLDs commonly associated with abuse.

    This is a conservative list — many of these also host legitimate services,
    so it contributes to a score rather than triggering standalone alerts.
    """
    suspicious_tlds = {
        ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
        ".online", ".site", ".info", ".biz", ".pw", ".cc", ".ws",
    }
    lower = domain.lower()
    return any(lower.endswith(tld) for tld in suspicious_tlds)
