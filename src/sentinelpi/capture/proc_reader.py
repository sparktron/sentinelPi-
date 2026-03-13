"""
capture/proc_reader.py - Read network state from Linux /proc filesystem.

This module does NOT require root privileges and works on any Linux system.
It parses:
  - /proc/net/arp  — ARP table (IP → MAC mappings)
  - /proc/net/tcp  — TCP connections (IPv4)
  - /proc/net/tcp6 — TCP connections (IPv6)
  - /proc/net/udp  — UDP sockets
  - /proc/net/dev  — Per-interface byte/packet counters

These are polled at configurable intervals rather than capturing raw packets,
making this module lightweight and safe for continuous Pi operation.
"""

from __future__ import annotations

import logging
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# TCP state code → human-readable name
TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


@dataclass
class ARPEntry:
    """A single entry from /proc/net/arp."""
    ip: str
    mac: str
    interface: str
    flags: str


@dataclass
class ProcConnection:
    """A parsed TCP/UDP socket entry from /proc/net/tcp[6]."""
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    protocol: str    # "tcp" | "tcp6" | "udp"
    inode: int
    pid: Optional[int] = None
    process_name: str = ""


@dataclass
class InterfaceStats:
    """Byte and packet counters for a network interface."""
    name: str
    rx_bytes: int = 0
    rx_packets: int = 0
    tx_bytes: int = 0
    tx_packets: int = 0
    rx_errors: int = 0
    tx_errors: int = 0


def read_arp_table() -> List[ARPEntry]:
    """
    Parse /proc/net/arp to get the current ARP table.

    Returns a list of ARPEntry objects. Incomplete entries (no MAC yet assigned,
    shown as 00:00:00:00:00:00) are excluded.
    """
    entries: List[ARPEntry] = []
    arp_path = Path("/proc/net/arp")
    if not arp_path.exists():
        logger.warning("/proc/net/arp not found — ARP monitoring unavailable.")
        return entries

    try:
        with open(arp_path, "r") as fh:
            lines = fh.readlines()
    except OSError as exc:
        logger.error("Failed to read /proc/net/arp: %s", exc)
        return entries

    # Skip header line
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        ip, _hw_type, flags, mac, _mask, iface = parts[:6]
        # Skip incomplete entries
        if mac == "00:00:00:00:00:00":
            continue
        entries.append(ARPEntry(ip=ip, mac=mac.lower(), interface=iface, flags=flags))

    return entries


def read_tcp_connections(include_listen: bool = True) -> List[ProcConnection]:
    """
    Parse /proc/net/tcp and /proc/net/tcp6.

    Args:
        include_listen: If False, LISTEN sockets are excluded (reduces noise).

    Returns a list of ProcConnection objects.
    """
    connections: List[ProcConnection] = []
    inode_to_pid = _build_inode_to_pid_map()

    for proto, path in [("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6")]:
        p = Path(path)
        if not p.exists():
            continue
        try:
            with open(p, "r") as fh:
                lines = fh.readlines()
        except OSError as exc:
            logger.debug("Cannot read %s: %s", path, exc)
            continue

        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 10:
                continue
            try:
                local_addr, local_port = _parse_addr(parts[1], proto == "tcp6")
                remote_addr, remote_port = _parse_addr(parts[2], proto == "tcp6")
                state_code = parts[3].upper()
                state = TCP_STATES.get(state_code, state_code)
                inode = int(parts[9])

                if not include_listen and state == "LISTEN":
                    continue

                pid = inode_to_pid.get(inode)
                pname = _get_process_name(pid) if pid else ""

                connections.append(ProcConnection(
                    local_ip=local_addr,
                    local_port=local_port,
                    remote_ip=remote_addr,
                    remote_port=remote_port,
                    state=state,
                    protocol=proto,
                    inode=inode,
                    pid=pid,
                    process_name=pname,
                ))
            except (ValueError, IndexError) as exc:
                logger.debug("Skipping malformed /proc/net/tcp line: %s (%s)", line.strip(), exc)

    return connections


def read_udp_sockets() -> List[ProcConnection]:
    """Parse /proc/net/udp for active UDP sockets."""
    connections: List[ProcConnection] = []
    inode_to_pid = _build_inode_to_pid_map()

    for path in ["/proc/net/udp", "/proc/net/udp6"]:
        p = Path(path)
        if not p.exists():
            continue
        try:
            with open(p, "r") as fh:
                lines = fh.readlines()
        except OSError:
            continue

        proto = "udp6" if "6" in path else "udp"
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 10:
                continue
            try:
                local_addr, local_port = _parse_addr(parts[1], proto == "udp6")
                remote_addr, remote_port = _parse_addr(parts[2], proto == "udp6")
                inode = int(parts[9])
                pid = inode_to_pid.get(inode)
                pname = _get_process_name(pid) if pid else ""
                connections.append(ProcConnection(
                    local_ip=local_addr,
                    local_port=local_port,
                    remote_ip=remote_addr,
                    remote_port=remote_port,
                    state="",
                    protocol=proto,
                    inode=inode,
                    pid=pid,
                    process_name=pname,
                ))
            except (ValueError, IndexError):
                pass

    return connections


def read_interface_stats() -> Dict[str, InterfaceStats]:
    """
    Parse /proc/net/dev to get per-interface byte/packet counters.

    Returns dict keyed by interface name.
    """
    stats: Dict[str, InterfaceStats] = {}
    path = Path("/proc/net/dev")
    if not path.exists():
        return stats

    try:
        with open(path, "r") as fh:
            lines = fh.readlines()
    except OSError:
        return stats

    # Skip 2-line header
    for line in lines[2:]:
        if ":" not in line:
            continue
        iface_name, data = line.split(":", 1)
        iface_name = iface_name.strip()
        fields = data.split()
        if len(fields) < 16:
            continue
        try:
            stats[iface_name] = InterfaceStats(
                name=iface_name,
                rx_bytes=int(fields[0]),
                rx_packets=int(fields[1]),
                rx_errors=int(fields[2]),
                tx_bytes=int(fields[8]),
                tx_packets=int(fields[9]),
                tx_errors=int(fields[10]),
            )
        except (ValueError, IndexError):
            pass

    return stats


def read_listening_ports() -> List[ProcConnection]:
    """Return only LISTEN sockets — useful for detecting new listening services."""
    all_tcp = read_tcp_connections(include_listen=True)
    return [c for c in all_tcp if c.state == "LISTEN"]


# ------------------------------------------------------------------
# Private helpers
# ------------------------------------------------------------------

def _parse_addr(hex_addr: str, is_ipv6: bool = False) -> Tuple[str, int]:
    """
    Convert a /proc/net/tcp hex address:port to (dotted_ip, port_int).

    IPv4:  0F02000A:0050 → ("10.0.2.15", 80)
    IPv6:  hex is 32 chars → expand and format
    """
    addr_hex, port_hex = hex_addr.split(":")
    port = int(port_hex, 16)

    if is_ipv6:
        # IPv6: 4 groups of 4 bytes each, stored in little-endian groups
        if len(addr_hex) == 32:
            raw = bytes.fromhex(addr_hex)
            # Each 4-byte chunk is little-endian
            parts = []
            for i in range(0, 16, 4):
                chunk = raw[i:i+4][::-1]  # reverse for little-endian
                parts.append(chunk.hex())
            ipv6_str = ":".join(parts[i] + parts[i+1] for i in range(0, 8, 2))
            try:
                ip = socket.inet_ntop(socket.AF_INET6, bytes.fromhex("".join(parts)))
            except Exception:
                ip = ipv6_str
        else:
            ip = "::"
    else:
        # IPv4: 4 bytes little-endian hex → dotted decimal
        raw = bytes.fromhex(addr_hex)
        ip = socket.inet_ntoa(raw[::-1])

    return ip, port


def _build_inode_to_pid_map() -> Dict[int, int]:
    """
    Build a mapping of socket inode → PID by scanning /proc/*/fd/*.

    This requires read access to /proc/<pid>/fd, which may be limited by OS
    permissions. Silently skips entries we can't read.
    """
    inode_map: Dict[int, int] = {}
    proc_path = Path("/proc")
    if not proc_path.exists():
        return inode_map

    try:
        pids = [int(d.name) for d in proc_path.iterdir() if d.name.isdigit()]
    except OSError:
        return inode_map

    for pid in pids:
        fd_dir = proc_path / str(pid) / "fd"
        try:
            for fd_link in fd_dir.iterdir():
                try:
                    target = os.readlink(str(fd_link))
                    if target.startswith("socket:["):
                        inode = int(target[8:-1])
                        inode_map[inode] = pid
                except (OSError, ValueError):
                    pass
        except (OSError, PermissionError):
            pass

    return inode_map


_process_name_cache: Dict[int, str] = {}
_process_name_lock = threading.Lock()


def _get_process_name(pid: int) -> str:
    """Read process name from /proc/<pid>/comm, with a simple cache."""
    with _process_name_lock:
        if pid in _process_name_cache:
            return _process_name_cache[pid]

    try:
        comm = Path(f"/proc/{pid}/comm").read_text().strip()
        with _process_name_lock:
            _process_name_cache[pid] = comm
        return comm
    except (OSError, PermissionError):
        return ""
