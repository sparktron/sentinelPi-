"""
tests/fixtures/sample_data.py - Simulated network traffic fixtures for testing.

These fixtures represent realistic scenarios:
1. Normal home network traffic
2. Port scan pattern
3. Beaconing malware pattern
4. ARP spoofing attempt
5. SSH brute force
6. New rogue device appearance
7. DNS tunneling pattern

Use these in tests to validate detector behavior without requiring
live network access or elevated privileges.
"""

from __future__ import annotations

import math
import random
from datetime import datetime, timedelta
from typing import List

from sentinelpi.models import Alert, AlertCategory, Device, Severity
from sentinelpi.capture.packet_capture import CapturedARP, CapturedConnection, CapturedDNS


def make_device(
    ip: str,
    mac: str,
    hostname: str = "",
    vendor: str = "",
    is_trusted: bool = False,
    is_gateway: bool = False,
) -> Device:
    now = datetime.utcnow()
    return Device(
        ip=ip,
        mac=mac,
        first_seen=now - timedelta(days=7),
        last_seen=now,
        hostname=hostname,
        vendor=vendor,
        is_trusted=is_trusted,
        is_gateway=is_gateway,
    )


# -----------------------------------------------------------------------
# Normal home network devices
# -----------------------------------------------------------------------

NORMAL_DEVICES = [
    make_device("192.168.1.1",   "aa:bb:cc:00:00:01", "router.local",     "TP-Link",          is_gateway=True),
    make_device("192.168.1.100", "aa:bb:cc:00:00:02", "desktop.local",    "Dell",             is_trusted=True),
    make_device("192.168.1.101", "aa:bb:cc:00:00:03", "laptop.local",     "Apple",            is_trusted=True),
    make_device("192.168.1.102", "aa:bb:cc:00:00:04", "phone.local",      "Apple",            is_trusted=True),
    make_device("192.168.1.103", "dc:a6:32:00:00:05", "sentinelpi.local", "Raspberry Pi",     is_trusted=True),
    make_device("192.168.1.104", "aa:bb:cc:00:00:06", "printer.local",    "HP",               is_trusted=True),
]


def make_normal_arp_entries():
    """Normal ARP table entries for known devices."""
    from sentinelpi.capture.proc_reader import ARPEntry
    return [
        ARPEntry(ip=d.ip, mac=d.mac, interface="eth0", flags="0x2")
        for d in NORMAL_DEVICES
    ]


# -----------------------------------------------------------------------
# Scenario 1: Port scan
# -----------------------------------------------------------------------

def make_port_scan_events(
    scanner_ip: str = "192.168.1.50",
    target_ip: str = "192.168.1.100",
    port_count: int = 100,
    start_time: datetime = None,
) -> List[CapturedConnection]:
    """
    Simulate a fast SYN scan from scanner_ip to target_ip.
    Generates port_count SYN packets within a 30-second window.
    """
    if start_time is None:
        start_time = datetime.utcnow()

    events = []
    for i in range(port_count):
        offset = timedelta(seconds=random.uniform(0, 30))
        events.append(CapturedConnection(
            timestamp=start_time + offset,
            src_ip=scanner_ip,
            src_port=random.randint(40000, 60000),
            dst_ip=target_ip,
            dst_port=i + 1,       # Sequential ports 1-N
            protocol="tcp",
            flags="S",            # SYN only — half-open scan
            size=60,
        ))
    return sorted(events, key=lambda e: e.timestamp)


# -----------------------------------------------------------------------
# Scenario 2: Beaconing malware
# -----------------------------------------------------------------------

def make_beacon_events(
    src_ip: str = "192.168.1.100",
    dst_ip: str = "198.51.100.42",  # TEST-NET-2 (RFC 5737) — safe test IP
    dst_port: int = 443,
    interval_seconds: float = 60.0,
    jitter_fraction: float = 0.05,
    count: int = 20,
    start_time: datetime = None,
) -> List[CapturedConnection]:
    """
    Simulate beaconing malware that connects to dst every `interval_seconds`.
    Small jitter (5%) makes it realistic but still very regular.
    """
    if start_time is None:
        start_time = datetime.utcnow()

    events = []
    current_time = start_time
    for i in range(count):
        events.append(CapturedConnection(
            timestamp=current_time,
            src_ip=src_ip,
            src_port=random.randint(40000, 60000),
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol="tcp",
            flags="SA",
            size=random.randint(100, 300),
        ))
        jitter = interval_seconds * jitter_fraction * random.uniform(-1, 1)
        current_time += timedelta(seconds=interval_seconds + jitter)

    return events


def make_irregular_events(
    src_ip: str = "192.168.1.100",
    dst_ip: str = "93.184.216.34",  # example.com
    dst_port: int = 443,
    count: int = 20,
    start_time: datetime = None,
) -> List[CapturedConnection]:
    """
    Simulate irregular (normal user) traffic that should NOT trigger beacon detection.
    High coefficient of variation — user-driven browsing patterns.
    """
    if start_time is None:
        start_time = datetime.utcnow()

    events = []
    current_time = start_time
    for i in range(count):
        events.append(CapturedConnection(
            timestamp=current_time,
            src_ip=src_ip,
            src_port=random.randint(40000, 60000),
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol="tcp",
            flags="SA",
            size=random.randint(200, 5000),
        ))
        # Very irregular: 1s to 300s between connections
        current_time += timedelta(seconds=random.expovariate(1/60))

    return events


# -----------------------------------------------------------------------
# Scenario 3: ARP spoofing
# -----------------------------------------------------------------------

def make_arp_spoof_events(
    victim_ip: str = "192.168.1.100",
    gateway_ip: str = "192.168.1.1",
    gateway_real_mac: str = "aa:bb:cc:00:00:01",
    attacker_mac: str = "de:ad:be:ef:00:01",
    count: int = 10,
    start_time: datetime = None,
) -> List[CapturedARP]:
    """
    Simulate ARP cache poisoning: attacker sends gratuitous ARPs claiming
    to be the gateway with a different MAC address.
    """
    if start_time is None:
        start_time = datetime.utcnow()

    events = []
    for i in range(count):
        events.append(CapturedARP(
            timestamp=start_time + timedelta(seconds=i * 0.5),
            op=2,                    # ARP reply
            src_mac=attacker_mac,    # Attacker's real MAC
            src_ip=gateway_ip,       # Claiming to be the gateway
            dst_mac="ff:ff:ff:ff:ff:ff",  # Broadcast
            dst_ip="0.0.0.0",
        ))
    return events


def make_normal_arp_events(
    ip: str = "192.168.1.100",
    mac: str = "aa:bb:cc:00:00:02",
    count: int = 5,
    start_time: datetime = None,
) -> List[CapturedARP]:
    """Normal ARP traffic — requests and replies from known device."""
    if start_time is None:
        start_time = datetime.utcnow()

    events = []
    for i in range(count):
        events.append(CapturedARP(
            timestamp=start_time + timedelta(seconds=i * 30),
            op=2,
            src_mac=mac,
            src_ip=ip,
            dst_mac="ff:ff:ff:ff:ff:ff",
            dst_ip="0.0.0.0",
        ))
    return events


# -----------------------------------------------------------------------
# Scenario 4: SSH brute force (auth log lines)
# -----------------------------------------------------------------------

def make_ssh_brute_force_log(
    attacker_ip: str = "203.0.113.99",  # TEST-NET-3 (RFC 5737) — safe test IP
    target_user: str = "admin",
    failure_count: int = 50,
    start_time: datetime = None,
) -> List[str]:
    """Generate realistic auth log lines for an SSH brute force attack."""
    if start_time is None:
        start_time = datetime.utcnow()

    lines = []
    users = [target_user, "root", "ubuntu", "pi", "admin", "user", "test"]
    for i in range(failure_count):
        ts = (start_time + timedelta(seconds=i * 2)).strftime("%b %d %H:%M:%S")
        user = random.choice(users)
        lines.append(
            f"{ts} sentinelpi sshd[1234]: Failed password for {user} "
            f"from {attacker_ip} port {random.randint(40000, 60000)} ssh2"
        )
    return lines


def make_ssh_success_log(
    src_ip: str = "192.168.1.50",
    user: str = "pi",
    start_time: datetime = None,
) -> List[str]:
    """Generate auth log line for a successful SSH login."""
    if start_time is None:
        start_time = datetime.utcnow()
    ts = start_time.strftime("%b %d %H:%M:%S")
    return [
        f"{ts} sentinelpi sshd[1234]: Accepted publickey for {user} "
        f"from {src_ip} port {random.randint(40000, 60000)} ssh2"
    ]


# -----------------------------------------------------------------------
# Scenario 5: DNS tunneling / DGA
# -----------------------------------------------------------------------

def make_dga_dns_events(
    src_ip: str = "192.168.1.100",
    count: int = 30,
    start_time: datetime = None,
) -> List[CapturedDNS]:
    """Simulate DGA domain generation — high entropy, NXDOMAIN responses."""
    if start_time is None:
        start_time = datetime.utcnow()

    import string
    import hashlib

    events = []
    for i in range(count):
        # Generate a pseudo-random high-entropy domain name
        seed = f"dga_seed_{i}_test"
        h = hashlib.md5(seed.encode()).hexdigest()[:12]
        domain = f"{h}.example-malware.xyz"

        events.append(CapturedDNS(
            timestamp=start_time + timedelta(seconds=i * 2),
            src_ip=src_ip,
            dst_ip="8.8.8.8",
            query_name=domain,
            query_type="A",
            is_response=True,
            is_nxdomain=True,     # Most DGA domains don't resolve
        ))
    return events


def make_dns_tunnel_event(
    src_ip: str = "192.168.1.100",
    timestamp: datetime = None,
) -> CapturedDNS:
    """Simulate a DNS tunneling query with a very long subdomain label."""
    if timestamp is None:
        timestamp = datetime.utcnow()

    # Long base32-encoded subdomain (iodine-style)
    long_subdomain = "JBSWY3DPEBLW64TMMQQQ4YTSMN2XAZLOOQ5C2YLNF3HSVKMMFZCA3DPNRUW4ZZPNUQHK3TPOQQGK3TF"
    return CapturedDNS(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip="8.8.8.8",
        query_name=f"{long_subdomain}.tunnel.example.com",
        query_type="TXT",
        is_response=False,
    )


# -----------------------------------------------------------------------
# Scenario 6: New rogue device
# -----------------------------------------------------------------------

def make_rogue_device_arp(
    timestamp: datetime = None,
) -> CapturedARP:
    """Simulate an unknown device appearing on the network."""
    if timestamp is None:
        timestamp = datetime.utcnow()
    return CapturedARP(
        timestamp=timestamp,
        op=1,                              # ARP request
        src_mac="de:ad:be:ef:ca:fe",       # Unknown MAC
        src_ip="192.168.1.200",            # Unknown IP
        dst_mac="ff:ff:ff:ff:ff:ff",
        dst_ip="192.168.1.1",
    )
