"""
detectors/arp_detector.py - ARP spoofing and man-in-the-middle detection.

Detects:
1. Gratuitous ARP replies not matching known inventory (classic MITM setup).
2. Conflicting ARP replies: two hosts claiming the same IP.
3. Gateway MAC changes (highest-priority indicator).
4. ARP replies flooding (many unsolicited replies from one MAC).

This detector processes CapturedARP events from the packet capture module
AND periodically cross-checks the ARP table from /proc/net/arp.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

from .base import BaseDetector
from ..capture.packet_capture import CapturedARP
from ..models import Alert, AlertCategory, Severity
from ..utils.network import normalize_mac, mac_to_vendor

logger = logging.getLogger(__name__)


class ARPDetector(BaseDetector):
    """
    Stateful ARP anomaly detector.

    Maintains:
    - ip_to_mac: the last known legitimate MAC for each IP
    - mac_to_ip: the last known legitimate IP for each MAC
    - recent_replies: sliding window of (timestamp, sender_mac, sender_ip) for flood detection
    - conflicting_claims: IPs that have had conflicting MACs claim them
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # Authoritative ARP state (populated from proc/arp and packet capture)
        self._ip_to_mac: Dict[str, str] = {}
        self._mac_to_ip: Dict[str, str] = {}

        # Recent ARP reply tracking for flood detection
        # mac → deque of timestamps
        self._reply_times: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

        # IPs with conflicting MAC claims in the last 5 minutes
        self._conflicts: Dict[str, Set[str]] = defaultdict(set)

        # Known gateway MAC (populated once we see it)
        self._known_gateway_mac: Optional[str] = None

        # Pre-load from device tracker inventory
        self._sync_from_inventory()

    def _sync_from_inventory(self) -> None:
        """Pre-populate ARP state from existing device inventory."""
        for device in self.device_tracker.get_all_devices():
            self._ip_to_mac[device.ip] = device.mac
            self._mac_to_ip[device.mac] = device.ip
            if device.is_gateway:
                self._known_gateway_mac = device.mac

    def process_event(self, event: object) -> List[Alert]:
        """Process a CapturedARP event from packet capture."""
        if not isinstance(event, CapturedARP):
            return []
        return self._analyze_arp(event)

    def poll(self) -> List[Alert]:
        """
        Cross-check /proc/net/arp against our known state.

        This provides coverage even when packet capture is disabled.
        """
        from ..capture.proc_reader import read_arp_table
        alerts: List[Alert] = []
        entries = read_arp_table()
        now = datetime.utcnow()

        for entry in entries:
            mac = normalize_mac(entry.mac)
            synthetic = CapturedARP(
                timestamp=now,
                op=2,           # treat as reply
                src_mac=mac,
                src_ip=entry.ip,
                dst_mac="ff:ff:ff:ff:ff:ff",
                dst_ip="0.0.0.0",
            )
            alerts.extend(self._analyze_arp(synthetic))

        return alerts

    def _analyze_arp(self, arp: CapturedARP) -> List[Alert]:
        alerts: List[Alert] = []

        # Ignore self-announcing (src_ip == dst_ip is gratuitous ARP, which is normal)
        # Ignore incomplete entries
        if not arp.src_ip or not arp.src_mac or arp.src_mac == "00:00:00:00:00:00":
            return []

        # Ignore broadcast/multicast MACs as sources
        if arp.src_mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return []

        if self._is_whitelisted_ip(arp.src_ip):
            return []

        known_mac = self._ip_to_mac.get(arp.src_ip)
        known_ip = self._mac_to_ip.get(arp.src_mac)

        # --- MAC conflict: different MAC claiming to be a known IP ---
        if known_mac and known_mac != arp.src_mac:
            self._conflicts[arp.src_ip].add(arp.src_mac)
            alert = self._conflict_alert(arp, known_mac)
            alerts.append(alert)
            self.device_tracker.mark_device_suspicious(arp.src_ip, score_delta=0.5)

        # --- Gateway MAC change — critical ---
        is_gateway_ip = (arp.src_ip == self.config.network.gateway_ip)
        if is_gateway_ip:
            if self._known_gateway_mac is None:
                self._known_gateway_mac = arp.src_mac
                logger.info("Learned gateway MAC: %s at %s", arp.src_mac, arp.src_ip)
            elif self._known_gateway_mac != arp.src_mac:
                alert = self._gateway_mac_change_alert(arp, self._known_gateway_mac)
                alerts.append(alert)
                self.device_tracker.mark_device_suspicious(arp.src_ip, score_delta=1.0)

        # --- ARP reply flood detection ---
        if arp.op == 2:  # ARP reply
            self._reply_times[arp.src_mac].append(arp.timestamp)
            flood_alert = self._check_reply_flood(arp)
            if flood_alert:
                alerts.append(flood_alert)

        # Update our state
        self._ip_to_mac[arp.src_ip] = arp.src_mac
        self._mac_to_ip[arp.src_mac] = arp.src_ip

        return alerts

    def _conflict_alert(self, arp: CapturedARP, known_mac: str) -> Alert:
        is_gateway = arp.src_ip == self.config.network.gateway_ip
        severity = Severity.CRITICAL if is_gateway else Severity.HIGH
        vendor_new = mac_to_vendor(arp.src_mac)
        vendor_old = mac_to_vendor(known_mac)

        return Alert(
            severity=severity,
            category=AlertCategory.ARP_ANOMALY,
            affected_host=arp.src_ip,
            affected_mac=arp.src_mac,
            title=f"ARP conflict: {arp.src_ip} claimed by new MAC {arp.src_mac}",
            description=(
                f"IP {arp.src_ip} was previously associated with MAC {known_mac} "
                f"[{vendor_old or 'unknown'}]. A new MAC {arp.src_mac} [{vendor_new or 'unknown'}] "
                f"is now claiming this IP. This is a classic indicator of ARP cache poisoning. "
                + ("This is your gateway IP — all traffic may be interceptable." if is_gateway else "")
            ),
            recommended_action=(
                "Compare the MAC addresses of devices on your network against your router's DHCP table. "
                "Look for an unexpected device. If this is your gateway, change your network password "
                "and check for unauthorized access points."
            ),
            confidence=0.9,
            confidence_rationale="Direct observation of conflicting ARP replies for a known IP.",
            dedup_key=f"arp_conflict:{arp.src_ip}:{arp.src_mac}",
            extra={"known_mac": known_mac, "new_mac": arp.src_mac, "is_gateway": is_gateway},
        )

    def _gateway_mac_change_alert(self, arp: CapturedARP, old_mac: str) -> Alert:
        return Alert(
            severity=Severity.CRITICAL,
            category=AlertCategory.ARP_ANOMALY,
            affected_host=arp.src_ip,
            affected_mac=arp.src_mac,
            title=f"CRITICAL: Gateway MAC changed from {old_mac} to {arp.src_mac}",
            description=(
                f"Your gateway ({arp.src_ip}) previously had MAC {old_mac} "
                f"[{mac_to_vendor(old_mac) or 'unknown'}]. "
                f"It is now advertising MAC {arp.src_mac} [{mac_to_vendor(arp.src_mac) or 'unknown'}]. "
                "An attacker may be performing ARP poisoning to intercept all your network traffic."
            ),
            recommended_action=(
                "1. Verify the physical MAC on your actual gateway/router. "
                "2. Check if any new device appeared on your network. "
                "3. Restart your gateway and flush ARP caches on all hosts. "
                "4. Consider using static ARP entries for your gateway."
            ),
            confidence=0.95,
            confidence_rationale="Gateway MAC changed from previously observed stable value.",
            dedup_key=f"gateway_mac_change:{arp.src_ip}",
            extra={"old_mac": old_mac, "new_mac": arp.src_mac},
        )

    def _check_reply_flood(self, arp: CapturedARP) -> Optional[Alert]:
        """Detect ARP reply flooding: >20 replies from one MAC in 10 seconds."""
        recent = self._reply_times[arp.src_mac]
        cutoff = arp.timestamp - timedelta(seconds=10)
        count = sum(1 for t in recent if t > cutoff)

        if count >= 20:
            return Alert(
                severity=Severity.HIGH,
                category=AlertCategory.ARP_ANOMALY,
                affected_host=arp.src_ip,
                affected_mac=arp.src_mac,
                title=f"ARP reply flood from {arp.src_mac}",
                description=(
                    f"MAC {arp.src_mac} sent {count} ARP replies in the last 10 seconds. "
                    "Gratuitous ARP flooding is used by ARP spoofing tools to overwrite ARP caches "
                    "on all devices on the segment."
                ),
                recommended_action=(
                    "Identify the device with MAC address " + arp.src_mac + " and investigate. "
                    "Check for ARP spoofing software (arpspoof, ettercap, bettercap)."
                ),
                confidence=0.85,
                confidence_rationale=f"{count} replies in 10 seconds from single MAC.",
                dedup_key=f"arp_flood:{arp.src_mac}",
                extra={"reply_count_10s": count},
            )
        return None
