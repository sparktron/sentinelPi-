"""
inventory/device_tracker.py - Device discovery and inventory management.

Tracks known LAN devices, their MAC/IP associations, and detects:
- New previously-unseen devices
- MAC address changes for a known IP (possible MITM / ARP spoofing)
- IP address changes for a known MAC (possible IP hijack)
- ARP table churn (many changes in a short window)
- Gateway MAC changes (high-priority ARP spoofing indicator)

The in-memory device map is the authoritative runtime state;
the database is used for persistence across restarts.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from ..config.manager import Config, get_trusted_ips, get_trusted_macs
from ..models import Alert, AlertCategory, AlertStatus, Device, Severity
from ..capture.proc_reader import ARPEntry, read_arp_table
from ..storage.database import Database
from ..utils.network import mac_to_vendor, normalize_mac, reverse_dns

logger = logging.getLogger(__name__)


class DeviceTracker:
    """
    Maintains a live inventory of LAN devices and emits alerts for anomalies.

    Poll interval: every 30 seconds by default (configurable).
    Thread safety: all public methods are protected by _lock.
    """

    POLL_INTERVAL = 30  # seconds between ARP table reads

    def __init__(self, config: Config, db: Database) -> None:
        self.config = config
        self.db = db
        self._lock = threading.RLock()

        # ip → Device (runtime in-memory cache)
        self._devices_by_ip: Dict[str, Device] = {}
        # mac → ip mapping (most recently seen)
        self._ip_by_mac: Dict[str, str] = {}

        # Track recent MAC changes per IP: ip → deque of (timestamp, mac) tuples
        self._arp_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=20))

        # Track ARP churn: timestamps of any MAC change event
        self._churn_times: deque = deque(maxlen=100)

        # Pending alerts to return to caller
        self._pending_alerts: List[Alert] = []

        # Load existing devices from database
        self._load_from_db()

        # Trusted sets for quick lookup
        self._trusted_ips = get_trusted_ips(config)
        self._trusted_macs = get_trusted_macs(config)

        logger.info(
            "DeviceTracker initialized with %d known devices.", len(self._devices_by_ip)
        )

    def _load_from_db(self) -> None:
        """Restore device inventory from the database on startup."""
        devices = self.db.get_all_devices()
        with self._lock:
            for device in devices:
                self._devices_by_ip[device.ip] = device
                self._ip_by_mac[device.mac] = device.ip
        logger.debug("Loaded %d devices from database.", len(devices))

    def run_forever(self, stop_event: threading.Event) -> None:
        """
        Poll ARP table in a loop until stop_event is set.

        This is the main entry point for the background device tracking thread.
        """
        logger.info("DeviceTracker polling started.")
        while not stop_event.is_set():
            try:
                self.poll()
            except Exception as exc:
                logger.error("DeviceTracker poll error: %s", exc, exc_info=True)
            stop_event.wait(timeout=self.POLL_INTERVAL)
        logger.info("DeviceTracker polling stopped.")

    def poll(self) -> List[Alert]:
        """
        Read ARP table and process all entries.

        Returns list of new Alert objects generated during this poll.
        Alerts are also stored in self._pending_alerts for retrieval.
        """
        entries = read_arp_table()
        alerts: List[Alert] = []

        for entry in entries:
            entry.mac = normalize_mac(entry.mac)
            new_alerts = self._process_arp_entry(entry)
            alerts.extend(new_alerts)

        # Check for excessive ARP churn
        churn_alert = self._check_arp_churn()
        if churn_alert:
            alerts.append(churn_alert)

        with self._lock:
            self._pending_alerts.extend(alerts)

        return alerts

    def _process_arp_entry(self, entry: ARPEntry) -> List[Alert]:
        """Process a single ARP table entry and detect anomalies."""
        alerts: List[Alert] = []
        now = datetime.utcnow()

        with self._lock:
            existing = self._devices_by_ip.get(entry.ip)
            known_ip_for_mac = self._ip_by_mac.get(entry.mac)

            # --- New device detection ---
            if existing is None:
                device = self._create_device(entry, now)
                self._devices_by_ip[entry.ip] = device
                self._ip_by_mac[entry.mac] = entry.ip
                self.db.upsert_device(device)

                if entry.ip not in self._trusted_ips and entry.mac not in self._trusted_macs:
                    alerts.append(self._new_device_alert(device))
                    logger.info("New device: %s (%s)", entry.ip, entry.mac)
                else:
                    logger.debug("Trusted device appeared: %s (%s)", entry.ip, entry.mac)
                return alerts

            # --- Device already known: update last_seen ---
            existing.last_seen = now

            # --- MAC change for known IP ---
            if existing.mac != entry.mac:
                alert = self._mac_change_alert(entry, existing, now)
                alerts.append(alert)
                self._churn_times.append(now)
                self._arp_history[entry.ip].append((now, entry.mac))

                # Update device record with new MAC
                old_mac = existing.mac
                existing.mac = entry.mac
                existing.suspicion_score = min(existing.suspicion_score + 0.3, 10.0)
                existing.alert_count += 1
                # Move ip_by_mac mapping
                self._ip_by_mac.pop(old_mac, None)
                self._ip_by_mac[entry.mac] = entry.ip
                self.db.upsert_device(existing)
                logger.warning("MAC change: %s was %s now %s", entry.ip, old_mac, entry.mac)

            # --- IP change for known MAC ---
            elif known_ip_for_mac and known_ip_for_mac != entry.ip:
                alert = self._ip_change_alert(entry, known_ip_for_mac, existing, now)
                alerts.append(alert)
                self._ip_by_mac[entry.mac] = entry.ip

            else:
                # Normal update
                self.db.upsert_device(existing)

        return alerts

    def _check_arp_churn(self) -> Optional[Alert]:
        """
        Detect rapid ARP MAC changes — a signature of ARP spoofing tools.

        If more than 5 MAC changes occur within 2 minutes, flag it.
        """
        with self._lock:
            now = datetime.utcnow()
            cutoff = now - timedelta(seconds=self.config.thresholds.arp_mac_change_window_seconds)
            recent = [t for t in self._churn_times if t > cutoff]

        if len(recent) >= 5:
            return Alert(
                severity=Severity.HIGH,
                category=AlertCategory.ARP_ANOMALY,
                affected_host="LAN",
                title="Excessive ARP table churn detected",
                description=(
                    f"{len(recent)} MAC address changes observed on the LAN within "
                    f"{self.config.thresholds.arp_mac_change_window_seconds}s. "
                    "This pattern is consistent with an active ARP spoofing/poisoning tool."
                ),
                recommended_action=(
                    "Check all devices on the network. Run 'arp -a' and compare MAC addresses "
                    "to known good values. Look for a device sending rapid ARP replies."
                ),
                confidence=0.75,
                confidence_rationale=f"High churn rate: {len(recent)} events in window",
                dedup_key="arp_churn:lan",
            )
        return None

    def _create_device(self, entry: ARPEntry, now: datetime) -> Device:
        """Create a new Device from an ARP entry, with optional hostname resolution."""
        vendor = mac_to_vendor(entry.mac)
        hostname = ""
        # Reverse DNS — skip if it would be too slow (we're in a poll loop)
        # Attempt with a short timeout only for first-seen devices
        try:
            hostname = reverse_dns(entry.ip, timeout=0.5)
        except Exception:
            pass

        is_trusted = (entry.ip in self._trusted_ips or entry.mac in self._trusted_macs)
        is_gateway = (entry.ip == self.config.network.gateway_ip or
                      entry.mac.lower() == self.config.network.gateway_mac.lower())

        return Device(
            ip=entry.ip,
            mac=entry.mac,
            first_seen=now,
            last_seen=now,
            hostname=hostname,
            vendor=vendor,
            is_trusted=is_trusted,
            is_gateway=is_gateway,
        )

    def _new_device_alert(self, device: Device) -> Alert:
        vendor_str = f" [{device.vendor}]" if device.vendor else ""
        hostname_str = f" ({device.hostname})" if device.hostname else ""
        return Alert(
            severity=Severity.LOW,
            category=AlertCategory.NEW_DEVICE,
            affected_host=device.ip,
            affected_mac=device.mac,
            title=f"New device appeared: {device.ip}{hostname_str}{vendor_str}",
            description=(
                f"A device with IP {device.ip} and MAC {device.mac}{vendor_str} "
                f"was seen for the first time{hostname_str}. "
                "This may be a new authorized device or an unauthorized device joining the network."
            ),
            recommended_action=(
                "Verify this device is one you recognize. If not, check your router's "
                "connected devices list and consider blocking the MAC address."
            ),
            confidence=1.0,
            confidence_rationale="First time this IP/MAC combination has been observed.",
            dedup_key=f"new_device:{device.ip}:{device.mac}",
        )

    def _mac_change_alert(self, entry: ARPEntry, existing: Device, now: datetime) -> Alert:
        is_gateway = existing.is_gateway or entry.ip == self.config.network.gateway_ip
        severity = Severity.CRITICAL if is_gateway else Severity.HIGH

        vendor_new = mac_to_vendor(entry.mac)
        vendor_old = mac_to_vendor(existing.mac)

        return Alert(
            severity=severity,
            category=AlertCategory.ARP_ANOMALY,
            affected_host=entry.ip,
            affected_mac=entry.mac,
            title=f"{'GATEWAY ' if is_gateway else ''}MAC address changed: {entry.ip}",
            description=(
                f"The MAC address for {entry.ip} changed from "
                f"{existing.mac} [{vendor_old or 'unknown vendor'}] to "
                f"{entry.mac} [{vendor_new or 'unknown vendor'}]. "
                "This can indicate ARP cache poisoning / man-in-the-middle attack, "
                "or a legitimate device replacement. "
                + ("WARNING: This is your gateway — traffic may be intercepted." if is_gateway else "")
            ),
            recommended_action=(
                "Immediately verify the MAC address on the physical device. "
                "Run 'arp -a' on multiple hosts to check consistency. "
                "If unexpected, disconnect the suspected device and check for a rogue DHCP server."
            ),
            confidence=0.85,
            confidence_rationale="Direct observation of conflicting MAC for known IP.",
            dedup_key=f"mac_change:{entry.ip}",
            extra={"old_mac": existing.mac, "new_mac": entry.mac, "is_gateway": is_gateway},
        )

    def _ip_change_alert(self, entry: ARPEntry, old_ip: str, existing: Device, now: datetime) -> Alert:
        return Alert(
            severity=Severity.MEDIUM,
            category=AlertCategory.ARP_ANOMALY,
            affected_host=entry.ip,
            affected_mac=entry.mac,
            title=f"Device IP changed: {entry.mac} was {old_ip}, now {entry.ip}",
            description=(
                f"A device with MAC {entry.mac} previously seen at {old_ip} "
                f"is now appearing at {entry.ip}. "
                "This could be DHCP reassignment or IP conflict."
            ),
            recommended_action="Verify DHCP leases on your router. Check for IP address conflicts.",
            confidence=0.7,
            confidence_rationale="Same MAC observed at different IPs within session.",
            dedup_key=f"ip_change:{entry.mac}",
            extra={"old_ip": old_ip, "new_ip": entry.ip},
        )

    # ------------------------------------------------------------------
    # Public read-only accessors
    # ------------------------------------------------------------------

    def get_device(self, ip: str) -> Optional[Device]:
        with self._lock:
            return self._devices_by_ip.get(ip)

    def get_all_devices(self) -> List[Device]:
        with self._lock:
            return list(self._devices_by_ip.values())

    def get_device_count(self) -> int:
        with self._lock:
            return len(self._devices_by_ip)

    def is_known_device(self, ip: str) -> bool:
        with self._lock:
            return ip in self._devices_by_ip

    def mark_device_suspicious(self, ip: str, score_delta: float = 0.2) -> None:
        """Increase suspicion score for a device — called by detectors."""
        with self._lock:
            device = self._devices_by_ip.get(ip)
            if device:
                device.suspicion_score = min(device.suspicion_score + score_delta, 10.0)
                device.alert_count += 1
                self.db.upsert_device(device)

    def get_gateway_mac(self) -> Optional[str]:
        """Return the MAC address of the configured gateway, if known."""
        with self._lock:
            gw_ip = self.config.network.gateway_ip
            device = self._devices_by_ip.get(gw_ip)
            return device.mac if device else None

    def pop_pending_alerts(self) -> List[Alert]:
        """Retrieve and clear pending alerts."""
        with self._lock:
            alerts = list(self._pending_alerts)
            self._pending_alerts.clear()
        return alerts
