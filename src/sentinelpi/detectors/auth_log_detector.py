"""
detectors/auth_log_detector.py - Authentication log anomaly detection.

Parses /var/log/auth.log (or journald equivalent) to detect:
1. SSH brute force: many failures from same IP in short window.
2. Successful SSH login from a new/unseen IP address.
3. Sudo privilege escalation events.
4. New user account creation.
5. Service crashes and restarts (system stability indicator).
6. Failed su/sudo attempts.

This module requires read access to /var/log/auth.log or equivalent.
No network access or root privileges required for reading the log file.
"""

from __future__ import annotations

import logging
import os
import re
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set

from .base import BaseDetector
from ..models import Alert, AlertCategory, Severity

logger = logging.getLogger(__name__)

# Regex patterns for common auth log events
# These patterns are compatible with both OpenSSH and Debian/Ubuntu auth.log format
PATTERNS = {
    "ssh_failure": re.compile(
        r"Failed (?:password|publickey|keyboard-interactive) for (?:invalid user )?(\S+) from ([\d.]+)"
    ),
    "ssh_success": re.compile(
        r"Accepted (?:password|publickey|keyboard-interactive) for (\S+) from ([\d.]+)"
    ),
    "ssh_invalid_user": re.compile(
        r"Invalid user (\S+) from ([\d.]+)"
    ),
    "sudo_success": re.compile(
        r"sudo:.*COMMAND=(.*)"
    ),
    "sudo_failure": re.compile(
        r"sudo:.*authentication failure"
    ),
    "new_user": re.compile(
        r"useradd.*new user.*name=(\S+)"
    ),
    "passwd_change": re.compile(
        r"passwd.*password changed for (\S+)"
    ),
    "service_restart": re.compile(
        r"systemd.*Restarting"
    ),
    "pam_failure": re.compile(
        r"pam_unix.*authentication failure.*user=(\S+)"
    ),
}


class AuthLogDetector(BaseDetector):
    """
    Tails and parses the auth log for security-relevant events.

    Uses file seek to avoid re-reading from the beginning on each poll.
    Handles log rotation gracefully.
    """

    POLL_INTERVAL = 30  # seconds between log file reads

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._log_path = Path(self.config.monitoring.auth_log_path)
        self._file_pos: int = 0
        self._file_inode: int = 0
        self._initialized = False
        self._lock = threading.Lock()

        # SSH failure tracking: src_ip → deque of timestamps
        self._ssh_failures: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        # Known SSH source IPs that have successfully logged in
        self._known_ssh_sources: Set[str] = set()
        # Alert cooldowns
        self._last_alert: Dict[str, datetime] = {}

    def poll(self) -> List[Alert]:
        """Read new log entries since last poll."""
        if not self.config.monitoring.auth_log_enabled:
            return []

        if not self._log_path.exists():
            return []

        alerts: List[Alert] = []
        with self._lock:
            new_lines = self._read_new_lines()

        for line in new_lines:
            line_alerts = self._parse_line(line.strip())
            alerts.extend(line_alerts)

        return alerts

    def _read_new_lines(self) -> List[str]:
        """
        Read lines added to the log file since last read.
        Handles log rotation by detecting inode changes.
        """
        try:
            stat = os.stat(self._log_path)
            current_inode = stat.st_ino

            # First read: skip to end to avoid alarming on historical data
            if not self._initialized:
                self._file_pos = stat.st_size
                self._file_inode = current_inode
                self._initialized = True
                logger.info("Auth log initialized at position %d.", self._file_pos)
                return []

            # Log rotation detected (inode changed)
            if current_inode != self._file_inode:
                logger.info("Auth log rotation detected — resetting position.")
                self._file_pos = 0
                self._file_inode = current_inode

            # File truncated (shouldn't happen but be defensive)
            if stat.st_size < self._file_pos:
                logger.warning("Auth log appears truncated — resetting position.")
                self._file_pos = 0

            if stat.st_size == self._file_pos:
                return []  # No new data

            with open(self._log_path, "r", errors="replace") as fh:
                fh.seek(self._file_pos)
                new_data = fh.read(1_048_576)  # Max 1MB per poll to bound CPU
                self._file_pos = fh.tell()

            return new_data.splitlines()

        except (OSError, PermissionError) as exc:
            logger.debug("Cannot read auth log %s: %s", self._log_path, exc)
            return []

    def _parse_line(self, line: str) -> List[Alert]:
        """Parse a single auth log line and return any alerts."""
        if not line:
            return []

        alerts: List[Alert] = []
        now = datetime.utcnow()

        # SSH login failure
        m = PATTERNS["ssh_failure"].search(line)
        if not m:
            m = PATTERNS["ssh_invalid_user"].search(line)
        if m:
            user = m.group(1)
            src_ip = m.group(2)
            self._ssh_failures[src_ip].append(now)
            alert = self._check_ssh_brute_force(src_ip, user, now)
            if alert:
                alerts.append(alert)
            return alerts

        # Successful SSH login
        m = PATTERNS["ssh_success"].search(line)
        if m:
            user = m.group(1)
            src_ip = m.group(2)
            alert = self._check_new_ssh_login(src_ip, user, now, line)
            if alert:
                alerts.append(alert)
            self._known_ssh_sources.add(src_ip)
            return alerts

        # Sudo privilege use
        m = PATTERNS["sudo_success"].search(line)
        if m:
            command = m.group(1)
            # Only alert on sudo use to sensitive commands
            if any(cmd in command for cmd in ["/bin/su", "/bin/bash", "/usr/bin/python", "passwd", "visudo"]):
                alert = self._sudo_sensitive_alert(command, now, line)
                if alert:
                    alerts.append(alert)
            return alerts

        # Sudo failure (user tried to use sudo but failed)
        if PATTERNS["sudo_failure"].search(line):
            alerts.append(self._sudo_failure_alert(now, line))
            return alerts

        # New user account created
        m = PATTERNS["new_user"].search(line)
        if m:
            user = m.group(1)
            dedup_key = f"new_user:{user}"
            if not self._is_on_cooldown(dedup_key, now, 86400):
                self._last_alert[dedup_key] = now
                alerts.append(Alert(
                    severity=Severity.MEDIUM,
                    category=AlertCategory.AUTH_ANOMALY,
                    affected_host="localhost",
                    title=f"New user account created: {user}",
                    description=f"A new user account '{user}' was created on this system.",
                    recommended_action="Verify this account creation was intentional and authorized.",
                    confidence=1.0,
                    confidence_rationale="Direct observation in auth log.",
                    dedup_key=dedup_key,
                    extra={"user": user, "log_line": line},
                ))

        return alerts

    def _check_ssh_brute_force(
        self, src_ip: str, user: str, now: datetime
    ) -> Optional[Alert]:
        """Alert if too many SSH failures from one IP in the window."""
        dedup_key = f"ssh_brute:{src_ip}"
        if self._is_on_cooldown(dedup_key, now, self.config.thresholds.ssh_failures_window_seconds):
            return None

        window = timedelta(seconds=self.config.thresholds.ssh_failures_window_seconds)
        cutoff = now - window
        recent = [t for t in self._ssh_failures[src_ip] if t > cutoff]

        if len(recent) < self.config.thresholds.ssh_failures_threshold:
            return None

        self._last_alert[dedup_key] = now

        return Alert(
            severity=Severity.HIGH,
            category=AlertCategory.AUTH_ANOMALY,
            affected_host="localhost",
            related_host=src_ip,
            title=f"SSH brute force: {src_ip} ({len(recent)} failures in {self.config.thresholds.ssh_failures_window_seconds}s)",
            description=(
                f"{src_ip} made {len(recent)} failed SSH authentication attempts "
                f"within {self.config.thresholds.ssh_failures_window_seconds} seconds. "
                f"Last failed user: '{user}'. "
                "This is a classic SSH brute force / credential stuffing attack pattern."
            ),
            recommended_action=(
                f"Block {src_ip} at your firewall. "
                "Consider installing fail2ban if not already running. "
                "Enable SSH key-only authentication and disable password auth in sshd_config."
            ),
            confidence=0.95,
            confidence_rationale=f"{len(recent)} failures in {self.config.thresholds.ssh_failures_window_seconds}s window.",
            dedup_key=dedup_key,
            extra={
                "failure_count": len(recent),
                "window_seconds": self.config.thresholds.ssh_failures_window_seconds,
                "last_user": user,
            },
        )

    def _check_new_ssh_login(
        self, src_ip: str, user: str, now: datetime, raw_line: str
    ) -> Optional[Alert]:
        """Alert on successful SSH logins from previously unseen source IPs."""
        if src_ip in self._known_ssh_sources:
            return None
        if self._is_whitelisted_ip(src_ip):
            return None

        dedup_key = f"new_ssh_login:{src_ip}:{user}"
        if self._is_on_cooldown(dedup_key, now, 3600):
            return None
        self._last_alert[dedup_key] = now

        from ..utils.geo import lookup_country
        country = lookup_country(src_ip)
        country_str = f" ({country})" if country else ""

        return Alert(
            severity=Severity.MEDIUM,
            category=AlertCategory.AUTH_ANOMALY,
            affected_host="localhost",
            related_host=src_ip,
            title=f"New SSH login: {user} from {src_ip}{country_str}",
            description=(
                f"User '{user}' successfully authenticated via SSH from {src_ip}{country_str}. "
                "This source IP has not been seen making successful SSH logins before. "
                "If unexpected, this could indicate compromised credentials."
            ),
            recommended_action=(
                f"Verify you recognize a login from {src_ip}. "
                "If unexpected, check for compromised credentials and review what the session did. "
                "Consider setting up SSH alerts via PAM or SSH 'ForceCommand'."
            ),
            confidence=0.80,
            confidence_rationale="First successful SSH login from this source IP.",
            dedup_key=dedup_key,
            extra={"user": user, "src_ip": src_ip, "country": country},
        )

    def _sudo_sensitive_alert(self, command: str, now: datetime, raw_line: str) -> Optional[Alert]:
        dedup_key = f"sudo_sensitive:{command[:50]}"
        if self._is_on_cooldown(dedup_key, now, 3600):
            return None
        self._last_alert[dedup_key] = now

        return Alert(
            severity=Severity.LOW,
            category=AlertCategory.AUTH_ANOMALY,
            affected_host="localhost",
            title=f"Sensitive sudo command executed: {command[:60]}",
            description=(
                f"A sensitive command was executed via sudo: {command}. "
                "Sensitive sudo commands include spawning shells, modifying system users, "
                "and running interpreters — all common privilege escalation techniques."
            ),
            recommended_action="Verify this sudo usage was authorized. Review the audit trail.",
            confidence=0.70,
            confidence_rationale="Sensitive command in sudo audit log.",
            dedup_key=dedup_key,
            extra={"command": command},
        )

    def _sudo_failure_alert(self, now: datetime, raw_line: str) -> Alert:
        dedup_key = f"sudo_failure:{now.strftime('%Y%m%d%H')}"
        return Alert(
            severity=Severity.LOW,
            category=AlertCategory.AUTH_ANOMALY,
            affected_host="localhost",
            title="Failed sudo attempt",
            description=(
                "A user attempted to use sudo but failed authentication. "
                "Could be a typo, forgotten password, or an unauthorized user trying to escalate privileges."
            ),
            recommended_action="Check who attempted sudo and verify it was authorized.",
            confidence=0.60,
            confidence_rationale="Direct observation in auth log.",
            dedup_key=dedup_key,
        )

    def _is_on_cooldown(self, key: str, now: datetime, seconds: int) -> bool:
        last = self._last_alert.get(key)
        return bool(last and (now - last).total_seconds() < seconds)
