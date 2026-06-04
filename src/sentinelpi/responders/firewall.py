"""
responders/firewall.py - Block a malicious IP via iptables/nftables.

Quarantines a known-bad external host by inserting DROP rules in both
directions (outbound to it — stop exfil/C2 — and inbound from it). It only ever
*plans* commands; the ResponderManager decides whether to execute and, by
default, runs everything in dry-run.

Safety rails baked in:
- Never blocks a private/loopback IP or a whitelisted IP (you can't firewall
  your own gateway out of existence).
- Only handles alerts whose category is in ``auto_block_categories`` and whose
  severity meets ``auto_block_min_severity``.
- Requires both the master switch and ``firewall_block_enabled``.
"""

from __future__ import annotations

import logging
from typing import Callable, List, Optional, Tuple

from .base import BaseResponder, ResponderAction
from ..models import Alert, Severity
from ..utils.network import is_private_ip, is_valid_ip

logger = logging.getLogger(__name__)

# Default command runner: returns (returncode, combined_output).
CommandRunner = Callable[[List[str]], Tuple[int, str]]


def _default_runner(argv: List[str]) -> Tuple[int, str]:
    import subprocess
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=10)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


class FirewallResponder(BaseResponder):
    """Inserts iptables/nftables DROP rules to quarantine a malicious IP."""

    def __init__(self, config, runner: Optional[CommandRunner] = None) -> None:
        super().__init__(config)
        self._runner = runner or _default_runner

    # ------------------------------------------------------------------ gating
    def can_handle(self, alert: Alert) -> bool:
        rc = self.config.response
        if not rc.firewall_block_enabled:
            return False
        if alert.category.value not in rc.auto_block_categories:
            return False
        try:
            if alert.severity < Severity(rc.auto_block_min_severity):
                return False
        except ValueError:
            logger.warning("Invalid auto_block_min_severity %r", rc.auto_block_min_severity)
            return False
        return self._blockable_ip(alert) is not None

    def _blockable_ip(self, alert: Alert) -> Optional[str]:
        """The external IP to block — related_host (the bad party) preferred."""
        for ip in (alert.related_host, alert.affected_host):
            if not ip or not is_valid_ip(ip):
                continue
            if is_private_ip(ip):
                continue
            if ip in self.config.whitelist_ips:
                continue
            return ip
        return None

    # -------------------------------------------------------------------- plan
    def plan(self, alert: Alert) -> Optional[ResponderAction]:
        ip = self._blockable_ip(alert)
        if ip is None:
            return None
        commands = self._build_commands(ip)
        return ResponderAction(
            responder=self.name,
            target=ip,
            description=f"Block {ip} ({self.config.response.firewall_backend}) — outbound and inbound DROP",
            commands=commands,
        )

    def _build_commands(self, ip: str) -> List[List[str]]:
        backend = self.config.response.firewall_backend
        if backend == "nftables":
            return [
                ["nft", "add", "rule", "inet", "filter", "output", "ip", "daddr", ip, "drop"],
                ["nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop"],
            ]
        # default: iptables. -I inserts at the top so the DROP wins.
        return [
            ["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"],
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
        ]

    # ----------------------------------------------------------------- execute
    def execute(self, action: ResponderAction) -> None:
        for argv in action.commands:
            try:
                code, output = self._runner(argv)
            except Exception as exc:  # runner blew up (binary missing, timeout, …)
                action.executed = True
                action.success = False
                action.error = f"{' '.join(argv)}: {exc}"
                logger.error("Firewall command failed: %s", action.error)
                return
            if code != 0:
                action.executed = True
                action.success = False
                action.error = f"{' '.join(argv)} -> exit {code}: {output}"
                logger.error("Firewall command non-zero exit: %s", action.error)
                return
        action.executed = True
        action.success = True
        logger.warning("Quarantined %s via %s.", action.target, self.config.response.firewall_backend)
