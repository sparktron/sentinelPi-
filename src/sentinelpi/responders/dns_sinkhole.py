"""
responders/dns_sinkhole.py - Block a malicious domain at the resolver.

The domain-level counterpart to FirewallResponder: when a DGA/C2/threat-intel
alert names a known-bad *domain*, push a block so the network's own resolver
answers it as dead. Three backends:

- ``hosts``   - append ``0.0.0.0 <domain>`` to a sinkhole hosts file the resolver
                includes (default; no external service needed).
- ``pihole``  - ``pihole -b <domain>``.
- ``unbound`` - ``unbound-control local_zone <domain> always_nxdomain``.

Like all responders it only *plans*; the ResponderManager owns the dry-run /
approval / execute gating. Safety rails: only acts on configured categories at/
above a severity, and never sinkholes a whitelisted domain.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from .base import BaseResponder, ResponderAction
from ..models import Alert, Severity
from ..utils.network import is_valid_ip

logger = logging.getLogger(__name__)

CommandRunner = Callable[[List[str]], Tuple[int, str]]


def _default_runner(argv: List[str]) -> Tuple[int, str]:
    import subprocess
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=10)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


class DNSSinkholeResponder(BaseResponder):
    """Sinkholes a malicious domain via a hosts file, Pi-hole, or Unbound."""

    def __init__(self, config, runner: Optional[CommandRunner] = None) -> None:
        super().__init__(config)
        self._runner = runner or _default_runner

    # ------------------------------------------------------------------ gating
    def can_handle(self, alert: Alert) -> bool:
        rc = self.config.response
        if not rc.dns_sinkhole_enabled:
            return False
        if alert.category.value not in rc.sinkhole_categories:
            return False
        try:
            if alert.severity < Severity(rc.sinkhole_min_severity):
                return False
        except ValueError:
            logger.warning("Invalid sinkhole_min_severity %r", rc.sinkhole_min_severity)
            return False
        return self._blockable_domain(alert) is not None

    def _blockable_domain(self, alert: Alert) -> Optional[str]:
        """The malicious domain to sinkhole (related_host, if it's a domain)."""
        candidate = (alert.related_host or "").strip().lower().rstrip(".")
        if not candidate or is_valid_ip(candidate) or "." not in candidate:
            return None
        if candidate in {d.lower() for d in self.config.whitelist_domains}:
            return None
        return candidate

    # -------------------------------------------------------------------- plan
    def plan(self, alert: Alert) -> Optional[ResponderAction]:
        domain = self._blockable_domain(alert)
        if domain is None:
            return None
        backend = self.config.response.dns_sinkhole_backend
        commands = self._build_commands(backend, domain)
        if backend == "hosts":
            desc = f"Sinkhole {domain} → 0.0.0.0 in {self.config.response.dns_sinkhole_hosts_file}"
        else:
            desc = f"Sinkhole {domain} via {backend}"
        return ResponderAction(responder=self.name, target=domain, description=desc, commands=commands)

    def _build_commands(self, backend: str, domain: str) -> List[List[str]]:
        if backend == "pihole":
            return [["pihole", "-b", domain]]
        if backend == "unbound":
            return [["unbound-control", "local_zone", domain, "always_nxdomain"]]
        return []  # hosts backend writes a file directly in execute()

    # ----------------------------------------------------------------- execute
    def execute(self, action: ResponderAction) -> None:
        backend = self.config.response.dns_sinkhole_backend
        if backend == "hosts":
            self._sinkhole_via_hosts(action)
            return
        for argv in action.commands:
            try:
                code, output = self._runner(argv)
            except Exception as exc:
                action.executed = True
                action.success = False
                action.error = f"{' '.join(argv)}: {exc}"
                logger.error("DNS sinkhole command failed: %s", action.error)
                return
            if code != 0:
                action.executed = True
                action.success = False
                action.error = f"{' '.join(argv)} -> exit {code}: {output}"
                logger.error("DNS sinkhole command non-zero exit: %s", action.error)
                return
        action.executed = True
        action.success = True
        logger.warning("Sinkholed %s via %s.", action.target, backend)

    def _sinkhole_via_hosts(self, action: ResponderAction) -> None:
        path = Path(self.config.response.dns_sinkhole_hosts_file)
        line = f"0.0.0.0 {action.target}\n"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Idempotent: don't append a domain that's already sinkholed.
            existing = path.read_text(encoding="utf-8") if path.exists() else ""
            if f" {action.target}\n" not in existing and not existing.endswith(f" {action.target}"):
                with path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
            action.executed = True
            action.success = True
            logger.warning("Sinkholed %s via hosts file %s.", action.target, path)
        except OSError as exc:
            action.executed = True
            action.success = False
            action.error = f"hosts write {path}: {exc}"
            logger.error("DNS sinkhole hosts write failed: %s", action.error)
