"""
responders/killswitch.py - Run an operator-supplied command on compromise.

The "kill switch" from the roadmap, kept deliberately generic: instead of
hardcoding a particular router API / hostapd / switch vendor, it runs a command
*you* configure, with the offending host's details substituted in. That covers
de-authing a Wi-Fi client, hitting a router's block API, flipping a switch-port
ACL, paging a script — whatever your environment needs.

Placeholders substituted in each command token:
    {ip}  {mac}  {related}  {category}  {severity}

Safety: it does nothing unless a command AND at least one category are
configured, and (like every responder) it runs only under the manager's
dry-run/approval/execute gating. The default severity gate is CRITICAL, and the
default category list is empty — so out of the box it never fires.
"""

from __future__ import annotations

import logging
from typing import Callable, List, Optional, Tuple

from .base import BaseResponder, ResponderAction
from ..models import Alert, Severity

logger = logging.getLogger(__name__)

CommandRunner = Callable[[List[str]], Tuple[int, str]]


def _default_runner(argv: List[str]) -> Tuple[int, str]:
    import subprocess
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=15)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


class KillSwitchResponder(BaseResponder):
    """Runs a configured command template against the offending host."""

    def __init__(self, config, runner: Optional[CommandRunner] = None) -> None:
        super().__init__(config)
        self._runner = runner or _default_runner

    # ------------------------------------------------------------------ gating
    def can_handle(self, alert: Alert) -> bool:
        rc = self.config.response
        if not rc.killswitch_enabled:
            return False
        if not rc.killswitch_command or not rc.killswitch_categories:
            return False  # nothing to run / nothing opted in
        if alert.category.value not in rc.killswitch_categories:
            return False
        try:
            if alert.severity < Severity(rc.killswitch_min_severity):
                return False
        except ValueError:
            logger.warning("Invalid killswitch_min_severity %r", rc.killswitch_min_severity)
            return False
        return bool(alert.affected_host or alert.related_host)

    # -------------------------------------------------------------------- plan
    def plan(self, alert: Alert) -> Optional[ResponderAction]:
        rc = self.config.response
        if not rc.killswitch_command:
            return None
        target = alert.affected_host or alert.related_host
        argv = [self._substitute(tok, alert) for tok in rc.killswitch_command]
        return ResponderAction(
            responder=self.name,
            target=target,
            description=f"Run kill switch for {target}: {' '.join(argv)}",
            commands=[argv],
        )

    @staticmethod
    def _substitute(token: str, alert: Alert) -> str:
        return (
            token.replace("{ip}", alert.affected_host)
            .replace("{mac}", alert.affected_mac)
            .replace("{related}", alert.related_host)
            .replace("{category}", alert.category.value)
            .replace("{severity}", alert.severity.value)
        )

    # ----------------------------------------------------------------- execute
    def execute(self, action: ResponderAction) -> None:
        for argv in action.commands:
            try:
                code, output = self._runner(argv)
            except Exception as exc:
                action.executed = True
                action.success = False
                action.error = f"{' '.join(argv)}: {exc}"
                logger.error("Kill switch command failed: %s", action.error)
                return
            if code != 0:
                action.executed = True
                action.success = False
                action.error = f"{' '.join(argv)} -> exit {code}: {output}"
                logger.error("Kill switch command non-zero exit: %s", action.error)
                return
        action.executed = True
        action.success = True
        logger.warning("Kill switch executed for %s.", action.target)
