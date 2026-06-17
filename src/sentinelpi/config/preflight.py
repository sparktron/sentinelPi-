"""
config/preflight.py - Active preflight checks for ``sentinelpi --check``.

Where ``--check-config`` is a static, side-effect-free validation of the config
file, ``--check`` goes further: it actually exercises the configured outputs so
operators catch a broken webhook URL, wrong SMTP credentials, or an unreachable
collector *before* an alert needs to go out.

Two kinds of check:

- Notifiers: each enabled network notifier's ``preflight()`` is called, which
  tests connectivity/credentials. Email only connects + authenticates (no mail
  sent); webhook/ntfy/forward deliver a clearly-labelled test notification.
- Responders: each enabled responder is asked to ``plan()`` a synthetic alert
  it should handle. Planning is side-effect-free by contract, so nothing is ever
  executed — this just confirms the responder is wired and shows what it *would*
  do.

Returns structured :class:`CheckResult` rows so the CLI can print them and pick
an exit code.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, List, Optional, Type

from ..models import Alert, AlertCategory, Severity
from ..alerts.notifiers import BaseNotifier
from ..responders.base import BaseResponder

logger = logging.getLogger(__name__)

# Documentation/test ranges, safe to use as synthetic targets (RFC 5737 / 2606).
_PROBE_PUBLIC_IP = "203.0.113.10"
_PROBE_DOMAIN = "malware.preflight.example"
_PROBE_GATEWAY_IP = "192.168.255.254"
_PROBE_GATEWAY_MAC = "02:00:00:00:00:01"
_PROBE_HOST_IP = "192.168.255.50"


# status is one of: "ok", "fail", "skip"
@dataclass
class CheckResult:
    name: str
    status: str
    detail: str

    @property
    def failed(self) -> bool:
        return self.status == "fail"


def run_preflight(config) -> List[CheckResult]:
    """Run all active preflight checks and return their results."""
    results: List[CheckResult] = []
    results.extend(_check_notifiers(config))
    results.extend(_check_responders(config))
    return results


# --------------------------------------------------------------------- notifiers
def _check_notifiers(config) -> List[CheckResult]:
    from ..alerts.notifiers import (
        EmailNotifier, WebhookNotifier, NtfyNotifier, TwilioSMSNotifier, SyslogNotifier,
        ForwardNotifier,
    )

    n = config.notifications
    results: List[CheckResult] = []

    specs: List[tuple[str, Callable[[], BaseNotifier]]] = []
    if n.email_enabled:
        specs.append(("notifier:email", lambda: EmailNotifier(config)))
    if n.webhook_enabled and n.webhook_url:
        specs.append(("notifier:webhook", lambda: WebhookNotifier(config)))
    if n.ntfy_enabled and n.ntfy_topic:
        specs.append(("notifier:ntfy", lambda: NtfyNotifier(config)))
    if n.sms_enabled:
        specs.append(("notifier:twilio-sms", lambda: TwilioSMSNotifier(config)))
    if n.siem_enabled and n.siem_host:
        specs.append(("notifier:siem", lambda: SyslogNotifier(config)))
    if config.cluster.role == "sensor" and config.cluster.collector_url:
        specs.append(("notifier:forward", lambda: ForwardNotifier(config)))

    if not specs:
        return [CheckResult("notifiers", "skip", "no network notifiers enabled")]

    for name, build in specs:
        notifier = None
        try:
            notifier = build()
            ok, detail = notifier.preflight()
            results.append(CheckResult(name, "ok" if ok else "fail", detail))
        except Exception as exc:
            results.append(CheckResult(name, "fail", f"{type(exc).__name__}: {exc}"))
        finally:
            if notifier is not None:
                try:
                    notifier.close(timeout=2.0)
                except Exception:
                    pass
    return results


# -------------------------------------------------------------------- responders
def _check_responders(config) -> List[CheckResult]:
    rc = config.response
    if not rc.enabled:
        return [CheckResult("responders", "skip", "response.enabled is false")]

    from ..responders.firewall import FirewallResponder
    from ..responders.dns_sinkhole import DNSSinkholeResponder
    from ..responders.arp_restore import ARPRestoreResponder
    from ..responders.killswitch import KillSwitchResponder

    mode = "dry-run" if rc.dry_run else "armed"
    specs: List[tuple[str, Type[BaseResponder], Optional[Alert]]] = []
    if rc.firewall_block_enabled:
        specs.append((
            "responder:firewall", FirewallResponder,
            _probe_alert(rc.auto_block_categories, rc.auto_block_min_severity,
                         related_host=_PROBE_PUBLIC_IP),
        ))
    if rc.dns_sinkhole_enabled:
        specs.append((
            "responder:dns_sinkhole", DNSSinkholeResponder,
            _probe_alert(rc.sinkhole_categories, rc.sinkhole_min_severity,
                         related_host=_PROBE_DOMAIN),
        ))
    if rc.arp_restore_enabled:
        specs.append((
            "responder:arp_restore", ARPRestoreResponder,
            _probe_alert([AlertCategory.ARP_ANOMALY.value], rc.arp_restore_min_severity,
                         affected_host=_PROBE_GATEWAY_IP, affected_mac=_PROBE_GATEWAY_MAC,
                         extra={"is_gateway": True}),
        ))
    if rc.killswitch_enabled:
        specs.append((
            "responder:killswitch", KillSwitchResponder,
            _probe_alert(rc.killswitch_categories, rc.killswitch_min_severity,
                         affected_host=_PROBE_HOST_IP),
        ))

    if not specs:
        return [CheckResult("responders", "skip", "enabled but no responders configured")]

    results: List[CheckResult] = []
    for name, cls, alert in specs:
        try:
            responder = cls(config)
            if alert is None:
                results.append(CheckResult(name, "skip", "no alert category opted in"))
                continue
            if not responder.can_handle(alert):
                results.append(CheckResult(
                    name, "skip",
                    "constructed, but no opted-in category/severity to plan against"))
                continue
            action = responder.plan(alert)
            if action is None:
                results.append(CheckResult(name, "ok", f"[{mode}] handled, nothing to do"))
            else:
                results.append(CheckResult(name, "ok", f"[{mode}] would: {action.description}"))
        except Exception as exc:
            results.append(CheckResult(name, "fail", f"{type(exc).__name__}: {exc}"))
    return results


def _probe_alert(categories, min_severity: str, **kwargs):
    """
    Build a synthetic alert that should satisfy a responder's ``can_handle``:
    its first opted-in category at the responder's minimum severity. Returns
    None when no category is opted in (the responder has nothing to act on).
    """
    if not categories:
        return None
    try:
        severity = Severity(min_severity)
    except ValueError:
        severity = Severity.HIGH
    try:
        category = AlertCategory(categories[0])
    except ValueError:
        category = AlertCategory.THREAT_INTEL
    return Alert(
        severity=severity,
        category=category,
        title="Preflight synthetic alert",
        description="Synthetic alert from `sentinelpi --check`; never executed.",
        **kwargs,
    )
