"""
tests/test_killswitch.py - Tests for the kill-switch command responder (Phase 2).

Verifies placeholder substitution, the safety gates (off / no command / no
categories / below severity), command execution via an injected runner, and an
end-to-end manager+approval path.
"""

from __future__ import annotations

import pytest

from sentinelpi.responders.killswitch import KillSwitchResponder
from sentinelpi.responders.manager import ResponderManager
from sentinelpi.models import Alert, AlertCategory, Severity


class _RecordingRunner:
    def __init__(self, code=0, output=""):
        self.calls = []
        self._code, self._output = code, output

    def __call__(self, argv):
        self.calls.append(argv)
        return self._code, self._output


def _alert(category=AlertCategory.THREAT_INTEL, severity=Severity.CRITICAL,
           ip="192.168.1.66", mac="de:ad:be:ef:00:66", related="45.9.148.99"):
    return Alert(
        severity=severity, category=category, affected_host=ip, affected_mac=mac,
        related_host=related, title="compromise", description="d",
    )


def _enable(config, *, command, categories, min_sev="critical"):
    config.response.killswitch_enabled = True
    config.response.killswitch_command = command
    config.response.killswitch_categories = categories
    config.response.killswitch_min_severity = min_sev


# ------------------------------------------------------------- substitution
def test_placeholders_are_substituted(config):
    _enable(config, command=["/opt/quarantine.sh", "{ip}", "{mac}", "{category}", "{severity}"],
            categories=["threat_intel"])
    runner = _RecordingRunner()
    r = KillSwitchResponder(config, runner=runner)
    r.execute(r.plan(_alert()))
    assert runner.calls == [
        ["/opt/quarantine.sh", "192.168.1.66", "de:ad:be:ef:00:66", "threat_intel", "critical"],
    ]


def test_target_prefers_affected_host(config):
    _enable(config, command=["block", "{ip}"], categories=["threat_intel"])
    r = KillSwitchResponder(config)
    assert r.plan(_alert(ip="192.168.1.5")).target == "192.168.1.5"


# --------------------------------------------------------------------- gating
def test_disabled_not_handled(config):
    _enable(config, command=["x", "{ip}"], categories=["threat_intel"])
    config.response.killswitch_enabled = False
    assert KillSwitchResponder(config).can_handle(_alert()) is False


def test_empty_command_not_handled(config):
    _enable(config, command=[], categories=["threat_intel"])
    assert KillSwitchResponder(config).can_handle(_alert()) is False


def test_empty_categories_not_handled(config):
    _enable(config, command=["x", "{ip}"], categories=[])
    assert KillSwitchResponder(config).can_handle(_alert()) is False


def test_category_gate(config):
    _enable(config, command=["x", "{ip}"], categories=["honeypot"])
    r = KillSwitchResponder(config)
    assert r.can_handle(_alert(category=AlertCategory.THREAT_INTEL)) is False
    assert r.can_handle(_alert(category=AlertCategory.HONEYPOT)) is True


def test_severity_gate(config):
    _enable(config, command=["x", "{ip}"], categories=["threat_intel"], min_sev="critical")
    r = KillSwitchResponder(config)
    assert r.can_handle(_alert(severity=Severity.HIGH)) is False
    assert r.can_handle(_alert(severity=Severity.CRITICAL)) is True


# ------------------------------------------------------------------ execution
def test_command_failure_recorded(config):
    _enable(config, command=["/opt/x.sh", "{ip}"], categories=["threat_intel"])
    runner = _RecordingRunner(code=3, output="boom")
    r = KillSwitchResponder(config, runner=runner)
    action = r.plan(_alert())
    r.execute(action)
    assert action.success is False and "boom" in action.error


def test_through_manager_with_approval(config):
    from sentinelpi.responders.base import PENDING, EXECUTED
    _enable(config, command=["/opt/x.sh", "{ip}"], categories=["honeypot"])
    config.response.enabled = True
    config.response.dry_run = False
    config.response.require_approval = True
    runner = _RecordingRunner()
    mgr = ResponderManager(config)
    mgr.add_responder(KillSwitchResponder(config, runner=runner))

    action = mgr.handle(_alert(category=AlertCategory.HONEYPOT))[0]
    assert action.status == PENDING and runner.calls == []
    mgr.approve(action.action_id)
    assert action.status == EXECUTED and runner.calls
