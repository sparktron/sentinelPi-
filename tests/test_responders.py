"""
tests/test_responders.py - Tests for Phase 2 active-response framework.

The safety model is the most important thing to pin:

    execute  ⇔  response.enabled  AND  NOT response.dry_run

Everything else (enabled+dry_run, master off) must plan/record but never run a
command. Commands are executed through an injected runner, so no real iptables
is ever invoked.
"""

from __future__ import annotations

import pytest

from sentinelpi.responders.firewall import FirewallResponder
from sentinelpi.responders.manager import ResponderManager
from sentinelpi.models import Alert, AlertCategory, Severity


def _threat_alert(related="45.9.148.99", severity=Severity.HIGH,
                  category=AlertCategory.THREAT_INTEL, affected="192.168.1.50"):
    return Alert(
        severity=severity, category=category,
        affected_host=affected, related_host=related, title="known-bad", description="d",
    )


class _RecordingRunner:
    """Captures argvs instead of running them; returns success."""
    def __init__(self, code=0, output=""):
        self.calls = []
        self._code, self._output = code, output

    def __call__(self, argv):
        self.calls.append(argv)
        return self._code, self._output


def _arm(config, *, enabled, dry_run, fw=True, require_approval=False):
    config.response.enabled = enabled
    config.response.dry_run = dry_run
    config.response.firewall_block_enabled = fw
    config.response.require_approval = require_approval


# --------------------------------------------------------------- gating (core)
def test_master_off_is_fully_inert(config):
    _arm(config, enabled=False, dry_run=False)
    runner = _RecordingRunner()
    mgr = ResponderManager(config)
    mgr.add_responder(FirewallResponder(config, runner=runner))

    actions = mgr.handle(_threat_alert())
    assert actions == []
    assert runner.calls == []  # nothing planned, nothing run


def test_enabled_but_dry_run_plans_without_executing(config):
    _arm(config, enabled=True, dry_run=True)
    runner = _RecordingRunner()
    mgr = ResponderManager(config)
    mgr.add_responder(FirewallResponder(config, runner=runner))

    actions = mgr.handle(_threat_alert())
    assert len(actions) == 1
    a = actions[0]
    assert a.dry_run is True and a.executed is False
    assert a.target == "45.9.148.99"
    assert a.commands  # it planned the iptables commands
    assert runner.calls == []  # but never ran them


def test_armed_executes(config):
    _arm(config, enabled=True, dry_run=False)
    runner = _RecordingRunner()
    mgr = ResponderManager(config)
    mgr.add_responder(FirewallResponder(config, runner=runner))

    actions = mgr.handle(_threat_alert())
    a = actions[0]
    assert a.executed is True and a.success is True
    # Both directions blocked.
    assert runner.calls == [
        ["iptables", "-I", "OUTPUT", "-d", "45.9.148.99", "-j", "DROP"],
        ["iptables", "-I", "INPUT", "-s", "45.9.148.99", "-j", "DROP"],
    ]


# ------------------------------------------------------------- responder gating
def test_firewall_disabled_does_not_handle(config):
    _arm(config, enabled=True, dry_run=False, fw=False)
    mgr = ResponderManager(config)
    mgr.add_responder(FirewallResponder(config, runner=_RecordingRunner()))
    assert mgr.handle(_threat_alert()) == []


def test_category_not_in_allowlist_is_skipped(config):
    _arm(config, enabled=True, dry_run=True)
    # default auto_block_categories == ["threat_intel"]
    fw = FirewallResponder(config)
    assert fw.can_handle(_threat_alert(category=AlertCategory.DNS_ANOMALY)) is False
    assert fw.can_handle(_threat_alert(category=AlertCategory.THREAT_INTEL)) is True


def test_below_min_severity_is_skipped(config):
    _arm(config, enabled=True, dry_run=True)
    config.response.auto_block_min_severity = "high"
    fw = FirewallResponder(config)
    assert fw.can_handle(_threat_alert(severity=Severity.MEDIUM)) is False
    assert fw.can_handle(_threat_alert(severity=Severity.CRITICAL)) is True


# --------------------------------------------------------------- safety: targets
def test_never_blocks_private_or_whitelisted(config):
    _arm(config, enabled=True, dry_run=True)
    fw = FirewallResponder(config)
    # related is private -> falls back to affected (also private) -> nothing
    assert fw.plan(_threat_alert(related="10.0.0.9", affected="192.168.1.5")) is None
    # whitelisted external IP is not blockable
    config.whitelist_ips = ["45.9.148.99"]
    assert fw.plan(_threat_alert(related="45.9.148.99")) is None


def test_domain_related_host_is_not_blockable(config):
    _arm(config, enabled=True, dry_run=True)
    fw = FirewallResponder(config)
    # A DNS threat-intel alert whose related_host is a domain (not an IP) and
    # whose affected_host is local has nothing firewall-blockable.
    assert fw.plan(_threat_alert(related="evil.example.com", affected="192.168.1.5")) is None


def test_nftables_backend_commands(config):
    _arm(config, enabled=True, dry_run=False)
    config.response.firewall_backend = "nftables"
    runner = _RecordingRunner()
    fw = FirewallResponder(config, runner=runner)
    action = fw.plan(_threat_alert())
    fw.execute(action)
    assert runner.calls[0][0] == "nft"
    assert "drop" in runner.calls[0]


# --------------------------------------------------------------- execution errors
def test_command_failure_is_recorded_not_raised(config):
    _arm(config, enabled=True, dry_run=False)
    runner = _RecordingRunner(code=1, output="permission denied")
    fw = FirewallResponder(config, runner=runner)
    action = fw.plan(_threat_alert())
    fw.execute(action)
    assert action.executed is True and action.success is False
    assert "permission denied" in action.error


def test_recent_actions_are_tracked(config):
    _arm(config, enabled=True, dry_run=True)
    mgr = ResponderManager(config)
    mgr.add_responder(FirewallResponder(config, runner=_RecordingRunner()))
    mgr.handle(_threat_alert())
    assert len(mgr.recent_actions()) == 1


# --------------------------------------------------------------- approval flow
def test_armed_with_approval_queues_pending_not_executed(config):
    from sentinelpi.responders.base import PENDING
    _arm(config, enabled=True, dry_run=False, require_approval=True)
    runner = _RecordingRunner()
    mgr = ResponderManager(config)
    mgr.add_responder(FirewallResponder(config, runner=runner))

    actions = mgr.handle(_threat_alert())
    assert len(actions) == 1
    assert actions[0].status == PENDING
    assert runner.calls == []  # nothing executed yet
    assert len(mgr.pending_actions()) == 1


def test_approve_executes_pending_action(config):
    from sentinelpi.responders.base import EXECUTED
    _arm(config, enabled=True, dry_run=False, require_approval=True)
    runner = _RecordingRunner()
    mgr = ResponderManager(config)
    mgr.add_responder(FirewallResponder(config, runner=runner))

    action = mgr.handle(_threat_alert())[0]
    approved = mgr.approve(action.action_id)
    assert approved.status == EXECUTED and approved.success is True
    assert runner.calls  # now it ran
    assert mgr.pending_actions() == []  # cleared from the queue


def test_reject_discards_pending_action(config):
    from sentinelpi.responders.base import REJECTED
    _arm(config, enabled=True, dry_run=False, require_approval=True)
    runner = _RecordingRunner()
    mgr = ResponderManager(config)
    mgr.add_responder(FirewallResponder(config, runner=runner))

    action = mgr.handle(_threat_alert())[0]
    rejected = mgr.reject(action.action_id)
    assert rejected.status == REJECTED
    assert runner.calls == []  # never executed
    assert mgr.pending_actions() == []


def test_auto_execute_category_bypasses_approval(config):
    from sentinelpi.responders.base import EXECUTED
    _arm(config, enabled=True, dry_run=False, require_approval=True)
    config.response.auto_execute_categories = ["threat_intel"]  # trust this category
    runner = _RecordingRunner()
    mgr = ResponderManager(config)
    mgr.add_responder(FirewallResponder(config, runner=runner))

    action = mgr.handle(_threat_alert())[0]
    assert action.status == EXECUTED
    assert runner.calls  # fired without approval
    assert mgr.pending_actions() == []


def test_approve_unknown_id_returns_none(config):
    _arm(config, enabled=True, dry_run=False, require_approval=True)
    mgr = ResponderManager(config)
    assert mgr.approve("nope") is None
    assert mgr.reject("nope") is None


# --------------------------------------------------------------- manager wiring
def test_alert_manager_invokes_responder(config, db, device_tracker):
    from sentinelpi.alerts.manager import AlertManager
    _arm(config, enabled=True, dry_run=False)
    runner = _RecordingRunner()
    rmgr = ResponderManager(config)
    rmgr.add_responder(FirewallResponder(config, runner=runner))

    am = AlertManager(config, db, device_tracker)
    am.set_responder_manager(rmgr)
    am.process_one(_threat_alert(related="45.9.148.99", affected=""))

    assert runner.calls, "alert manager should drive the responder on a fired alert"
