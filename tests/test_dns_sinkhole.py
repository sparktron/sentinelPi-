"""
tests/test_dns_sinkhole.py - Tests for the DNS sinkhole responder (Phase 2).

Covers domain selection, the three backends (hosts file write, pihole, unbound
commands), gating, and idempotency. Subprocess backends use an injected runner;
the hosts backend writes to a tmp file.
"""

from __future__ import annotations

import pytest

from sentinelpi.responders.dns_sinkhole import DNSSinkholeResponder
from sentinelpi.responders.manager import ResponderManager
from sentinelpi.models import Alert, AlertCategory, Severity


class _RecordingRunner:
    def __init__(self, code=0, output=""):
        self.calls = []
        self._code, self._output = code, output

    def __call__(self, argv):
        self.calls.append(argv)
        return self._code, self._output


def _dns_alert(related="evil.example.com", severity=Severity.HIGH,
               category=AlertCategory.THREAT_INTEL):
    return Alert(
        severity=severity, category=category,
        affected_host="192.168.1.50", related_host=related, title="bad domain", description="d",
    )


def _enable(config, *, backend="hosts", hosts_file=None):
    config.response.dns_sinkhole_enabled = True
    config.response.dns_sinkhole_backend = backend
    if hosts_file:
        config.response.dns_sinkhole_hosts_file = str(hosts_file)


# ----------------------------------------------------------------- domain pick
def test_ignores_ip_related_host(config):
    _enable(config)
    r = DNSSinkholeResponder(config)
    assert r.plan(_dns_alert(related="45.9.148.99")) is None


def test_ignores_non_domain(config):
    _enable(config)
    r = DNSSinkholeResponder(config)
    assert r.plan(_dns_alert(related="localhost")) is None  # no dot


def test_whitelisted_domain_not_sinkholed(config):
    _enable(config)
    config.whitelist_domains = ["evil.example.com"]
    r = DNSSinkholeResponder(config)
    assert r.plan(_dns_alert()) is None


# ----------------------------------------------------------------- hosts backend
def test_hosts_backend_writes_file(config, tmp_path):
    f = tmp_path / "sinkhole.hosts"
    _enable(config, backend="hosts", hosts_file=f)
    r = DNSSinkholeResponder(config)
    action = r.plan(_dns_alert())
    r.execute(action)
    assert action.success is True
    assert "0.0.0.0 evil.example.com" in f.read_text()


def test_hosts_backend_is_idempotent(config, tmp_path):
    f = tmp_path / "sinkhole.hosts"
    _enable(config, backend="hosts", hosts_file=f)
    r = DNSSinkholeResponder(config)
    for _ in range(3):
        r.execute(r.plan(_dns_alert()))
    assert f.read_text().count("evil.example.com") == 1


# ----------------------------------------------------------------- subprocess backends
def test_pihole_backend_command(config):
    _enable(config, backend="pihole")
    runner = _RecordingRunner()
    r = DNSSinkholeResponder(config, runner=runner)
    r.execute(r.plan(_dns_alert()))
    assert runner.calls == [["pihole", "-b", "evil.example.com"]]


def test_unbound_backend_command(config):
    _enable(config, backend="unbound")
    runner = _RecordingRunner()
    r = DNSSinkholeResponder(config, runner=runner)
    r.execute(r.plan(_dns_alert()))
    assert runner.calls[0][0] == "unbound-control"
    assert "always_nxdomain" in runner.calls[0]


def test_command_failure_recorded(config):
    _enable(config, backend="pihole")
    runner = _RecordingRunner(code=2, output="not installed")
    r = DNSSinkholeResponder(config, runner=runner)
    action = r.plan(_dns_alert())
    r.execute(action)
    assert action.success is False and "not installed" in action.error


# ----------------------------------------------------------------- gating
def test_disabled_does_not_handle(config):
    config.response.dns_sinkhole_enabled = False
    assert DNSSinkholeResponder(config).can_handle(_dns_alert()) is False


def test_category_and_severity_gates(config):
    _enable(config)
    r = DNSSinkholeResponder(config)
    assert r.can_handle(_dns_alert(category=AlertCategory.PORT_SCAN)) is False
    assert r.can_handle(_dns_alert(severity=Severity.MEDIUM)) is False
    assert r.can_handle(_dns_alert(category=AlertCategory.DNS_ANOMALY)) is True


# ----------------------------------------------------------------- via manager + approval
def test_through_manager_with_approval(config, tmp_path):
    from sentinelpi.responders.base import PENDING, EXECUTED
    f = tmp_path / "sinkhole.hosts"
    _enable(config, backend="hosts", hosts_file=f)
    config.response.enabled = True
    config.response.dry_run = False
    config.response.require_approval = True

    mgr = ResponderManager(config)
    mgr.add_responder(DNSSinkholeResponder(config))
    action = mgr.handle(_dns_alert())[0]
    assert action.status == PENDING
    assert not f.exists()  # not written yet

    mgr.approve(action.action_id)
    assert action.status == EXECUTED
    assert "evil.example.com" in f.read_text()
