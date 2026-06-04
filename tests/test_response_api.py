"""
tests/test_response_api.py - Dashboard endpoints for the approval workflow.

Exercises /api/responses/{pending,recent,<id>/approve,<id>/reject} end-to-end
through Flask's test client, with a real ResponderManager whose firewall command
runner is stubbed (no iptables).
"""

from __future__ import annotations

import pytest

from sentinelpi.ui.dashboard import FLASK_AVAILABLE, create_app
from sentinelpi.responders.manager import ResponderManager
from sentinelpi.responders.firewall import FirewallResponder
from sentinelpi.models import Alert, AlertCategory, Severity

pytestmark = pytest.mark.skipif(not FLASK_AVAILABLE, reason="Flask not installed")


class _RecordingRunner:
    def __init__(self):
        self.calls = []

    def __call__(self, argv):
        self.calls.append(argv)
        return 0, ""


def _threat_alert():
    return Alert(
        severity=Severity.HIGH, category=AlertCategory.THREAT_INTEL,
        affected_host="", related_host="45.9.148.99", title="known-bad", description="d",
    )


@pytest.fixture
def client_and_mgr(config, db, device_tracker, baseline, alert_manager):
    config.dashboard.access_token = ""
    config.response.enabled = True
    config.response.dry_run = False
    config.response.firewall_block_enabled = True
    config.response.require_approval = True

    runner = _RecordingRunner()
    rmgr = ResponderManager(config)
    rmgr.add_responder(FirewallResponder(config, runner=runner))

    app = create_app(config, db, device_tracker, baseline, alert_manager, responder_manager=rmgr)
    app.config.update(TESTING=True)
    headers = {"Authorization": f"Bearer {config.dashboard.access_token}"}
    return app.test_client(), rmgr, runner, headers


def test_pending_lists_queued_action(client_and_mgr):
    client, rmgr, runner, headers = client_and_mgr
    rmgr.handle(_threat_alert())

    resp = client.get("/api/responses/pending", headers=headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data) == 1
    assert data[0]["target"] == "45.9.148.99"
    assert data[0]["status"] == "pending"
    assert runner.calls == []  # not executed yet


def test_approve_endpoint_executes(client_and_mgr):
    client, rmgr, runner, headers = client_and_mgr
    action = rmgr.handle(_threat_alert())[0]

    resp = client.post(f"/api/responses/{action.action_id}/approve", headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "executed"
    assert runner.calls  # the firewall command ran
    assert client.get("/api/responses/pending", headers=headers).get_json() == []


def test_reject_endpoint_discards(client_and_mgr):
    client, rmgr, runner, headers = client_and_mgr
    action = rmgr.handle(_threat_alert())[0]

    resp = client.post(f"/api/responses/{action.action_id}/reject", headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "rejected"
    assert runner.calls == []


def test_approve_unknown_id_is_404(client_and_mgr):
    client, rmgr, runner, headers = client_and_mgr
    assert client.post("/api/responses/nope/approve", headers=headers).status_code == 404


def test_response_endpoints_require_auth(client_and_mgr):
    client, rmgr, runner, headers = client_and_mgr
    assert client.get("/api/responses/pending").status_code == 401


def test_endpoints_absent_without_responder_manager(config, db, device_tracker, baseline, alert_manager):
    config.dashboard.access_token = ""
    app = create_app(config, db, device_tracker, baseline, alert_manager)  # no responder_manager
    headers = {"Authorization": f"Bearer {config.dashboard.access_token}"}
    app.config.update(TESTING=True)
    # The route simply doesn't exist -> 404.
    assert app.test_client().get("/api/responses/pending", headers=headers).status_code == 404
