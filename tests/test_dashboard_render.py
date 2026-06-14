"""
tests/test_dashboard_render.py - The dashboard HTML ships the frontend wiring it
depends on.

The dashboard's behavior lives in template JavaScript (no Python), so a refactor
could silently drop it and every Python test would still pass. These tests assert
against the *served* markup that the two recently-added pieces are present:

  - the Active Response approval section (+ its /api/responses wiring), and
  - the apiFetch wrapper that redirects to /login when the session 401s.

The index page accepts a Bearer token (like the API), so we authenticate that way.
"""

from __future__ import annotations

import pytest

from sentinelpi.ui.dashboard import FLASK_AVAILABLE, create_app

pytestmark = pytest.mark.skipif(not FLASK_AVAILABLE, reason="Flask not installed")


@pytest.fixture
def authed_client(config, db, device_tracker, baseline, alert_manager):
    config.dashboard.access_token = "tok"
    app = create_app(config, db, device_tracker, baseline, alert_manager)
    app.config.update(TESTING=True)
    return app.test_client(), {"Authorization": "Bearer tok"}


def test_index_serves_dashboard(authed_client):
    client, headers = authed_client
    resp = client.get("/", headers=headers)
    assert resp.status_code == 200
    assert b"SentinelPi Dashboard" in resp.data


def test_index_includes_active_response_wiring(authed_client):
    client, headers = authed_client
    html = client.get("/", headers=headers).get_data(as_text=True)
    # The section container + the data source it loads from.
    assert 'id="responses-section"' in html
    assert "/api/responses/recent" in html
    assert "loadResponses" in html
    # Approve / reject controls call the right endpoints.
    assert "approveAction" in html and "rejectAction" in html
    assert "/approve" in html and "/reject" in html


def test_index_redirects_to_login_on_session_expiry(authed_client):
    client, headers = authed_client
    html = client.get("/", headers=headers).get_data(as_text=True)
    # apiFetch wraps every call and bounces to /login on a 401.
    assert "apiFetch" in html
    assert "window.location = '/login'" in html
    assert "401" in html


def test_index_includes_incident_timeline_wiring(authed_client):
    client, headers = authed_client
    html = client.get("/", headers=headers).get_data(as_text=True)
    # The incident timeline renderer + the field it reads from the alert dict.
    assert "incidentTimeline" in html
    assert "a.timeline" in html
    assert "incident-timeline" in html


def test_index_includes_live_update_wiring(authed_client):
    client, headers = authed_client
    html = client.get("/", headers=headers).get_data(as_text=True)
    assert "EventSource" in html
    assert "/api/events" in html
    assert "connectLiveUpdates" in html
    assert "startPollingFallback" in html
    assert 'id="live-status"' in html


def test_events_api_streams_dashboard_status(authed_client):
    client, headers = authed_client
    resp = client.get("/api/events?once=1", headers=headers)

    assert resp.status_code == 200
    assert resp.mimetype == "text/event-stream"
    body = resp.get_data(as_text=True)
    assert "event: dashboard" in body
    assert '"status": "running"' in body
    assert '"tick": 0' in body


def test_alerts_api_exposes_incident_timeline(authed_client, db):
    from datetime import timezone
    from sentinelpi.models import Alert, AlertCategory, Severity
    from sentinelpi.utils import clock

    client, headers = authed_client
    timeline = [
        {"timestamp": clock.now().isoformat(), "category": "new_device",
         "severity": "medium", "title": "New device 10.0.0.9",
         "affected_host": "10.0.0.9", "related_host": None},
        {"timestamp": clock.now().isoformat(), "category": "lateral_movement",
         "severity": "high", "title": "Lateral movement from 10.0.0.9",
         "affected_host": "10.0.0.9", "related_host": "10.0.0.20"},
    ]
    db.save_alert(Alert(
        severity=Severity.HIGH,
        category=AlertCategory.INCIDENT,
        affected_host="10.0.0.9",
        title="Possible intrusion sequence: 10.0.0.9",
        description="ordered sequence",
        extra={"actor": "10.0.0.9", "timeline": timeline},
    ))

    resp = client.get("/api/alerts?hours=24&limit=50", headers=headers)
    assert resp.status_code == 200
    incident = next(a for a in resp.get_json() if a["category"] == "incident")
    assert incident["timeline"] is not None
    assert len(incident["timeline"]) == 2
    assert incident["timeline"][1]["category"] == "lateral_movement"
