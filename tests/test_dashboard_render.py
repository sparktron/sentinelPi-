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

from sentinelpi.models import Alert, AlertCategory, Device, Severity
from sentinelpi.responders.base import ResponderAction
from sentinelpi.ui.dashboard import FLASK_AVAILABLE, create_app
from sentinelpi.utils import clock

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


def test_index_links_hosts_to_drilldown_pages(authed_client):
    client, headers = authed_client
    html = client.get("/", headers=headers).get_data(as_text=True)
    assert "/devices/${encodeURIComponent(d.ip)}" in html
    assert "/devices/${encodeURIComponent(a.affected_host)}" in html
    assert "/devices/${encodeURIComponent(h.ip)}" in html


def test_device_detail_page_serves_for_known_host(authed_client, db):
    client, headers = authed_client
    db.upsert_device(Device(ip="10.0.0.9", mac="aa:bb:cc:dd:ee:ff"))

    resp = client.get("/devices/10.0.0.9", headers=headers)

    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Host <code id=\"host-ip\">10.0.0.9</code>" in html
    assert "/api/devices/${encodeURIComponent(HOST_IP)}/detail" in html
    assert "EventSource" in html


def test_device_detail_page_404s_for_unknown_host(authed_client):
    client, headers = authed_client
    assert client.get("/devices/10.0.0.250", headers=headers).status_code == 404


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


def test_device_detail_api_returns_host_context(authed_client, db):
    client, headers = authed_client
    ip = "10.0.0.9"
    db.upsert_device(Device(
        ip=ip,
        mac="aa:bb:cc:dd:ee:ff",
        hostname="workstation",
        vendor="Example NIC",
        alert_count=1,
        suspicion_score=3.5,
    ))
    db.save_alert(Alert(
        severity=Severity.HIGH,
        category=AlertCategory.DNS_ANOMALY,
        affected_host=ip,
        title="Suspicious DNS",
        description="Repeated lookups",
    ))
    db.record_destination(ip, "8.8.8.8", 53, "udp")
    db.record_destination(ip, "8.8.8.8", 53, "udp")
    db.save_dns_observation(clock.now(), ip, "example.test", "A", is_nxdomain=True)
    db.record_host_profile_value(ip, "dst_port", "443")
    db.record_host_profile_value(ip, "peer", "10.0.0.20")
    db.record_host_hour(ip, 13)
    db.record_host_country(ip, "US")

    resp = client.get(f"/api/devices/{ip}/detail", headers=headers)

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["device"]["ip"] == ip
    assert data["device"]["hostname"] == "workstation"
    assert data["recent_alerts"][0]["title"] == "Suspicious DNS"
    assert data["known_destinations"][0]["dst_ip"] == "8.8.8.8"
    assert data["known_destinations"][0]["hit_count"] == 2
    assert data["dns_history"][0]["query_name"] == "example.test"
    assert data["dns_history"][0]["nxdomain_count"] == 1
    assert data["host_profile"]["destination_ports"] == ["443"]
    assert data["host_profile"]["internal_peers"] == ["10.0.0.20"]
    assert data["host_profile"]["active_hours"] == [13]
    assert data["host_profile"]["countries"] == ["US"]


def test_device_detail_api_filters_response_actions(config, db, device_tracker, baseline, alert_manager):
    ip = "10.0.0.9"
    other_ip = "10.0.0.20"
    config.dashboard.access_token = "tok"
    db.upsert_device(Device(ip=ip, mac="aa:bb:cc:dd:ee:ff"))

    class _ResponderManager:
        def recent_actions(self):
            return [
                ResponderAction(responder="FirewallResponder", target=ip, description="Block host"),
                ResponderAction(responder="FirewallResponder", target=other_ip, description="Block other"),
            ]

    app = create_app(
        config, db, device_tracker, baseline, alert_manager, responder_manager=_ResponderManager()
    )
    app.config.update(TESTING=True)
    client = app.test_client()

    resp = client.get(f"/api/devices/{ip}/detail", headers={"Authorization": "Bearer tok"})

    assert resp.status_code == 200
    actions = resp.get_json()["response_actions"]
    assert [a["target"] for a in actions] == [ip]
