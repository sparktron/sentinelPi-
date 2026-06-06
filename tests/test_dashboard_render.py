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
