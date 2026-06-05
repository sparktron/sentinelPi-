"""
tests/test_per_sensor.py - Per-sensor multi-host dashboard views (Phase 3).

Covers the schema-v6 sensor column: save_alert populates it from
extra["sensor"], get_recent_alerts filters by sensor (with "local" selecting
locally-raised alerts), get_sensors aggregates, and the dashboard surfaces
/api/sensors plus the ?sensor= filter on /api/alerts.
"""

from __future__ import annotations

import pytest

from sentinelpi.models import Alert, AlertCategory, Severity
from sentinelpi.ui.dashboard import FLASK_AVAILABLE, create_app


def _alert(sensor=None, **kw):
    base = dict(severity=Severity.HIGH, category=AlertCategory.PORT_SCAN,
                affected_host="192.168.1.50", title="t", description="d")
    base.update(kw)
    a = Alert(**base)
    if sensor is not None:
        a.extra["sensor"] = sensor
    return a


def _seed(db):
    db.save_alert(_alert(sensor="pi-garage", dedup_key="a"))
    db.save_alert(_alert(sensor="pi-garage", dedup_key="b"))
    db.save_alert(_alert(sensor="pi-attic", dedup_key="c"))
    db.save_alert(_alert(dedup_key="d"))   # local (no sensor tag)


# --------------------------------------------------------------------- database
def test_save_alert_populates_sensor_column(db):
    db.save_alert(_alert(sensor="pi-garage", dedup_key="x"))
    conn = db._get_connection()
    row = conn.execute("SELECT sensor FROM alerts").fetchone()
    assert row["sensor"] == "pi-garage"


def test_get_recent_alerts_filters_by_sensor(db):
    _seed(db)
    assert len(db.get_recent_alerts(sensor="pi-garage")) == 2
    assert len(db.get_recent_alerts(sensor="pi-attic")) == 1
    # "local" selects alerts raised on this node (no forwarded sensor tag).
    local = db.get_recent_alerts(sensor="local")
    assert len(local) == 1 and "sensor" not in local[0].extra


def test_get_sensors_aggregates(db):
    _seed(db)
    by_id = {s["sensor"]: s for s in db.get_sensors()}
    assert by_id["pi-garage"]["alert_count"] == 2
    assert by_id["pi-attic"]["alert_count"] == 1
    assert by_id["local"]["alert_count"] == 1


# -------------------------------------------------------------------- dashboard
@pytest.fixture
def client(config, db, device_tracker, baseline, alert_manager):
    if not FLASK_AVAILABLE:
        pytest.skip("Flask not installed")
    config.dashboard.access_token = "test-token"
    _seed(db)
    app = create_app(config, db, device_tracker, baseline, alert_manager)
    app.config.update(TESTING=True)
    headers = {"Authorization": "Bearer test-token"}
    return app.test_client(), headers


def test_api_sensors_lists_reporters(client):
    c, headers = client
    data = {s["sensor"]: s["alert_count"] for s in c.get("/api/sensors", headers=headers).get_json()}
    assert data == {"pi-garage": 2, "pi-attic": 1, "local": 1}


def test_api_alerts_sensor_filter(client):
    c, headers = client
    resp = c.get("/api/alerts?sensor=pi-garage", headers=headers)
    assert resp.status_code == 200
    alerts = resp.get_json()
    assert len(alerts) == 2
    assert all(a["sensor"] == "pi-garage" for a in alerts)


def test_api_alerts_includes_sensor_field(client):
    c, headers = client
    alerts = c.get("/api/alerts", headers=headers).get_json()
    assert {a["sensor"] for a in alerts} == {"pi-garage", "pi-attic", "local"}
