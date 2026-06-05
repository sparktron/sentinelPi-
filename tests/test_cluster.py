"""
tests/test_cluster.py - Sensor/collector multi-host coverage (Phase 3).

Covers Alert <-> dict round-trip, the ForwardNotifier payload/gating (requests
stubbed), and the collector /api/ingest endpoint (auth, save, sensor tagging,
loop-prevention) through Flask's test client.
"""

from __future__ import annotations

import pytest

from sentinelpi.models import Alert, AlertCategory, Severity, alert_from_dict


def _alert(**kw):
    base = dict(severity=Severity.HIGH, category=AlertCategory.THREAT_INTEL,
                affected_host="192.168.1.50", related_host="45.9.148.99",
                title="known-bad", description="d")
    base.update(kw)
    return Alert(**base)


# ----------------------------------------------------------------- round-trip
def test_alert_dict_round_trip():
    from sentinelpi.alerts.notifiers import BaseNotifier
    original = _alert(confidence=0.9)
    original.extra["k"] = "v"
    d = BaseNotifier._alert_to_dict(None, original)  # static-ish helper
    back = alert_from_dict(d)
    assert back.alert_id == original.alert_id
    assert back.severity == original.severity
    assert back.category == original.category
    assert back.affected_host == original.affected_host
    assert back.extra["k"] == "v"


def test_alert_from_dict_bad_values_fall_back():
    a = alert_from_dict({"severity": "purple", "category": "nope", "timestamp": "garbage"})
    assert a.severity == Severity.INFO
    assert a.category == AlertCategory.SYSTEM
    assert a.timestamp is not None


# --------------------------------------------------------------- ForwardNotifier
def test_forward_notifier_posts_payload(config, monkeypatch):
    from sentinelpi.alerts import notifiers as N

    config.cluster.collector_url = "https://collector:8888/api/ingest"
    config.cluster.collector_key = "secret"
    config.cluster.sensor_id = "pi-livingroom"
    config.cluster.forward_min_severity = "low"

    posted = {}

    class _Resp:
        def raise_for_status(self): pass

    def fake_post(url, json=None, headers=None, timeout=None, **kwargs):
        posted.update(url=url, json=json, headers=headers, kwargs=kwargs)
        return _Resp()

    import requests
    monkeypatch.setattr(requests, "post", fake_post)

    fwd = N.ForwardNotifier(config)
    fwd._forward(_alert())  # call worker body directly (no thread timing)

    assert posted["url"] == "https://collector:8888/api/ingest"
    assert posted["headers"]["X-SentinelPi-Collector-Key"] == "secret"
    assert posted["json"]["sensor_id"] == "pi-livingroom"
    assert posted["json"]["alert"]["affected_host"] == "192.168.1.50"
    # Default TLS: verify on (True), no client cert presented.
    assert posted["kwargs"]["verify"] is True
    assert "cert" not in posted["kwargs"]


def test_forward_notifier_mtls_kwargs(config, monkeypatch):
    from sentinelpi.alerts import notifiers as N

    config.cluster.collector_url = "https://collector:8888/api/ingest"
    config.cluster.collector_key = "secret"
    config.cluster.tls_ca_cert = "/etc/sentinelpi/ca.pem"
    config.cluster.tls_client_cert = "/etc/sentinelpi/client.pem"
    config.cluster.tls_client_key = "/etc/sentinelpi/client.key"

    posted = {}

    class _Resp:
        def raise_for_status(self): pass

    def fake_post(url, json=None, headers=None, timeout=None, **kwargs):
        posted.update(kwargs=kwargs)
        return _Resp()

    import requests
    monkeypatch.setattr(requests, "post", fake_post)

    N.ForwardNotifier(config)._forward(_alert())
    # CA bundle becomes verify=; client cert/key become a cert tuple (mutual TLS).
    assert posted["kwargs"]["verify"] == "/etc/sentinelpi/ca.pem"
    assert posted["kwargs"]["cert"] == ("/etc/sentinelpi/client.pem", "/etc/sentinelpi/client.key")


def test_forward_notifier_skips_remote_and_low(config):
    from sentinelpi.alerts import notifiers as N
    config.cluster.collector_url = "https://c/api/ingest"
    config.cluster.forward_min_severity = "high"
    fwd = N.ForwardNotifier(config)

    # below min severity -> not queued
    fwd.send(_alert(severity=Severity.LOW))
    assert fwd._queue.qsize() == 0
    # already a remote alert -> not re-forwarded
    remote = _alert(severity=Severity.CRITICAL)
    remote.extra["sensor"] = "other"
    fwd.send(remote)
    assert fwd._queue.qsize() == 0


def test_forward_notifier_no_url_is_noop(config):
    from sentinelpi.alerts import notifiers as N
    config.cluster.collector_url = ""
    fwd = N.ForwardNotifier(config)
    fwd.send(_alert(severity=Severity.CRITICAL))
    assert fwd._queue.qsize() == 0


# --------------------------------------------------------------- ingest endpoint
@pytest.fixture
def collector(config, db, device_tracker, baseline, alert_manager):
    from sentinelpi.ui.dashboard import FLASK_AVAILABLE, create_app
    if not FLASK_AVAILABLE:
        pytest.skip("Flask not installed")
    config.dashboard.access_token = ""
    config.cluster.collector_key = "shared-key"
    app = create_app(config, db, device_tracker, baseline, alert_manager)
    app.config.update(TESTING=True)
    return app.test_client(), db


def _payload():
    from sentinelpi.alerts.notifiers import BaseNotifier
    return {"sensor_id": "pi-garage", "alert": BaseNotifier._alert_to_dict(None, _alert())}


def test_ingest_requires_collector_key(collector):
    client, _ = collector
    assert client.post("/api/ingest", json=_payload()).status_code == 401
    assert client.post("/api/ingest", json=_payload(),
                       headers={"X-SentinelPi-Collector-Key": "wrong"}).status_code == 401


def test_ingest_saves_and_tags_sensor(collector):
    client, db = collector
    resp = client.post("/api/ingest", json=_payload(),
                       headers={"X-SentinelPi-Collector-Key": "shared-key"})
    assert resp.status_code == 200
    assert resp.get_json()["fired"] is True

    saved = db.get_recent_alerts(limit=10)
    assert len(saved) == 1
    assert saved[0].extra.get("sensor") == "pi-garage"


def test_ingest_rejects_bad_body(collector):
    client, _ = collector
    resp = client.post("/api/ingest", json={"sensor_id": "x"},  # no alert
                       headers={"X-SentinelPi-Collector-Key": "shared-key"})
    assert resp.status_code == 400


def test_ingest_absent_without_collector_key(config, db, device_tracker, baseline, alert_manager):
    from sentinelpi.ui.dashboard import FLASK_AVAILABLE, create_app
    if not FLASK_AVAILABLE:
        pytest.skip("Flask not installed")
    config.dashboard.access_token = ""
    config.cluster.collector_key = ""  # not a collector
    app = create_app(config, db, device_tracker, baseline, alert_manager)
    app.config.update(TESTING=True)
    assert app.test_client().post("/api/ingest", json=_payload()).status_code == 404


# ----------------------------------------------------------- mTLS verified header
@pytest.fixture
def mtls_collector(config, db, device_tracker, baseline, alert_manager):
    from sentinelpi.ui.dashboard import FLASK_AVAILABLE, create_app
    if not FLASK_AVAILABLE:
        pytest.skip("Flask not installed")
    config.dashboard.access_token = ""
    config.cluster.collector_key = "shared-key"
    config.cluster.ingest_require_verified_header = True
    app = create_app(config, db, device_tracker, baseline, alert_manager)
    app.config.update(TESTING=True)
    return app.test_client()


def test_ingest_requires_verified_header_when_enabled(mtls_collector):
    # Right key but no proxy-verified header -> 403 (before the key check).
    resp = mtls_collector.post(
        "/api/ingest", json=_payload(),
        headers={"X-SentinelPi-Collector-Key": "shared-key"},
    )
    assert resp.status_code == 403


def test_ingest_accepts_verified_header(mtls_collector):
    resp = mtls_collector.post(
        "/api/ingest", json=_payload(),
        headers={
            "X-SentinelPi-Collector-Key": "shared-key",
            "X-SentinelPi-Client-Verified": "SUCCESS",
        },
    )
    assert resp.status_code == 200
    assert resp.get_json()["fired"] is True
