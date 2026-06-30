from __future__ import annotations

import json
from datetime import datetime, timezone

from sentinelpi.alerts import siem
from sentinelpi.alerts.notifiers import OTLPNotifier, SyslogNotifier
from sentinelpi.config.manager import Config
from sentinelpi.models import Alert, AlertCategory, Severity


def _alert(**kwargs) -> Alert:
    base = dict(
        timestamp=datetime(2026, 6, 16, 12, 30, tzinfo=timezone.utc),
        severity=Severity.HIGH,
        category=AlertCategory.PORT_SCAN,
        affected_host="192.168.1.50",
        affected_mac="aa:bb:cc:dd:ee:ff",
        related_host="192.168.1.1",
        title="Port scan detected",
        description="Host scanned 40 ports in 30s",
        recommended_action="Investigate the host",
        confidence=0.85,
    )
    base.update(kwargs)
    return Alert(**base)


def test_format_ecs_maps_core_fields():
    doc = siem.format_ecs(_alert(), product_version="1.2.3")

    assert doc["@timestamp"] == "2026-06-16T12:30:00+00:00"
    assert doc["message"] == "Port scan detected"
    assert doc["event"]["id"]
    assert doc["event"]["severity"] == siem.ECS_SEVERITY[Severity.HIGH]
    assert "intrusion_detection" in doc["event"]["category"]
    assert doc["log"]["level"] == "high"
    assert doc["observer"]["product"] == "SentinelPi"
    assert doc["observer"]["version"] == "1.2.3"
    # PORT_SCAN: related_host is the scanner (actor → source); affected_host is the target (→ destination).
    assert doc["source"]["ip"] == "192.168.1.1"
    assert doc["destination"]["ip"] == "192.168.1.50"
    assert doc["sentinelpi"]["recommended_action"] == "Investigate the host"


def test_format_ecs_outbound_alert_standard_mapping():
    """For non-detector categories affected_host is the actor and maps to source."""
    doc = siem.format_ecs(_alert(
        category=AlertCategory.CONNECTION_ANOMALY,
        affected_host="10.0.0.5",
        affected_mac="11:22:33:44:55:66",
        related_host="8.8.8.8",
    ))
    assert doc["source"]["ip"] == "10.0.0.5"
    assert doc["source"]["mac"] == "11:22:33:44:55:66"
    assert doc["destination"]["ip"] == "8.8.8.8"


def test_format_ecs_converts_naive_and_other_tz_to_utc():
    aware = siem.format_ecs(_alert(timestamp=datetime(2026, 6, 16, 14, 30,
                                                       tzinfo=timezone(__import__("datetime").timedelta(hours=2)))))
    assert aware["@timestamp"] == "2026-06-16T12:30:00+00:00"


def test_format_ecs_line_is_valid_json():
    line = siem.format_ecs_line(_alert(extra={"ports": [22, 80]}))
    parsed = json.loads(line)
    assert parsed["sentinelpi"]["extra"]["ports"] == [22, 80]
    assert "\n" not in line


def test_format_cef_header_and_extension():
    line = siem.format_cef(_alert(), product_version="9.9.9")

    assert line.startswith("CEF:0|SentinelPi|SentinelPi|9.9.9|port_scan|Port scan detected|8|")
    # PORT_SCAN: scanner (related_host) is src; scanned target (affected_host) is dst.
    assert "src=192.168.1.1" in line
    assert "dst=192.168.1.50" in line
    assert "cs1=Investigate the host" in line
    assert "cs1Label=recommendedAction" in line


def test_format_cef_lateral_movement_swaps_source_dest():
    line = siem.format_cef(_alert(
        category=AlertCategory.LATERAL_MOVEMENT,
        affected_host="10.0.0.20",   # target
        related_host="10.0.0.5",     # mover/actor
        affected_mac="",
    ))
    assert "src=10.0.0.5" in line
    assert "dst=10.0.0.20" in line


def test_format_cef_escapes_special_characters():
    line = siem.format_cef(_alert(title="weird|name", description="a=b\nc"))
    # Pipe in the header name is escaped...
    assert "weird\\|name" in line
    # ...and '=' / newline in an extension value are escaped.
    assert "msg=a\\=b\\nc" in line


def test_format_syslog_pri_and_frame():
    frame = siem.format_syslog(
        "PAYLOAD",
        severity=Severity.CRITICAL,
        timestamp_iso="2026-06-16T12:30:00+00:00",
        hostname="pi",
        facility="local0",
    )
    # local0 (16) * 8 + critical (2) = 130; RFC 5424: PROCID MSGID STRUCTURED-DATA all '-'
    assert frame == "<130>1 2026-06-16T12:30:00+00:00 pi sentinelpi - - - PAYLOAD"


def _siem_config(**overrides) -> Config:
    config = Config()
    n = config.notifications
    n.siem_enabled = True
    n.siem_host = "10.0.0.5"
    n.siem_port = 514
    for key, value in overrides.items():
        setattr(n, key, value)
    return config


def test_syslog_notifier_respects_min_severity():
    config = _siem_config(siem_min_severity="high")
    notifier = SyslogNotifier(config)
    sent: list[bytes] = []
    notifier._transmit = lambda data: sent.append(data)

    notifier.send(_alert(severity=Severity.LOW))
    notifier.send(_alert(severity=Severity.CRITICAL))
    notifier.close(timeout=2)

    assert len(sent) == 1
    assert not notifier._thread.is_alive()


def test_syslog_notifier_close_drains_queue_with_selected_format():
    config = _siem_config(siem_format="cef")
    notifier = SyslogNotifier(config)
    sent: list[bytes] = []
    notifier._transmit = lambda data: sent.append(data)

    notifier.send(_alert(severity=Severity.HIGH))
    notifier.close(timeout=2)

    assert len(sent) == 1
    assert b"CEF:0|SentinelPi" in sent[0]


def test_syslog_notifier_preflight_uses_transmit():
    config = _siem_config()
    notifier = SyslogNotifier(config)
    sent: list[bytes] = []
    notifier._transmit = lambda data: sent.append(data)

    ok, detail = notifier.preflight()
    notifier.close(timeout=2)

    assert ok is True
    assert sent  # preflight alert was rendered and transmitted
    assert "10.0.0.5:514" in detail


# --- OTLP / OpenTelemetry export ---------------------------------------------

def _otlp_log_record(doc: dict) -> dict:
    return doc["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]


def _otlp_attrs(doc: dict) -> dict:
    return {a["key"]: a["value"] for a in _otlp_log_record(doc)["attributes"]}


def test_format_otlp_envelope_and_severity():
    doc = siem.format_otlp(_alert(), product_version="9.9.9", host_name="pi")
    lr = _otlp_log_record(doc)
    assert lr["severityText"] == "ERROR"  # HIGH -> ERROR band
    assert lr["severityNumber"] == siem.OTLP_SEVERITY_NUMBER[Severity.HIGH]
    assert lr["body"] == {"stringValue": "Port scan detected"}
    # Unix nanoseconds, encoded as a string (OTLP/JSON int64 rule).
    assert lr["timeUnixNano"] == str(int(_alert().timestamp.timestamp() * 1_000_000_000))
    scope = doc["resourceLogs"][0]["scopeLogs"][0]["scope"]
    assert scope["version"] == "9.9.9"


def test_format_otlp_attribute_value_types():
    attrs = _otlp_attrs(siem.format_otlp(_alert(extra={"ports": [22, 80]})))
    # PORT_SCAN: scanner (related_host) → source.ip; target (affected_host) → destination.ip.
    assert attrs["source.ip"] == {"stringValue": "192.168.1.1"}
    assert attrs["destination.ip"] == {"stringValue": "192.168.1.50"}
    assert attrs["sentinelpi.confidence"] == {"doubleValue": 0.85}
    # Nested extra is serialized as a JSON string value.
    assert attrs["sentinelpi.extra"]["stringValue"]
    assert json.loads(attrs["sentinelpi.extra"]["stringValue"]) == {"ports": [22, 80]}


def test_format_otlp_port_scan_source_is_scanner():
    """Detector alert: scanner is source, scanned host is destination in OTLP."""
    attrs = _otlp_attrs(siem.format_otlp(_alert(
        category=AlertCategory.PORT_SCAN,
        affected_host="192.168.1.50",  # target
        related_host="192.168.1.1",    # scanner
    )))
    assert attrs["source.ip"] == {"stringValue": "192.168.1.1"}
    assert attrs["destination.ip"] == {"stringValue": "192.168.1.50"}


def test_format_otlp_resource_attributes():
    doc = siem.format_otlp(_alert(), service_name="sensor-1", host_name="pi-lan")
    res = {a["key"]: a["value"]["stringValue"] for a in doc["resourceLogs"][0]["resource"]["attributes"]}
    assert res["service.name"] == "sensor-1"
    assert res["host.name"] == "pi-lan"


def test_format_otlp_is_json_serializable():
    json.dumps(siem.format_otlp(_alert()))  # must not raise


def _otlp_config(**overrides) -> Config:
    config = Config()
    n = config.notifications
    n.otlp_enabled = True
    n.otlp_endpoint = "http://collector:4318/v1/logs"
    for key, value in overrides.items():
        setattr(n, key, value)
    return config


def test_otlp_notifier_respects_min_severity():
    notifier = OTLPNotifier(_otlp_config(otlp_min_severity="high"))
    exported: list = []
    notifier._export = lambda alert: exported.append(alert.alert_id)

    notifier.send(_alert(severity=Severity.LOW))
    notifier.send(_alert(severity=Severity.CRITICAL))
    notifier.close(timeout=2)

    assert len(exported) == 1
    assert not notifier._thread.is_alive()


def test_otlp_notifier_posts_payload(monkeypatch):
    notifier = OTLPNotifier(_otlp_config(otlp_headers={"Authorization": "Bearer t"}))
    captured = {}

    class _Resp:
        def raise_for_status(self):
            pass

    import requests
    def _fake_post(url, json=None, headers=None, timeout=None):
        captured.update(url=url, json=json, headers=headers, timeout=timeout)
        return _Resp()
    monkeypatch.setattr(requests, "post", _fake_post)

    notifier.send(_alert(severity=Severity.HIGH))
    notifier.close(timeout=2)

    assert captured["url"] == "http://collector:4318/v1/logs"
    assert captured["headers"]["Content-Type"] == "application/json"
    assert captured["headers"]["Authorization"] == "Bearer t"
    assert "resourceLogs" in captured["json"]
