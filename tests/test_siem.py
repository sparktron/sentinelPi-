from __future__ import annotations

import json
from datetime import datetime, timezone

from sentinelpi.alerts import siem
from sentinelpi.alerts.notifiers import SyslogNotifier
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
    assert doc["source"]["ip"] == "192.168.1.50"
    assert doc["source"]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert doc["destination"]["ip"] == "192.168.1.1"
    assert doc["sentinelpi"]["recommended_action"] == "Investigate the host"


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
    assert "src=192.168.1.50" in line
    assert "smac=aa:bb:cc:dd:ee:ff" in line
    assert "dst=192.168.1.1" in line
    assert "cs1=Investigate the host" in line
    assert "cs1Label=recommendedAction" in line


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
