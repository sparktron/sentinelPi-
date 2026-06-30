"""
alerts/siem.py - SIEM-friendly serialization for alerts.

Pure, socket-free formatters that turn an :class:`Alert` into the wire
representations security information and event management (SIEM) platforms
expect:

- ``format_ecs``  - Elastic Common Schema (ECS) JSON document (Elastic, Splunk).
- ``format_cef``  - ArcSight Common Event Format (CEF) line (QRadar, ArcSight).
- ``format_syslog`` - wraps a payload in an RFC 5424 syslog frame.

Keeping these as standalone functions makes the field mappings easy to unit
test without opening a socket; :class:`SyslogNotifier` composes them and ships
the result over UDP/TCP.
"""

from __future__ import annotations

import json
from datetime import timezone

from ..models import Alert, AlertCategory, Severity

# Alert categories where affected_host is the victim/target and related_host is
# the actor (scanner, mover). SIEM "source" should map to the actor so downstream
# triage identifies the attacker, not the scanned target, as the initiator.
_ACTOR_IN_RELATED: frozenset[AlertCategory] = frozenset({
    AlertCategory.PORT_SCAN,
    AlertCategory.LATERAL_MOVEMENT,
})


def _siem_source_dest(alert: Alert) -> tuple[str, str, str]:
    """Return (source_ip, source_mac, destination_ip) with correct actor semantics.

    For PORT_SCAN and LATERAL_MOVEMENT alerts the scanner/mover lives in
    related_host and the target in affected_host — invert so SIEMs see the
    attacker as source and the victim as destination.
    """
    if alert.category in _ACTOR_IN_RELATED and alert.related_host:
        return alert.related_host, "", alert.affected_host
    return alert.affected_host, alert.affected_mac, alert.related_host

# Severity -> RFC 5424 syslog severity code (lower is more severe).
SYSLOG_SEVERITY: dict[Severity, int] = {
    Severity.INFO:     6,   # informational
    Severity.LOW:      5,   # notice
    Severity.MEDIUM:   4,   # warning
    Severity.HIGH:     3,   # error
    Severity.CRITICAL: 2,   # critical
}

# Severity -> CEF severity (0-10 scale).
CEF_SEVERITY: dict[Severity, int] = {
    Severity.INFO:     1,
    Severity.LOW:      3,
    Severity.MEDIUM:   5,
    Severity.HIGH:     8,
    Severity.CRITICAL: 10,
}

# Severity -> numeric ECS ``event.severity``.
ECS_SEVERITY: dict[Severity, int] = {
    Severity.INFO:     1,
    Severity.LOW:      3,
    Severity.MEDIUM:   5,
    Severity.HIGH:     7,
    Severity.CRITICAL: 9,
}

# Severity -> OpenTelemetry SeverityNumber (1-24) and SeverityText. OTLP bands:
# TRACE 1-4, DEBUG 5-8, INFO 9-12, WARN 13-16, ERROR 17-20, FATAL 21-24.
OTLP_SEVERITY_NUMBER: dict[Severity, int] = {
    Severity.INFO:     9,    # INFO
    Severity.LOW:      11,   # INFO3
    Severity.MEDIUM:   13,   # WARN
    Severity.HIGH:     17,   # ERROR
    Severity.CRITICAL: 21,   # FATAL
}
OTLP_SEVERITY_TEXT: dict[Severity, str] = {
    Severity.INFO:     "INFO",
    Severity.LOW:      "INFO",
    Severity.MEDIUM:   "WARN",
    Severity.HIGH:     "ERROR",
    Severity.CRITICAL: "FATAL",
}

# Named syslog facilities operators are likely to route to a SIEM.
SYSLOG_FACILITIES: dict[str, int] = {
    "user":   1,
    "daemon": 3,
    "local0": 16,
    "local1": 17,
    "local2": 18,
    "local3": 19,
    "local4": 20,
    "local5": 21,
    "local6": 22,
    "local7": 23,
}

# ECS ``event.category`` keyword(s) per alert category, drawn from the ECS
# allowed-values set so dashboards built on the schema can filter cleanly.
_ECS_CATEGORY: dict[AlertCategory, list[str]] = {
    AlertCategory.ARP_ANOMALY:        ["network"],
    AlertCategory.NEW_DEVICE:         ["host"],
    AlertCategory.PORT_SCAN:          ["network", "intrusion_detection"],
    AlertCategory.BEACON:             ["network", "intrusion_detection"],
    AlertCategory.CONNECTION_ANOMALY: ["network"],
    AlertCategory.DNS_ANOMALY:        ["network"],
    AlertCategory.LATERAL_MOVEMENT:   ["network", "intrusion_detection"],
    AlertCategory.AUTH_ANOMALY:       ["authentication"],
    AlertCategory.TRAFFIC_SPIKE:      ["network"],
    AlertCategory.PROCESS_ANOMALY:    ["process"],
    AlertCategory.THREAT_INTEL:       ["threat", "intrusion_detection"],
    AlertCategory.HONEYPOT:           ["intrusion_detection"],
    AlertCategory.INCIDENT:           ["intrusion_detection"],
    AlertCategory.SYSTEM:             ["host"],
}


def _aware_utc_iso(alert: Alert) -> str:
    """Return the alert timestamp as a UTC ISO-8601 string."""
    ts = alert.timestamp
    if ts.tzinfo is None:
        return ts.isoformat()
    return ts.astimezone(timezone.utc).isoformat()


def format_ecs(alert: Alert, *, product_version: str = "1.0.0") -> dict:
    """Render an alert as an Elastic Common Schema (ECS) document."""
    doc: dict = {
        "@timestamp": _aware_utc_iso(alert),
        "message": alert.title,
        "ecs": {"version": "8.11.0"},
        "event": {
            "id": alert.alert_id,
            "kind": "alert",
            "category": _ECS_CATEGORY.get(alert.category, ["network"]),
            "type": ["info"],
            "action": alert.category.value,
            "severity": ECS_SEVERITY.get(alert.severity, 1),
            "reason": alert.description,
            "module": "sentinelpi",
            "dataset": "sentinelpi.alert",
        },
        "log": {"level": alert.severity.value},
        "observer": {
            "vendor": "SentinelPi",
            "product": "SentinelPi",
            "type": "ids",
            "version": product_version,
        },
        "rule": {"name": alert.category.value, "ruleset": "sentinelpi"},
        "sentinelpi": {
            "confidence": round(alert.confidence, 3),
            "confidence_rationale": alert.confidence_rationale,
            "recommended_action": alert.recommended_action,
            "dedup_key": alert.dedup_key,
        },
    }
    src_ip, src_mac, dst_ip = _siem_source_dest(alert)
    if src_ip:
        doc["source"] = {"ip": src_ip}
        doc["host"] = {"ip": alert.affected_host}
        if src_mac:
            doc["source"]["mac"] = src_mac
    if src_mac and "source" not in doc:
        doc["host"] = {"mac": src_mac}
    if dst_ip:
        doc["destination"] = {"ip": dst_ip}
    if alert.extra:
        doc["sentinelpi"]["extra"] = alert.extra
    return doc


def format_ecs_line(alert: Alert, *, product_version: str = "1.0.0") -> str:
    """ECS document as a single compact JSON line."""
    return json.dumps(format_ecs(alert, product_version=product_version), default=str)


def _cef_escape_header(value: str) -> str:
    """Escape a CEF header field (backslash and pipe)."""
    return value.replace("\\", "\\\\").replace("|", "\\|")


def _cef_escape_ext(value: str) -> str:
    """Escape a CEF extension value (backslash, equals, newlines)."""
    return (
        value.replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\n", "\\n")
        .replace("\r", "\\n")
    )


def format_cef(alert: Alert, *, product_version: str = "1.0.0") -> str:
    """Render an alert as an ArcSight Common Event Format (CEF) line."""
    header = "|".join(
        _cef_escape_header(part)
        for part in (
            "CEF:0",
            "SentinelPi",
            "SentinelPi",
            product_version,
            alert.category.value,
            alert.title or alert.category.value,
            str(CEF_SEVERITY.get(alert.severity, 1)),
        )
    )

    # Extension key/value pairs. Use standard CEF keys where they exist and
    # custom string/number labels (cs1/cn1...) for SentinelPi-specific context.
    pairs: list[tuple[str, str]] = [
        ("externalId", alert.alert_id),
        ("rt", _aware_utc_iso(alert)),
        ("cat", alert.category.value),
    ]
    src_ip, src_mac, dst_ip = _siem_source_dest(alert)
    if src_ip:
        pairs.append(("src", src_ip))
    if src_mac:
        pairs.append(("smac", src_mac))
    if dst_ip:
        pairs.append(("dst", dst_ip))
    if alert.description:
        pairs.append(("msg", alert.description))
    pairs.append(("cn1", str(round(alert.confidence, 3))))
    pairs.append(("cn1Label", "confidence"))
    if alert.recommended_action:
        pairs.append(("cs1", alert.recommended_action))
        pairs.append(("cs1Label", "recommendedAction"))

    extension = " ".join(f"{key}={_cef_escape_ext(value)}" for key, value in pairs)
    return f"{header}|{extension}"


def format_syslog(
    payload: str,
    *,
    severity: Severity,
    timestamp_iso: str,
    hostname: str,
    app_name: str = "sentinelpi",
    facility: str = "local0",
    procid: str = "-",
) -> str:
    """
    Wrap a payload in an RFC 5424 syslog frame.

    PRI = facility * 8 + severity. The structured-data field is left empty
    (``-``); the ECS/CEF payload carries the structured content.
    """
    fac = SYSLOG_FACILITIES.get(facility, 16)
    sev = SYSLOG_SEVERITY.get(severity, 5)
    pri = fac * 8 + sev
    host = hostname or "-"
    return f"<{pri}>1 {timestamp_iso} {host} {app_name} {procid} - - {payload}"


def _otlp_any_value(value) -> dict:
    """Wrap a Python scalar as an OTLP AnyValue (JSON/HTTP encoding)."""
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}  # OTLP/JSON encodes int64 as a string
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, str):
        return {"stringValue": value}
    return {"stringValue": json.dumps(value, default=str)}


def _otlp_attributes(mapping: dict) -> list:
    """Build an OTLP KeyValue list, skipping empty/None values."""
    out = []
    for key, value in mapping.items():
        if value is None or value == "":
            continue
        out.append({"key": key, "value": _otlp_any_value(value)})
    return out


def _unix_nanos(alert: Alert) -> str:
    """Alert timestamp as Unix nanoseconds (string, per OTLP/JSON int64 rules)."""
    return str(int(alert.timestamp.timestamp() * 1_000_000_000))


def format_otlp(
    alert: Alert,
    *,
    service_name: str = "sentinelpi",
    product_version: str = "1.0.0",
    host_name: str = "",
) -> dict:
    """
    Render an alert as an OpenTelemetry OTLP/HTTP JSON ``LogsData`` envelope
    (one ``resourceLogs`` -> ``scopeLogs`` -> ``logRecords`` entry), ready to
    POST to an OTLP logs endpoint (``/v1/logs``).
    """
    nanos = _unix_nanos(alert)
    src_ip, src_mac, dst_ip = _siem_source_dest(alert)
    log_record = {
        "timeUnixNano": nanos,
        "observedTimeUnixNano": nanos,
        "severityNumber": OTLP_SEVERITY_NUMBER.get(alert.severity, 9),
        "severityText": OTLP_SEVERITY_TEXT.get(alert.severity, "INFO"),
        "body": {"stringValue": alert.title},
        "attributes": _otlp_attributes({
            "event.id": alert.alert_id,
            "event.category": alert.category.value,
            "event.action": alert.category.value,
            "event.severity": alert.severity.value,
            "source.ip": src_ip,
            "source.mac": src_mac,
            "destination.ip": dst_ip,
            "sentinelpi.confidence": round(alert.confidence, 3),
            "sentinelpi.confidence_rationale": alert.confidence_rationale,
            "sentinelpi.recommended_action": alert.recommended_action,
            "sentinelpi.dedup_key": alert.dedup_key,
            "sentinelpi.description": alert.description,
            "sentinelpi.extra": alert.extra or None,
        }),
    }
    resource_attrs = _otlp_attributes({
        "service.name": service_name,
        "service.version": product_version,
        "host.name": host_name,
    })
    return {
        "resourceLogs": [
            {
                "resource": {"attributes": resource_attrs},
                "scopeLogs": [
                    {
                        "scope": {"name": "sentinelpi", "version": product_version},
                        "logRecords": [log_record],
                    }
                ],
            }
        ]
    }
