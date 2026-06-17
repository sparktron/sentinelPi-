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
    if alert.affected_host:
        doc["source"] = {"ip": alert.affected_host}
        doc["host"] = {"ip": alert.affected_host}
        if alert.affected_mac:
            doc["source"]["mac"] = alert.affected_mac
    if alert.affected_mac and "source" not in doc:
        doc["host"] = {"mac": alert.affected_mac}
    if alert.related_host:
        doc["destination"] = {"ip": alert.related_host}
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
    if alert.affected_host:
        pairs.append(("src", alert.affected_host))
    if alert.affected_mac:
        pairs.append(("smac", alert.affected_mac))
    if alert.related_host:
        pairs.append(("dst", alert.related_host))
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
