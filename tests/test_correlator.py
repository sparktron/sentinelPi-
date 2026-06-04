"""
tests/test_correlator.py - Incident correlation (Phase 3).

Verifies the IncidentCorrelator escalates an actor seen across enough sensors or
hitting enough targets into one INCIDENT alert, the window/cooldown behavior,
loop-prevention, and that AlertManager raises the incident through the pipeline.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from sentinelpi.alerts.correlator import IncidentCorrelator
from sentinelpi.models import Alert, AlertCategory, Severity
from sentinelpi.utils import clock


def _alert(actor="192.168.1.66", target="", sensor=None,
           category=AlertCategory.PORT_SCAN, severity=Severity.MEDIUM):
    a = Alert(severity=severity, category=category, affected_host=actor,
              related_host=target, title="t", description="d")
    if sensor is not None:
        a.extra["sensor"] = sensor
    return a


@pytest.fixture
def correlator(config):
    config.correlation.enabled = True
    config.correlation.window_seconds = 300
    config.correlation.min_sensors = 2
    config.correlation.min_targets = 5
    config.correlation.cooldown_seconds = 600
    return IncidentCorrelator(config)


def test_no_incident_below_thresholds(correlator):
    assert correlator.observe(_alert(sensor="pi-a")) is None
    assert correlator.observe(_alert(sensor="pi-a")) is None  # same sensor, no targets


def test_incident_across_sensors(correlator):
    assert correlator.observe(_alert(sensor="pi-a")) is None
    incident = correlator.observe(_alert(sensor="pi-b"))  # 2nd distinct sensor
    assert incident is not None
    assert incident.category == AlertCategory.INCIDENT
    assert incident.affected_host == "192.168.1.66"
    assert set(incident.extra["sensors"]) == {"pi-a", "pi-b"}


def test_incident_across_targets(correlator):
    inc = None
    for i in range(5):  # 5 distinct targets, single sensor
        inc = correlator.observe(_alert(target=f"10.0.0.{i}", sensor="pi-a"))
    assert inc is not None
    assert inc.extra["target_count"] == 5


def test_incident_cooldown(correlator):
    correlator.observe(_alert(sensor="pi-a"))
    first = correlator.observe(_alert(sensor="pi-b"))
    assert first is not None
    # Still over threshold, but within cooldown -> no duplicate incident.
    assert correlator.observe(_alert(sensor="pi-c")) is None


def test_window_pruning(config):
    config.correlation.enabled = True
    config.correlation.window_seconds = 60
    config.correlation.min_sensors = 2
    config.correlation.min_targets = 99
    corr = IncidentCorrelator(config)

    old = clock.FixedClock(clock.now() - timedelta(seconds=120))
    with clock.use_clock(old):
        assert corr.observe(_alert(sensor="pi-a")) is None  # ages out of window
    # Now (real clock): only one in-window sensor -> no incident.
    assert corr.observe(_alert(sensor="pi-b")) is None


def test_incident_alerts_are_not_recorrelated(correlator):
    incident = _alert(category=AlertCategory.INCIDENT)
    assert correlator.observe(incident) is None


def test_no_actor_is_ignored(correlator):
    assert correlator.observe(_alert(actor="", target="")) is None


def test_alert_manager_raises_incident(config, db, device_tracker):
    from sentinelpi.alerts.manager import AlertManager
    config.correlation.enabled = True
    config.correlation.min_sensors = 2
    am = AlertManager(config, db, device_tracker)

    captured = []
    notifier = type("N", (), {"send": lambda self, a: captured.append(a)})()
    am.add_notifier(notifier)

    # Distinct alerts (distinct dedup keys) from two sensors for the same actor.
    a1 = _alert(sensor="pi-a", category=AlertCategory.PORT_SCAN)
    a1.dedup_key = "scan:pi-a"
    a2 = _alert(sensor="pi-b", category=AlertCategory.PORT_SCAN)
    a2.dedup_key = "scan:pi-b"
    am.process_one(a1)
    am.process_one(a2)

    # An INCIDENT alert should have been generated and fired through the pipeline.
    assert any(a.category == AlertCategory.INCIDENT for a in captured)
    saved = db.get_recent_alerts(limit=20)
    assert any(a.category == AlertCategory.INCIDENT for a in saved)
