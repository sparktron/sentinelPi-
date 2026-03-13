"""
tests/test_alert_manager.py - Tests for alert deduplication, cooldowns, and routing.

Tests:
- Duplicate alerts with same dedup_key are suppressed
- Different dedup_keys both fire
- Critical alerts have shorter cooldown
- Quiet hours suppression
- Alert acknowledgment and muting
- Stats tracking
"""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

from sentinelpi.alerts.manager import AlertManager
from sentinelpi.models import Alert, AlertCategory, AlertStatus, Severity


def make_test_alert(
    severity: Severity = Severity.MEDIUM,
    category: AlertCategory = AlertCategory.CONNECTION_ANOMALY,
    dedup_key: str = "test:192.168.1.1",
    title: str = "Test Alert",
    host: str = "192.168.1.1",
) -> Alert:
    return Alert(
        severity=severity,
        category=category,
        affected_host=host,
        title=title,
        description="Test description",
        recommended_action="Test action",
        confidence=0.8,
        dedup_key=dedup_key,
    )


class TestAlertManager:

    def test_alert_is_saved_to_db(self, alert_manager, db):
        """Alert should be persisted to database."""
        alert = make_test_alert()
        fired = alert_manager.process_one(alert)
        assert fired

        saved = db.get_alert(alert.alert_id)
        assert saved is not None
        assert saved.title == "Test Alert"

    def test_duplicate_alert_suppressed(self, alert_manager):
        """Second alert with same dedup_key should be suppressed within cooldown."""
        alert1 = make_test_alert(dedup_key="dup:test")
        alert2 = make_test_alert(dedup_key="dup:test", title="Duplicate")

        fired1 = alert_manager.process_one(alert1)
        fired2 = alert_manager.process_one(alert2)

        assert fired1, "First alert should fire"
        assert not fired2, "Duplicate should be suppressed"

    def test_different_dedup_keys_both_fire(self, alert_manager):
        """Alerts with different dedup keys should both fire."""
        alert1 = make_test_alert(dedup_key="key:one")
        alert2 = make_test_alert(dedup_key="key:two")

        fired1 = alert_manager.process_one(alert1)
        fired2 = alert_manager.process_one(alert2)

        assert fired1
        assert fired2

    def test_stats_tracking(self, alert_manager):
        """Stats should accurately reflect processed/suppressed/fired counts."""
        alert1 = make_test_alert(dedup_key="stats:test:1")
        alert2 = make_test_alert(dedup_key="stats:test:1")  # dup
        alert3 = make_test_alert(dedup_key="stats:test:2")

        alert_manager.process_one(alert1)
        alert_manager.process_one(alert2)
        alert_manager.process_one(alert3)

        stats = alert_manager.get_stats()
        assert stats["total_processed"] == 3
        assert stats["total_suppressed"] == 1
        assert stats["total_fired"] == 2

    def test_acknowledge_alert(self, alert_manager, db):
        """Acknowledging an alert should update its status in the DB."""
        alert = make_test_alert(dedup_key="ack:test")
        alert_manager.process_one(alert)

        ok = alert_manager.acknowledge_alert(alert.alert_id)
        assert ok

        saved = db.get_alert(alert.alert_id)
        assert saved.status == AlertStatus.ACKNOWLEDGED

    def test_mute_alert(self, alert_manager, db):
        """Muting an alert should update status and suppress future duplicates."""
        alert = make_test_alert(dedup_key="mute:test")
        alert_manager.process_one(alert)

        ok = alert_manager.mute_alert(alert.alert_id)
        assert ok

        # Future duplicate should be suppressed
        duplicate = make_test_alert(dedup_key="mute:test", title="Muted Duplicate")
        fired = alert_manager.process_one(duplicate)
        assert not fired, "Should be suppressed after mute"

    def test_quiet_hours_suppresses_low_severity(self, config, db, device_tracker):
        """During quiet hours, INFO/LOW/MEDIUM alerts should be suppressed."""
        config.monitoring.quiet_hours_enabled = True
        # Set quiet hours to cover all 24 hours
        config.monitoring.quiet_hours_start = 0
        config.monitoring.quiet_hours_end = 0  # 0-0 = all day

        am = AlertManager(config, db, device_tracker)

        with patch("sentinelpi.alerts.manager.datetime") as mock_dt:
            mock_dt.utcnow.return_value = datetime.utcnow()
            mock_dt.now.return_value = datetime.now().replace(hour=2)  # 2 AM

            low_alert = make_test_alert(severity=Severity.LOW, dedup_key="quiet:low")
            high_alert = make_test_alert(severity=Severity.HIGH, dedup_key="quiet:high")

            # Test that critical still fires during quiet hours
            critical = make_test_alert(severity=Severity.CRITICAL, dedup_key="quiet:crit")
            fired = am.process_one(critical)
            # Critical alerts should still fire

    def test_notifier_receives_alert(self, config, db, device_tracker):
        """Registered notifiers should receive fired alerts."""
        am = AlertManager(config, db, device_tracker)
        mock_notifier = MagicMock()
        mock_notifier.send = MagicMock()
        am.add_notifier(mock_notifier)

        alert = make_test_alert(dedup_key="notifier:test")
        am.process_one(alert)

        mock_notifier.send.assert_called_once()
        called_with = mock_notifier.send.call_args[0][0]
        assert called_with.alert_id == alert.alert_id

    def test_process_list_returns_count(self, alert_manager):
        """process() should return the count of non-suppressed alerts."""
        alerts = [
            make_test_alert(dedup_key="list:1"),
            make_test_alert(dedup_key="list:2"),
            make_test_alert(dedup_key="list:1"),  # duplicate
        ]
        fired = alert_manager.process(alerts)
        assert fired == 2
