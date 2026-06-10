from __future__ import annotations

from datetime import datetime, timezone

from sentinelpi.alerts.notifiers import EmailNotifier
from sentinelpi.alerts.manager import AlertManager
from sentinelpi.config.manager import Config, NotificationConfig
from sentinelpi.models import Alert, AlertCategory, Severity


class _FakeSMTP:
    sent_messages = []

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def ehlo(self):
        pass

    def login(self, username, password):
        pass

    def send_message(self, msg):
        self.sent_messages.append(msg)


def test_email_notifier_does_not_append_z_to_aware_timestamp(monkeypatch):
    import smtplib

    _FakeSMTP.sent_messages = []
    monkeypatch.setattr(smtplib, "SMTP", _FakeSMTP)

    notifier = EmailNotifier.__new__(EmailNotifier)
    notifier._config = NotificationConfig(email_to=["ops@example.com"])

    alert = Alert(
        timestamp=datetime(2026, 6, 10, 12, 30, tzinfo=timezone.utc),
        severity=Severity.HIGH,
        category=AlertCategory.SYSTEM,
        affected_host="localhost",
        title="Test",
        description="Body",
        recommended_action="Act",
    )

    notifier._send_email(alert)

    body = _FakeSMTP.sent_messages[0].get_payload(decode=True).decode("utf-8")
    assert "Time: 2026-06-10T12:30:00+00:00\n" in body
    assert "+00:00Z" not in body


def test_webhook_notifier_close_drains_queue():
    from sentinelpi.alerts.notifiers import WebhookNotifier

    config = Config()
    config.notifications.webhook_enabled = True
    config.notifications.webhook_url = "https://collector.example/webhook"
    delivered = []

    notifier = WebhookNotifier(config)
    notifier._post_webhook = lambda alert: delivered.append(alert.alert_id)
    alert = Alert(severity=Severity.MEDIUM, category=AlertCategory.SYSTEM, title="Queued")

    notifier.send(alert)
    notifier.close(timeout=2)

    assert delivered == [alert.alert_id]
    assert not notifier._thread.is_alive()


def test_alert_manager_closes_registered_notifiers(config, db, device_tracker):
    class _Closeable:
        closed = False

        def send(self, alert):
            pass

        def close(self, timeout=5.0):
            self.closed = True

    notifier = _Closeable()
    manager = AlertManager(config, db, device_tracker)
    manager.add_notifier(notifier)

    manager.close_notifiers(timeout=0.1)

    assert notifier.closed
