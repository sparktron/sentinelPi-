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


def _ntfy_config():
    config = Config()
    n = config.notifications
    n.ntfy_enabled = True
    n.ntfy_server = "https://ntfy.example"
    n.ntfy_topic = "sentinel-secret"
    n.ntfy_dashboard_url = "https://pi.lan:8888/"
    n.ntfy_dashboard_token = "tok-123"
    n.ntfy_min_severity = "medium"
    return config


def test_ntfy_send_filters_below_min_severity():
    from sentinelpi.alerts.notifiers import NtfyNotifier

    notifier = NtfyNotifier(_ntfy_config())
    captured = []
    notifier._publish = lambda payload: captured.append(payload)

    notifier.send(Alert(severity=Severity.LOW, category=AlertCategory.SYSTEM, title="Quiet"))
    notifier.send(Alert(severity=Severity.HIGH, category=AlertCategory.SYSTEM,
                        title="Loud", affected_host="10.0.0.5"))
    notifier.close(timeout=2)

    assert len(captured) == 1
    assert captured[0]["topic"] == "sentinel-secret"
    assert "Loud" in captured[0]["title"]
    assert captured[0]["priority"] == 4
    assert not notifier._thread.is_alive()


def test_ntfy_notify_pending_attaches_approval_buttons():
    from sentinelpi.alerts.notifiers import NtfyNotifier
    from sentinelpi.responders.base import ResponderAction

    notifier = NtfyNotifier(_ntfy_config())
    captured = []
    notifier._publish = lambda payload: captured.append(payload)

    action = ResponderAction(
        responder="FirewallResponder",
        target="10.0.0.9",
        description="Block 10.0.0.9",
        action_id="act-42",
    )
    notifier.notify_pending(action)
    notifier.close(timeout=2)

    assert len(captured) == 1
    actions = captured[0]["actions"]
    labels = {a["label"]: a for a in actions}
    assert set(labels) == {"Approve", "Reject"}
    assert labels["Approve"]["url"] == "https://pi.lan:8888/api/responses/act-42/approve"
    assert labels["Reject"]["url"] == "https://pi.lan:8888/api/responses/act-42/reject"
    assert labels["Approve"]["method"] == "POST"
    assert labels["Approve"]["headers"]["Authorization"] == "Bearer tok-123"


def test_ntfy_notify_pending_omits_buttons_without_dashboard_creds():
    from sentinelpi.alerts.notifiers import NtfyNotifier
    from sentinelpi.responders.base import ResponderAction

    config = _ntfy_config()
    config.notifications.ntfy_dashboard_token = ""  # no creds → no buttons
    notifier = NtfyNotifier(config)
    captured = []
    notifier._publish = lambda payload: captured.append(payload)

    notifier.notify_pending(ResponderAction(
        responder="FirewallResponder", target="10.0.0.9", description="Block"))
    notifier.close(timeout=2)

    assert len(captured) == 1
    assert "actions" not in captured[0]


def test_ntfy_disabled_sends_nothing():
    from sentinelpi.alerts.notifiers import NtfyNotifier

    config = _ntfy_config()
    config.notifications.ntfy_enabled = False
    notifier = NtfyNotifier(config)
    captured = []
    notifier._publish = lambda payload: captured.append(payload)

    notifier.send(Alert(severity=Severity.CRITICAL, category=AlertCategory.SYSTEM, title="X"))
    notifier.close(timeout=2)

    assert captured == []


def test_responder_manager_fires_pending_notifier():
    from sentinelpi.responders.manager import ResponderManager
    from sentinelpi.responders.base import BaseResponder, ResponderAction

    config = Config()
    config.response.enabled = True
    config.response.dry_run = False
    config.response.require_approval = True

    class _StubResponder(BaseResponder):
        def can_handle(self, alert):
            return True

        def plan(self, alert):
            return ResponderAction(responder="StubResponder", target="10.0.0.9",
                                   description="Block it")

        def execute(self, action):
            action.executed = True
            action.success = True

    manager = ResponderManager(config)
    manager.add_responder(_StubResponder(config))
    notified = []
    manager.set_pending_notifier(notified.append)

    actions = manager.handle(Alert(severity=Severity.HIGH, category=AlertCategory.PORT_SCAN,
                                   title="scan", affected_host="10.0.0.9"))

    assert len(actions) == 1
    assert len(notified) == 1
    assert notified[0].action_id == actions[0].action_id
    assert actions[0].status == "pending"


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
