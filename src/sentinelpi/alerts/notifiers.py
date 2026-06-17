"""
alerts/notifiers.py - Alert output channels.

Each notifier receives an Alert and delivers it via its channel.
Notifiers should be fast and non-blocking; use internal queues for
channels that may have latency (email, webhook).

Available notifiers:
- ConsoleNotifier: Colored terminal output.
- FileNotifier: Rotating log file in JSON Lines format.
- EmailNotifier: SMTP email (optional).
- WebhookNotifier: HTTP POST to a URL (optional).
- NtfyNotifier: ntfy push with Approve/Reject action buttons (optional).
- TwilioSMSNotifier: SMS via Twilio Programmable Messaging (optional).
- SyslogNotifier: SIEM export over syslog in ECS or CEF format (optional).
"""

from __future__ import annotations

import json
import logging
import queue
import smtplib
import socket
import threading
from abc import ABC, abstractmethod
from email.mime.text import MIMEText
from logging.handlers import RotatingFileHandler
from pathlib import Path

from ..models import Alert, AlertCategory, Severity
from ..config.manager import Config

logger = logging.getLogger(__name__)


def _preflight_alert() -> Alert:
    """A harmless INFO alert used to exercise a notifier during ``--check``."""
    return Alert(
        severity=Severity.INFO,
        category=AlertCategory.SYSTEM,
        title="SentinelPi preflight check",
        description="Test notification from `sentinelpi --check`. Safe to ignore.",
        recommended_action="No action needed.",
    )

# ANSI color codes for terminal output
_COLORS = {
    Severity.INFO:     "\033[36m",     # Cyan
    Severity.LOW:      "\033[32m",     # Green
    Severity.MEDIUM:   "\033[33m",     # Yellow
    Severity.HIGH:     "\033[31m",     # Red
    Severity.CRITICAL: "\033[1;31m",   # Bold Red
}
_RESET = "\033[0m"


class BaseNotifier(ABC):
    """Abstract base for all alert notifiers."""

    @abstractmethod
    def send(self, alert: Alert) -> None:
        """Deliver the alert. Must be thread-safe."""
        ...

    def close(self, timeout: float = 5.0) -> None:
        """Release resources and stop background workers, if any."""
        return None

    def preflight(self) -> tuple[bool, str]:
        """
        Actively exercise this notifier's channel for ``sentinelpi --check``.

        Returns ``(ok, detail)``. The default is a no-op for channels with
        nothing to probe (console, file). Network notifiers override this to
        test connectivity/credentials, which may deliver a test notification.
        """
        return (True, "no active check")

    def _alert_to_dict(self, alert: Alert) -> dict:
        """Convert an Alert to a JSON-serializable dict."""
        return {
            "alert_id": alert.alert_id,
            "timestamp": alert.timestamp.isoformat(),
            "severity": alert.severity.value,
            "category": alert.category.value,
            "affected_host": alert.affected_host,
            "affected_mac": alert.affected_mac,
            "related_host": alert.related_host,
            "title": alert.title,
            "description": alert.description,
            "recommended_action": alert.recommended_action,
            "confidence": round(alert.confidence, 3),
            "confidence_rationale": alert.confidence_rationale,
            "dedup_key": alert.dedup_key,
            "extra": alert.extra,
        }


class ConsoleNotifier(BaseNotifier):
    """
    Prints alerts to stdout with ANSI color coding by severity.

    Safe to use as the primary output channel for interactive use.
    """

    def __init__(self, min_severity: Severity = Severity.INFO) -> None:
        self.min_severity = min_severity
        self._lock = threading.Lock()

    def send(self, alert: Alert) -> None:
        if alert.severity < self.min_severity:
            return

        color = _COLORS.get(alert.severity, "")
        ts = alert.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        host_str = f" [{alert.affected_host}]" if alert.affected_host else ""

        with self._lock:
            print(
                f"{color}[{ts}] [{alert.severity.value.upper():8}] "
                f"[{alert.category.value}]{host_str} {alert.title}{_RESET}"
            )
            if alert.description:
                print(f"  {alert.description}")
            if alert.recommended_action:
                print(f"  → {alert.recommended_action}")


class FileNotifier(BaseNotifier):
    """
    Writes alerts as JSON Lines to a rotating file.

    Each line is a complete JSON object — easy to parse with jq or import
    into log management systems.
    """

    def __init__(
        self,
        log_path: str,
        min_severity: Severity = Severity.INFO,
        max_bytes: int = 10_485_760,
        backup_count: int = 5,
    ) -> None:
        self.min_severity = min_severity
        self._lock = threading.Lock()

        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        self._handler = RotatingFileHandler(
            log_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )

    def send(self, alert: Alert) -> None:
        if alert.severity < self.min_severity:
            return
        try:
            line = json.dumps(self._alert_to_dict(alert), default=str)
            with self._lock:
                self._handler.stream.write(line + "\n")
                self._handler.stream.flush()
                # Size-based rollover. RotatingFileHandler.shouldRollover needs a
                # LogRecord (we have none), so check the byte budget directly.
                if self._handler.maxBytes > 0 and self._handler.stream.tell() >= self._handler.maxBytes:
                    self._handler.doRollover()
        except Exception as exc:
            logger.error("FileNotifier write failed: %s", exc)

    def close(self, timeout: float = 5.0) -> None:
        with self._lock:
            self._handler.close()


class EmailNotifier(BaseNotifier):
    """
    Sends email alerts via SMTP.

    Uses a background thread to avoid blocking the alert pipeline on
    network latency. Emails are queued and sent in a worker thread.
    """

    def __init__(self, config: Config) -> None:
        self._config = config.notifications
        self._min_severity = Severity(self._config.email_min_severity)
        import queue as q_module
        self._queue: "q_module.Queue[Alert]" = q_module.Queue(maxsize=100)
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._worker, daemon=True, name="EmailNotifier")
        self._thread.start()

    def send(self, alert: Alert) -> None:
        if not self._config.email_enabled:
            return
        if alert.severity < self._min_severity:
            return
        if self._stop_event.is_set():
            logger.warning("Email notifier is stopping — dropping alert notification.")
            return
        try:
            self._queue.put_nowait(alert)
        except Exception:
            logger.warning("Email queue full — dropping alert notification.")

    def _worker(self) -> None:
        """Background thread that drains the email queue."""
        while not self._stop_event.is_set() or not self._queue.empty():
            try:
                alert = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._send_email(alert)
            except Exception as exc:
                logger.warning("Email notification failed: %s", exc)

    def close(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        if self._thread.is_alive():
            logger.warning("Email notifier did not stop cleanly.")

    def preflight(self) -> tuple[bool, str]:
        if not self._config.email_enabled:
            return (True, "disabled")
        host, port = self._config.email_smtp_host, self._config.email_smtp_port
        try:
            if self._config.email_smtp_tls:
                smtp: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=10)
            else:
                smtp = smtplib.SMTP(host, port, timeout=10)
            try:
                smtp.ehlo()
                if self._config.email_username:
                    smtp.login(self._config.email_username, self._config.email_password)
                smtp.noop()
            finally:
                smtp.quit()
        except Exception as exc:
            return (False, f"SMTP {host}:{port}: {exc}")
        authed = " (auth OK)" if self._config.email_username else ""
        return (True, f"connected to SMTP {host}:{port}{authed}; no message sent")

    def _send_email(self, alert: Alert) -> None:
        """Send a single alert email."""
        subject = f"[SentinelPi] [{alert.severity.value.upper()}] {alert.title}"
        body = (
            f"SentinelPi Alert\n"
            f"{'='*60}\n"
            f"Severity: {alert.severity.value.upper()}\n"
            f"Category: {alert.category.value}\n"
            f"Host: {alert.affected_host}\n"
            f"Time: {alert.timestamp.isoformat()}\n\n"
            f"Title: {alert.title}\n\n"
            f"Description:\n{alert.description}\n\n"
            f"Recommended Action:\n{alert.recommended_action}\n\n"
            f"Confidence: {alert.confidence:.0%} — {alert.confidence_rationale}\n"
        )

        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = self._config.email_from
        msg["To"] = ", ".join(self._config.email_to)

        try:
            if self._config.email_smtp_tls:
                with smtplib.SMTP_SSL(
                    self._config.email_smtp_host,
                    self._config.email_smtp_port,
                    timeout=10,
                ) as smtp:
                    if self._config.email_username:
                        smtp.login(self._config.email_username, self._config.email_password)
                    smtp.send_message(msg)
            else:
                with smtplib.SMTP(
                    self._config.email_smtp_host,
                    self._config.email_smtp_port,
                    timeout=10,
                ) as smtp:
                    smtp.ehlo()
                    if self._config.email_smtp_tls:
                        smtp.starttls()
                    if self._config.email_username:
                        smtp.login(self._config.email_username, self._config.email_password)
                    smtp.send_message(msg)
            logger.debug("Email sent for alert: %s", alert.title)
        except Exception as exc:
            logger.error("Failed to send email alert: %s", exc)


class WebhookNotifier(BaseNotifier):
    """
    Sends alerts as JSON HTTP POST to a configured webhook URL.

    Compatible with Slack incoming webhooks, Discord, Home Assistant,
    ntfy.sh, and any custom HTTP receiver.
    """

    def __init__(self, config: Config) -> None:
        self._config = config.notifications
        self._min_severity = Severity(self._config.webhook_min_severity)
        self._hostname = socket.gethostname()
        import queue as q_module
        self._queue: "q_module.Queue[Alert]" = q_module.Queue(maxsize=200)
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._worker, daemon=True, name="WebhookNotifier")
        self._thread.start()

    def send(self, alert: Alert) -> None:
        if not self._config.webhook_enabled or not self._config.webhook_url:
            return
        if alert.severity < self._min_severity:
            return
        if self._stop_event.is_set():
            logger.warning("Webhook notifier is stopping — dropping notification.")
            return
        try:
            self._queue.put_nowait(alert)
        except Exception:
            logger.warning("Webhook queue full — dropping notification.")

    def _worker(self) -> None:
        while not self._stop_event.is_set() or not self._queue.empty():
            try:
                alert = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._post_webhook(alert)
            except Exception as exc:
                logger.warning("Webhook notification failed: %s", exc)

    def close(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        if self._thread.is_alive():
            logger.warning("Webhook notifier did not stop cleanly.")

    def preflight(self) -> tuple[bool, str]:
        if not self._config.webhook_enabled or not self._config.webhook_url:
            return (True, "disabled")
        try:
            self._post_webhook(_preflight_alert())
        except Exception as exc:
            return (False, f"POST {self._config.webhook_url}: {exc}")
        return (True, f"delivered test payload to {self._config.webhook_url}")

    def _post_webhook(self, alert: Alert) -> None:
        # Raises on failure; the worker loop wraps this and logs. Letting it
        # raise also lets preflight() report delivery success/failure.
        import requests
        payload = {
            "source": "SentinelPi",
            "hostname": self._hostname,
            "alert": self._alert_to_dict(alert),
        }
        headers = {"Content-Type": "application/json"}
        if self._config.webhook_secret:
            headers["X-SentinelPi-Secret"] = self._config.webhook_secret

        resp = requests.post(
            self._config.webhook_url,
            json=payload,
            headers=headers,
            timeout=10,
        )
        resp.raise_for_status()
        logger.debug("Webhook delivered for: %s", alert.title)


class NtfyNotifier(BaseNotifier):
    """
    Pushes alerts to an ntfy topic, and — for responder actions awaiting human
    approval — sends an actionable notification with Approve/Reject buttons that
    call the dashboard's response API directly from your phone.

    Two entry points:
    - ``send(alert)``: normal alert push (filtered by ``ntfy_min_severity``).
    - ``notify_pending(action)``: an action-button notification for a PENDING
      responder action. Wired in by the ResponderManager so approvals close the
      loop without opening the dashboard. Buttons are only attached when both
      ``ntfy_dashboard_url`` and ``ntfy_dashboard_token`` are configured.

    Like the other network notifiers, delivery is queued and drained on a daemon
    worker so the alert pipeline never blocks on ntfy latency.
    """

    # Severity → ntfy priority (1=min … 5=max).
    _PRIORITY = {
        Severity.INFO: 2,
        Severity.LOW: 2,
        Severity.MEDIUM: 3,
        Severity.HIGH: 4,
        Severity.CRITICAL: 5,
    }
    _TAGS = {
        Severity.INFO: ["information_source"],
        Severity.LOW: ["information_source"],
        Severity.MEDIUM: ["warning"],
        Severity.HIGH: ["rotating_light"],
        Severity.CRITICAL: ["rotating_light"],
    }

    def __init__(self, config: Config) -> None:
        self._config = config.notifications
        self._min_severity = Severity(self._config.ntfy_min_severity)
        self._hostname = socket.gethostname()
        self._queue: "queue.Queue[dict]" = queue.Queue(maxsize=200)
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._worker, daemon=True, name="NtfyNotifier")
        self._thread.start()

    def send(self, alert: Alert) -> None:
        if not self._config.ntfy_enabled or not self._config.ntfy_topic:
            return
        if alert.severity < self._min_severity:
            return
        host = f" [{alert.affected_host}]" if alert.affected_host else ""
        payload = {
            "topic": self._config.ntfy_topic,
            "title": f"[{alert.severity.value.upper()}]{host} {alert.title}",
            "message": alert.description or alert.title,
            "priority": self._PRIORITY.get(alert.severity, 3),
            "tags": self._TAGS.get(alert.severity, []),
        }
        self._enqueue(payload)

    def notify_pending(self, action) -> None:
        """
        Push an actionable notification for a responder action awaiting approval.

        ``action`` is a ResponderAction (duck-typed: ``action_id``, ``responder``,
        ``target``, ``description``). Safe to call regardless of config — it no-ops
        when ntfy is disabled.
        """
        if not self._config.ntfy_enabled or not self._config.ntfy_topic:
            return
        payload: dict = {
            "topic": self._config.ntfy_topic,
            "title": f"[APPROVAL] {action.responder} on {action.target}",
            "message": action.description or "Action awaiting approval.",
            "priority": 5,
            "tags": ["police_car_light"],
        }
        actions = self._approval_buttons(action.action_id)
        if actions:
            payload["actions"] = actions
        self._enqueue(payload)

    def _approval_buttons(self, action_id: str) -> list:
        """Build ntfy http action buttons that hit the dashboard response API."""
        base = self._config.ntfy_dashboard_url.rstrip("/")
        token = self._config.ntfy_dashboard_token
        if not base or not token:
            return []
        headers = {"Authorization": f"Bearer {token}"}
        return [
            {
                "action": "http",
                "label": "Approve",
                "url": f"{base}/api/responses/{action_id}/approve",
                "method": "POST",
                "headers": headers,
                "clear": True,
            },
            {
                "action": "http",
                "label": "Reject",
                "url": f"{base}/api/responses/{action_id}/reject",
                "method": "POST",
                "headers": headers,
                "clear": True,
            },
        ]

    def _enqueue(self, payload: dict) -> None:
        if self._stop_event.is_set():
            logger.warning("ntfy notifier is stopping — dropping notification.")
            return
        try:
            self._queue.put_nowait(payload)
        except Exception:
            logger.warning("ntfy queue full — dropping notification.")

    def _worker(self) -> None:
        while not self._stop_event.is_set() or not self._queue.empty():
            try:
                payload = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._publish(payload)
            except Exception as exc:
                logger.warning("ntfy notification failed: %s", exc)

    def close(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        if self._thread.is_alive():
            logger.warning("ntfy notifier did not stop cleanly.")

    def preflight(self) -> tuple[bool, str]:
        if not self._config.ntfy_enabled or not self._config.ntfy_topic:
            return (True, "disabled")
        target = f"{self._config.ntfy_server.rstrip('/')}/{self._config.ntfy_topic}"
        try:
            self._publish({
                "topic": self._config.ntfy_topic,
                "title": "SentinelPi preflight check",
                "message": "Test notification from `sentinelpi --check`. Safe to ignore.",
                "priority": 2,
                "tags": ["white_check_mark"],
            })
        except Exception as exc:
            return (False, f"publish to {target}: {exc}")
        return (True, f"published test notification to {target}")

    def _publish(self, payload: dict) -> None:
        import requests
        headers = {"Content-Type": "application/json"}
        if self._config.ntfy_token:
            headers["Authorization"] = f"Bearer {self._config.ntfy_token}"
        resp = requests.post(
            self._config.ntfy_server.rstrip("/"),
            json=payload,
            headers=headers,
            timeout=10,
        )
        resp.raise_for_status()
        logger.debug("ntfy notification delivered: %s", payload.get("title"))


class TwilioSMSNotifier(BaseNotifier):
    """
    Sends SMS alerts through Twilio Programmable Messaging.

    Delivery is queued so Twilio latency cannot block detection. Configure either
    Account SID + Auth Token, or API Key SID + API Key Secret with the Account
    SID used in the REST resource URL.
    """

    API_BASE = "https://api.twilio.com/2010-04-01"

    def __init__(self, config: Config) -> None:
        self._config = config.notifications
        self._min_severity = Severity(self._config.sms_min_severity)
        self._hostname = socket.gethostname()
        self._queue: "queue.Queue[Alert]" = queue.Queue(maxsize=100)
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._worker, daemon=True, name="TwilioSMSNotifier")
        self._thread.start()

    def send(self, alert: Alert) -> None:
        if not self._config.sms_enabled:
            return
        if alert.severity < self._min_severity:
            return
        if self._stop_event.is_set():
            logger.warning("Twilio SMS notifier is stopping — dropping alert notification.")
            return
        try:
            self._queue.put_nowait(alert)
        except Exception:
            logger.warning("Twilio SMS queue full — dropping alert notification.")

    def _worker(self) -> None:
        while not self._stop_event.is_set() or not self._queue.empty():
            try:
                alert = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._send_sms(alert)
            except Exception as exc:
                logger.warning("Twilio SMS notification failed: %s", exc)

    def close(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        if self._thread.is_alive():
            logger.warning("Twilio SMS notifier did not stop cleanly.")

    def preflight(self) -> tuple[bool, str]:
        if not self._config.sms_enabled:
            return (True, "disabled")
        try:
            self._send_sms(_preflight_alert())
        except Exception as exc:
            return (False, f"Twilio SMS: {exc}")
        return (True, f"sent test SMS to {len(self._config.sms_to)} recipient(s)")

    def _send_sms(self, alert: Alert) -> None:
        import requests

        body = self._format_sms(alert)
        url = f"{self.API_BASE}/Accounts/{self._config.sms_account_sid}/Messages.json"
        auth = self._auth()
        for recipient in self._config.sms_to:
            data = {
                "To": recipient,
                "Body": body,
            }
            if self._config.sms_messaging_service_sid:
                data["MessagingServiceSid"] = self._config.sms_messaging_service_sid
            else:
                data["From"] = self._config.sms_from

            resp = requests.post(url, data=data, auth=auth, timeout=10)
            resp.raise_for_status()
        logger.debug("Twilio SMS sent for alert: %s", alert.title)

    def _auth(self) -> tuple[str, str]:
        if self._config.sms_api_key_sid and self._config.sms_api_key_secret:
            return (self._config.sms_api_key_sid, self._config.sms_api_key_secret)
        return (self._config.sms_account_sid, self._config.sms_auth_token)

    def _format_sms(self, alert: Alert) -> str:
        host = alert.affected_host or alert.related_host or "unknown host"
        text = (
            f"SentinelPi {alert.severity.value.upper()}: {alert.title} "
            f"({alert.category.value}, {host})"
        )
        if alert.recommended_action:
            text = f"{text}. {alert.recommended_action}"
        if len(text) > 320:
            return text[:317].rstrip() + "..."
        return text


class ForwardNotifier(BaseNotifier):
    """
    Sensor-side notifier: forwards alerts to a central collector's ingest
    endpoint (Phase 3). Mirrors WebhookNotifier's async queue + worker, but
    targets a SentinelPi collector and authenticates with the shared cluster
    key. Never forwards an alert that already carries a 'sensor' tag (it came
    from another sensor), so collectors can't bounce events around.
    """

    def __init__(self, config: Config) -> None:
        self._cluster = config.cluster
        self._min_severity = Severity(self._cluster.forward_min_severity)
        import queue as q_module
        self._queue: "q_module.Queue[Alert]" = q_module.Queue(maxsize=500)
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._worker, daemon=True, name="ForwardNotifier")
        self._thread.start()

    def send(self, alert: Alert) -> None:
        if not self._cluster.collector_url:
            return
        if alert.severity < self._min_severity:
            return
        if alert.extra.get("sensor"):
            return  # don't re-forward a remote alert
        if self._stop_event.is_set():
            logger.warning("Forward notifier is stopping — dropping forwarded alert.")
            return
        try:
            self._queue.put_nowait(alert)
        except Exception:
            logger.warning("Forward queue full — dropping forwarded alert.")

    def _worker(self) -> None:
        while not self._stop_event.is_set() or not self._queue.empty():
            try:
                alert = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._forward(alert)
            except Exception as exc:
                logger.warning("Alert forwarding failed: %s", exc)

    def close(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        if self._thread.is_alive():
            logger.warning("Forward notifier did not stop cleanly.")

    def preflight(self) -> tuple[bool, str]:
        if not self._cluster.collector_url:
            return (True, "disabled")
        try:
            self._forward(_preflight_alert())
        except Exception as exc:
            return (False, f"forward to {self._cluster.collector_url}: {exc}")
        return (True, f"forwarded test alert to {self._cluster.collector_url}")

    def _forward(self, alert: Alert) -> None:
        import requests
        payload = {"sensor_id": self._cluster.sensor_id, "alert": self._alert_to_dict(alert)}
        headers = {"Content-Type": "application/json"}
        if self._cluster.collector_key:
            headers["X-SentinelPi-Collector-Key"] = self._cluster.collector_key
        resp = requests.post(
            self._cluster.collector_url,
            json=payload,
            headers=headers,
            timeout=10,
            **self._tls_kwargs(),
        )
        resp.raise_for_status()
        logger.debug("Forwarded alert to collector: %s", alert.title)

    def _tls_kwargs(self) -> dict:
        """
        Build requests' TLS args from cluster config. ``verify`` becomes the CA
        bundle path when set (so the collector's cert is checked against it),
        otherwise the boolean tls_verify. ``cert`` enables mutual TLS by
        presenting the sensor's client certificate.
        """
        kwargs: dict = {"verify": self._cluster.tls_ca_cert or self._cluster.tls_verify}
        if self._cluster.tls_client_cert:
            if self._cluster.tls_client_key:
                kwargs["cert"] = (self._cluster.tls_client_cert, self._cluster.tls_client_key)
            else:
                kwargs["cert"] = self._cluster.tls_client_cert
        return kwargs


class SyslogNotifier(BaseNotifier):
    """
    Streams alerts to a SIEM collector over syslog (UDP or TCP).

    Each alert is rendered in a SIEM-friendly payload format — ECS (Elastic
    Common Schema JSON) or CEF (ArcSight Common Event Format) — then wrapped in
    an RFC 5424 syslog frame. Delivery is async (queue + worker) like the other
    network notifiers, so a slow or unreachable collector never blocks
    detection. TCP frames are newline-delimited (RFC 6587 non-transparent
    framing); UDP sends one datagram per alert.
    """

    def __init__(self, config: Config) -> None:
        from .. import __version__

        n = config.notifications
        self._format = n.siem_format
        self._transport = n.siem_transport
        self._host = n.siem_host
        self._port = n.siem_port
        self._facility = n.siem_facility
        self._min_severity = Severity(n.siem_min_severity)
        self._version = __version__
        self._hostname = socket.gethostname()
        self._queue: "queue.Queue[Alert]" = queue.Queue(maxsize=1000)
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._worker, daemon=True, name="SyslogNotifier")
        self._thread.start()

    def send(self, alert: Alert) -> None:
        if not self._host:
            return
        if alert.severity < self._min_severity:
            return
        if self._stop_event.is_set():
            logger.warning("Syslog notifier is stopping — dropping alert.")
            return
        try:
            self._queue.put_nowait(alert)
        except queue.Full:
            logger.warning("Syslog queue full — dropping alert.")

    def _worker(self) -> None:
        while not self._stop_event.is_set() or not self._queue.empty():
            try:
                alert = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._emit(alert)
            except Exception as exc:
                logger.warning("Syslog export failed: %s", exc)

    def close(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        if self._thread.is_alive():
            logger.warning("Syslog notifier did not stop cleanly.")

    def preflight(self) -> tuple[bool, str]:
        if not self._host:
            return (True, "disabled")
        try:
            self._emit(_preflight_alert())
        except Exception as exc:
            return (False, f"syslog {self._transport}://{self._host}:{self._port}: {exc}")
        return (True, f"sent test event to {self._transport}://{self._host}:{self._port} ({self._format})")

    def _render(self, alert: Alert) -> str:
        from . import siem

        if self._format == "cef":
            payload = siem.format_cef(alert, product_version=self._version)
        else:
            payload = siem.format_ecs_line(alert, product_version=self._version)
        return siem.format_syslog(
            payload,
            severity=alert.severity,
            timestamp_iso=siem._aware_utc_iso(alert),
            hostname=self._hostname,
            facility=self._facility,
        )

    def _emit(self, alert: Alert) -> None:
        message = self._render(alert)
        self._transmit(message.encode("utf-8"))

    def _transmit(self, data: bytes) -> None:
        """Send one framed message to the collector. Raises on failure."""
        if self._transport == "tcp":
            with socket.create_connection((self._host, self._port), timeout=10) as sock:
                sock.sendall(data + b"\n")
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(data, (self._host, self._port))
