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
"""

from __future__ import annotations

import json
import logging
import smtplib
import socket
import threading
from abc import ABC, abstractmethod
from datetime import datetime
from email.mime.text import MIMEText
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from ..models import Alert, Severity
from ..config.manager import Config

logger = logging.getLogger(__name__)

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

    def _alert_to_dict(self, alert: Alert) -> dict:
        """Convert an Alert to a JSON-serializable dict."""
        return {
            "alert_id": alert.alert_id,
            "timestamp": alert.timestamp.isoformat() + "Z",
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
                self._handler.doRollover() if self._handler.shouldRollover(None) else None
        except Exception as exc:
            logger.error("FileNotifier write failed: %s", exc)


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
        self._thread = threading.Thread(target=self._worker, daemon=True, name="EmailNotifier")
        self._thread.start()

    def send(self, alert: Alert) -> None:
        if not self._config.email_enabled:
            return
        if alert.severity < self._min_severity:
            return
        try:
            self._queue.put_nowait(alert)
        except Exception:
            logger.warning("Email queue full — dropping alert notification.")

    def _worker(self) -> None:
        """Background thread that drains the email queue."""
        while True:
            try:
                alert = self._queue.get(timeout=5.0)
                self._send_email(alert)
            except Exception:
                pass

    def _send_email(self, alert: Alert) -> None:
        """Send a single alert email."""
        subject = f"[SentinelPi] [{alert.severity.value.upper()}] {alert.title}"
        body = (
            f"SentinelPi Alert\n"
            f"{'='*60}\n"
            f"Severity: {alert.severity.value.upper()}\n"
            f"Category: {alert.category.value}\n"
            f"Host: {alert.affected_host}\n"
            f"Time: {alert.timestamp.isoformat()}Z\n\n"
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
        self._thread = threading.Thread(target=self._worker, daemon=True, name="WebhookNotifier")
        self._thread.start()

    def send(self, alert: Alert) -> None:
        if not self._config.webhook_enabled or not self._config.webhook_url:
            return
        if alert.severity < self._min_severity:
            return
        try:
            self._queue.put_nowait(alert)
        except Exception:
            logger.warning("Webhook queue full — dropping notification.")

    def _worker(self) -> None:
        while True:
            try:
                alert = self._queue.get(timeout=5.0)
                self._post_webhook(alert)
            except Exception:
                pass

    def _post_webhook(self, alert: Alert) -> None:
        try:
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
        except Exception as exc:
            logger.error("Webhook delivery failed: %s", exc)
