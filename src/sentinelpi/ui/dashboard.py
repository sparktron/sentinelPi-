"""
ui/dashboard.py - Lightweight local web dashboard using Flask.

Features:
- Recent alerts with filter/search
- Device inventory table
- Baseline summary
- Top suspicious hosts
- Acknowledgment / mute controls
- Simple token-based access protection (optional)

Security:
- Binds to 127.0.0.1 by default (never exposed to network unless configured)
- Access token required on every route, supplied via the Authorization header
  only (never the query string); auto-generated and logged once if unset
- Refuses to bind to a non-loopback host with no token (fail closed)
- No user input is ever evaluated as code
- All dynamic data is JSON-serialized (no raw template injection)
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import secrets
import threading
from datetime import datetime, timedelta
from ..utils import clock
from functools import wraps
from typing import TYPE_CHECKING, Optional

from ..models import AlertStatus, Severity

logger = logging.getLogger(__name__)

try:
    from flask import Flask, jsonify, render_template, request, abort, Response
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    logger.warning("Flask not available — web dashboard disabled.")

try:
    # Production-grade, pure-Python WSGI server with a real shutdown API.
    from waitress import create_server as _create_waitress_server
    WAITRESS_AVAILABLE = True
except ImportError:
    WAITRESS_AVAILABLE = False

if TYPE_CHECKING:
    from ..config.manager import Config
    from ..storage.database import Database
    from ..inventory.device_tracker import DeviceTracker
    from ..baseline.engine import BaselineEngine
    from ..alerts.manager import AlertManager


def _bounded_int(raw: Optional[str], default: int, lo: int, hi: int) -> int:
    """
    Parse an int query param, clamped to [lo, hi].

    Returns ``default`` when the param is absent/empty. Raises ValueError on a
    non-numeric value so the caller can return a 400 instead of a 500.
    """
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ValueError(f"expected an integer, got {raw!r}")
    return max(lo, min(value, hi))


def _is_loopback(host: str) -> bool:
    """True if host binds only to the loopback interface (no network exposure)."""
    if host in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        # Unknown hostname — treat as non-loopback (fail safe / err on exposed).
        return False


def create_app(
    config: "Config",
    db: "Database",
    device_tracker: "DeviceTracker",
    baseline: "BaselineEngine",
    alert_manager: "AlertManager",
    responder_manager=None,
) -> Optional["Flask"]:
    """
    Create and configure the Flask application.

    Returns None if Flask is not installed.
    """
    if not FLASK_AVAILABLE:
        return None

    app = Flask(__name__, template_folder="templates")
    # Random per-process secret — never a hardcoded value (signs Flask sessions/flashes).
    app.config["SECRET_KEY"] = secrets.token_hex(32)

    # Secure by default: if no token was configured, generate one and log it
    # once. This means the dashboard — which exposes the full network picture
    # and trust/ack/mute mutation endpoints — is never unauthenticated.
    if not config.dashboard.access_token:
        config.dashboard.access_token = secrets.token_urlsafe(32)
        logger.warning(
            "No dashboard access_token configured — generated a random one for this run:\n"
            "    %s\n"
            "Pass it as 'Authorization: Bearer <token>'. Set dashboard.access_token in config "
            "to make it stable across restarts.",
            config.dashboard.access_token,
        )

    # ------------------------------------------------------------------
    # Authentication middleware (token required, header only)
    # ------------------------------------------------------------------

    def require_token(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = config.dashboard.access_token
            if not token:
                # Fail closed: an empty token should be impossible (auto-generated
                # above), but if it ever happens, deny rather than expose.
                abort(401)
            # Header only — never accept the token via query string, which lands
            # in access logs, browser history, and Referer headers.
            auth = request.headers.get("Authorization", "")
            provided = auth[7:] if auth.startswith("Bearer ") else ""
            # Constant-time compare to avoid leaking the token via timing.
            if not provided or not hmac.compare_digest(provided, token):
                abort(401)
            return f(*args, **kwargs)
        return decorated

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    @app.route("/")
    @require_token
    def index():
        return render_template("dashboard.html")

    @app.route("/api/status")
    @require_token
    def api_status():
        now = clock.now()
        last_24h = now - timedelta(hours=24)
        counts = db.get_alert_counts_by_severity(last_24h)
        baseline_summary = baseline.get_summary()
        manager_stats = alert_manager.get_stats()

        return jsonify({
            "status": "running",
            "timestamp": now.isoformat(),
            "alert_counts_24h": counts,
            "device_count": device_tracker.get_device_count(),
            "baseline": baseline_summary,
            "alert_manager": manager_stats,
        })

    @app.route("/api/alerts")
    @require_token
    def api_alerts():
        try:
            limit = _bounded_int(request.args.get("limit"), default=100, lo=1, hi=500)
            hours = _bounded_int(request.args.get("hours"), default=24, lo=1, hi=24 * 90)
        except ValueError as exc:
            return jsonify({"error": f"Invalid query parameter: {exc}"}), 400

        severity = request.args.get("severity")
        status = request.args.get("status")
        host = request.args.get("host")

        try:
            sev_filter = Severity(severity) if severity else None
            status_filter = AlertStatus(status) if status else None
        except ValueError:
            return jsonify({
                "error": "Invalid 'severity' or 'status' value",
                "valid_severity": [s.value for s in Severity],
                "valid_status": [s.value for s in AlertStatus],
            }), 400

        since = clock.now() - timedelta(hours=hours)

        alerts = db.get_recent_alerts(
            limit=limit,
            since=since,
            severity=sev_filter,
            status=status_filter,
            host=host,
        )

        return jsonify([_alert_to_dict(a) for a in alerts])

    @app.route("/api/alerts/<alert_id>/acknowledge", methods=["POST"])
    @require_token
    def api_acknowledge(alert_id: str):
        ok = alert_manager.acknowledge_alert(alert_id)
        return jsonify({"ok": ok})

    @app.route("/api/alerts/<alert_id>/mute", methods=["POST"])
    @require_token
    def api_mute(alert_id: str):
        ok = alert_manager.mute_alert(alert_id)
        return jsonify({"ok": ok})

    # ------------------------------------------------------------------
    # Active-response endpoints (only present when a responder manager is wired)
    # ------------------------------------------------------------------
    if responder_manager is not None:
        @app.route("/api/responses/pending")
        @require_token
        def api_responses_pending():
            return jsonify([_action_to_dict(a) for a in responder_manager.pending_actions()])

        @app.route("/api/responses/recent")
        @require_token
        def api_responses_recent():
            return jsonify([_action_to_dict(a) for a in responder_manager.recent_actions()])

        @app.route("/api/responses/<action_id>/approve", methods=["POST"])
        @require_token
        def api_responses_approve(action_id: str):
            action = responder_manager.approve(action_id)
            if action is None:
                abort(404)
            return jsonify(_action_to_dict(action))

        @app.route("/api/responses/<action_id>/reject", methods=["POST"])
        @require_token
        def api_responses_reject(action_id: str):
            action = responder_manager.reject(action_id)
            if action is None:
                abort(404)
            return jsonify(_action_to_dict(action))

    @app.route("/api/devices")
    @require_token
    def api_devices():
        devices = device_tracker.get_all_devices()
        return jsonify([_device_to_dict(d) for d in devices])

    @app.route("/api/devices/<ip>/trust", methods=["POST"])
    @require_token
    def api_trust_device(ip: str):
        """Mark a device as trusted (reduces its alert noise)."""
        device = device_tracker.get_device(ip)
        if not device:
            abort(404)
        device.is_trusted = True
        db.upsert_device(device)
        return jsonify({"ok": True, "ip": ip})

    @app.route("/api/suspicious")
    @require_token
    def api_suspicious():
        hosts = db.get_top_suspicious_hosts(limit=20)
        return jsonify(hosts)

    @app.route("/api/dns/top")
    @require_token
    def api_dns_top():
        domains = db.get_top_dns_domains(limit=50)
        return jsonify(domains)

    @app.route("/api/report/daily")
    @require_token
    def api_daily_report():
        return jsonify(_generate_daily_report(db, device_tracker, baseline))

    # ------------------------------------------------------------------
    # Error handlers
    # ------------------------------------------------------------------

    @app.errorhandler(401)
    def unauthorized(e):
        return jsonify({"error": "Unauthorized — provide access token"}), 401

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not found"}), 404

    return app


def _alert_to_dict(alert) -> dict:
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
        "status": alert.status.value,
        "enrichment": alert.extra.get("enrichment"),
    }


def _action_to_dict(action) -> dict:
    return {
        "action_id": action.action_id,
        "responder": action.responder,
        "target": action.target,
        "description": action.description,
        "commands": [" ".join(c) for c in action.commands],
        "status": action.status,
        "dry_run": action.dry_run,
        "executed": action.executed,
        "success": action.success,
        "error": action.error,
        "alert_id": action.alert_id,
        "created_at": action.created_at.isoformat(),
    }


def _device_to_dict(device) -> dict:
    return {
        "ip": device.ip,
        "mac": device.mac,
        "hostname": device.hostname,
        "vendor": device.vendor,
        "first_seen": device.first_seen.isoformat(),
        "last_seen": device.last_seen.isoformat(),
        "is_trusted": device.is_trusted,
        "is_gateway": device.is_gateway,
        "alert_count": device.alert_count,
        "suspicion_score": round(device.suspicion_score, 2),
        "device_type": device.extra.get("device_type", "unknown"),
        "device_type_confidence": device.extra.get("device_type_confidence", 0.0),
    }


def _generate_daily_report(db, device_tracker, baseline) -> dict:
    """Generate a daily summary report."""
    now = clock.now()
    since = now - timedelta(hours=24)

    alerts = db.get_recent_alerts(limit=1000, since=since)
    devices = device_tracker.get_all_devices()

    # New devices in last 24h
    new_devices = [d for d in devices if d.first_seen > since]

    # Alert counts by severity
    by_severity = {}
    for alert in alerts:
        by_severity[alert.severity.value] = by_severity.get(alert.severity.value, 0) + 1

    # Alert counts by category
    by_category = {}
    for alert in alerts:
        by_category[alert.category.value] = by_category.get(alert.category.value, 0) + 1

    # Top alerting hosts
    host_counts: dict = {}
    for alert in alerts:
        if alert.affected_host:
            host_counts[alert.affected_host] = host_counts.get(alert.affected_host, 0) + 1
    top_hosts = sorted(host_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "period": "last_24h",
        "generated_at": now.isoformat(),
        "total_alerts": len(alerts),
        "alerts_by_severity": by_severity,
        "alerts_by_category": by_category,
        "new_devices": [_device_to_dict(d) for d in new_devices],
        "top_alerting_hosts": [{"host": h, "count": c} for h, c in top_hosts],
        "total_known_devices": len(devices),
        "baseline_summary": baseline.get_summary(),
    }


class DashboardServer:
    """
    Runs the dashboard WSGI app in a dedicated daemon thread.

    Prefers waitress (production-grade, pure-Python) so we get a real, graceful
    shutdown via stop(). If waitress is not installed we fall back to Flask's
    Werkzeug dev server with a loud warning — that path has no clean shutdown
    and is only appropriate for local development.
    """

    def __init__(self, app: "Flask", config: "Config") -> None:
        self._app = app
        self._config = config
        self._thread: Optional[threading.Thread] = None
        # waitress server handle, set only on the waitress path; gives us .close().
        self._server = None

    def start(self) -> None:
        if not FLASK_AVAILABLE or self._app is None:
            logger.warning("Dashboard not started — Flask not available.")
            return

        host = self._config.dashboard.host
        port = self._config.dashboard.port

        # Fail closed: refuse to expose the dashboard on a non-loopback address
        # without authentication. create_app() auto-generates a token, so this
        # should never trip in normal use — it guards against a misconfigured
        # config object reaching the server with auth disabled.
        if not self._config.dashboard.access_token and not _is_loopback(host):
            logger.error(
                "Refusing to bind dashboard to non-loopback host %s with no access_token "
                "(would expose an unauthenticated control panel). Set dashboard.access_token "
                "or bind to 127.0.0.1.",
                host,
            )
            return

        if WAITRESS_AVAILABLE:
            self._start_waitress(host, port)
        else:
            logger.warning(
                "waitress not installed — falling back to the Flask/Werkzeug dev server. "
                "This has no graceful shutdown and is not hardened; install waitress for "
                "production use (pip install waitress)."
            )
            self._start_dev_server(host, port)

        logger.info("Dashboard started at http://%s:%d/", host, port)

    def _start_waitress(self, host: str, port: int) -> None:
        # create_server binds the socket synchronously, so a bad bind raises here
        # (on the caller's thread) rather than dying silently in the worker.
        self._server = _create_waitress_server(self._app, host=host, port=port)
        self._thread = threading.Thread(
            target=self._server.run, daemon=True, name="DashboardServer"
        )
        self._thread.start()

    def _start_dev_server(self, host: str, port: int) -> None:
        def run():
            self._app.run(
                host=host,
                port=port,
                debug=False,          # Never enable debug in production
                use_reloader=False,   # Reloader not safe in daemon thread
                threaded=True,
            )

        self._thread = threading.Thread(target=run, daemon=True, name="DashboardServer")
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        if self._server is not None:
            # waitress: closing the server breaks its serve loop, so run() returns
            # and the thread exits cleanly.
            logger.info("Stopping dashboard server (graceful)…")
            try:
                self._server.close()
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("Error closing dashboard server: %s", exc)
            if self._thread is not None:
                self._thread.join(timeout=timeout)
            self._server = None
        else:
            # Dev-server fallback has no clean shutdown API; as a daemon thread it
            # dies with the main process.
            logger.info("Dashboard server stopping (dev server — daemon thread exits with process).")
