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
- Optional access token in Authorization header or query param
- No user input is ever evaluated as code
- All dynamic data is JSON-serialized (no raw template injection)
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timedelta
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

if TYPE_CHECKING:
    from ..config.manager import Config
    from ..storage.database import Database
    from ..inventory.device_tracker import DeviceTracker
    from ..baseline.engine import BaselineEngine
    from ..alerts.manager import AlertManager


def create_app(
    config: "Config",
    db: "Database",
    device_tracker: "DeviceTracker",
    baseline: "BaselineEngine",
    alert_manager: "AlertManager",
) -> Optional["Flask"]:
    """
    Create and configure the Flask application.

    Returns None if Flask is not installed.
    """
    if not FLASK_AVAILABLE:
        return None

    app = Flask(__name__, template_folder="templates")
    app.config["SECRET_KEY"] = "sentinelpi-dashboard-key"

    # ------------------------------------------------------------------
    # Authentication middleware (optional token)
    # ------------------------------------------------------------------

    def require_token(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = config.dashboard.access_token
            if not token:
                return f(*args, **kwargs)
            # Accept token via Authorization header or ?token= query param
            provided = (
                request.headers.get("Authorization", "").replace("Bearer ", "")
                or request.args.get("token", "")
            )
            if provided != token:
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
        now = datetime.utcnow()
        last_24h = now - timedelta(hours=24)
        counts = db.get_alert_counts_by_severity(last_24h)
        baseline_summary = baseline.get_summary()
        manager_stats = alert_manager.get_stats()

        return jsonify({
            "status": "running",
            "timestamp": now.isoformat() + "Z",
            "alert_counts_24h": counts,
            "device_count": device_tracker.get_device_count(),
            "baseline": baseline_summary,
            "alert_manager": manager_stats,
        })

    @app.route("/api/alerts")
    @require_token
    def api_alerts():
        limit = min(int(request.args.get("limit", 100)), 500)
        hours = int(request.args.get("hours", 24))
        severity = request.args.get("severity")
        status = request.args.get("status")
        host = request.args.get("host")

        since = datetime.utcnow() - timedelta(hours=hours)
        sev_filter = Severity(severity) if severity else None
        status_filter = AlertStatus(status) if status else None

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
        "status": alert.status.value,
    }


def _device_to_dict(device) -> dict:
    return {
        "ip": device.ip,
        "mac": device.mac,
        "hostname": device.hostname,
        "vendor": device.vendor,
        "first_seen": device.first_seen.isoformat() + "Z",
        "last_seen": device.last_seen.isoformat() + "Z",
        "is_trusted": device.is_trusted,
        "is_gateway": device.is_gateway,
        "alert_count": device.alert_count,
        "suspicion_score": round(device.suspicion_score, 2),
    }


def _generate_daily_report(db, device_tracker, baseline) -> dict:
    """Generate a daily summary report."""
    now = datetime.utcnow()
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
        "generated_at": now.isoformat() + "Z",
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
    Wrapper that runs the Flask dashboard in a dedicated daemon thread.
    """

    def __init__(self, app: "Flask", config: "Config") -> None:
        self._app = app
        self._config = config
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if not FLASK_AVAILABLE or self._app is None:
            logger.warning("Dashboard not started — Flask not available.")
            return

        host = self._config.dashboard.host
        port = self._config.dashboard.port

        def run():
            # Use werkzeug's built-in server — fine for local single-user dashboard
            self._app.run(
                host=host,
                port=port,
                debug=False,          # Never enable debug in production
                use_reloader=False,   # Reloader not safe in daemon thread
                threaded=True,
            )

        self._thread = threading.Thread(target=run, daemon=True, name="DashboardServer")
        self._thread.start()
        logger.info("Dashboard started at http://%s:%d/", host, port)

    def stop(self) -> None:
        # Flask dev server doesn't have a clean shutdown API;
        # since it's a daemon thread it'll die with the main process.
        logger.info("Dashboard server stopping (daemon thread will exit with main process).")
