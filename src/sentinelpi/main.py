"""
main.py - SentinelPi service runner.

This is the main entry point. It:
1. Loads configuration.
2. Initializes all subsystems.
3. Starts background threads for each module.
4. Handles graceful shutdown on SIGTERM/SIGINT.
5. Performs periodic maintenance (DB vacuum, report generation).

Thread model:
  - Main thread: signal handling and maintenance scheduler.
  - DeviceTracker thread: polls ARP table every 30s.
  - ConnectionDetector thread: polls /proc/net/tcp every 60s.
  - AuthLogDetector thread: tails auth log every 30s.
  - BeaconDetector thread: polls /proc/net connections every 60s.
  - LateralMovementDetector thread: polls /proc/net every 60s.
  - PacketCapture thread: scapy sniff loop (if enabled).
  - EventRouter thread: dispatches packet events to detectors.
  - DashboardServer thread: waitress production server when available (if enabled).

All detector threads share:
  - Config object (read-only after startup)
  - Database instance (thread-safe via thread-local connections)
  - BaselineEngine (thread-safe via RLock)
  - AlertManager (thread-safe via lock)
  - DeviceTracker (thread-safe via RLock)
"""

from __future__ import annotations

import logging
import logging.handlers
import queue
import signal
import sys
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, List, Optional

if TYPE_CHECKING:
    from .ui.dashboard import DashboardServer

from .config.manager import Config, load_config, validate_config
from .config.preflight import run_preflight
from .storage.database import Database
from .baseline.engine import BaselineEngine
from .inventory.device_tracker import DeviceTracker
from .alerts.manager import AlertManager
from .alerts.notifiers import (
    ConsoleNotifier, FileNotifier, EmailNotifier, WebhookNotifier, NtfyNotifier, TwilioSMSNotifier,
    SyslogNotifier, OTLPNotifier, ForwardNotifier,
)
from .responders.manager import ResponderManager
from .responders.firewall import FirewallResponder
from .responders.dns_sinkhole import DNSSinkholeResponder
from .responders.arp_restore import ARPRestoreResponder
from .responders.killswitch import KillSwitchResponder
from .detectors.arp_detector import ARPDetector
from .detectors.beacon_detector import BeaconDetector
from .detectors.connection_detector import ConnectionDetector
from .detectors.dns_detector import DNSDetector
from .detectors.lateral_movement_detector import LateralMovementDetector
from .detectors.auth_log_detector import AuthLogDetector
from .detectors.doh_detector import DoHDetector
from .detectors.geo_country_detector import GeoCountryDetector
from .detectors.asn_detector import ASNReputationDetector
from .detectors.active_hours_detector import ActiveHoursDetector
from .detectors.host_profile_detector import HostProfileDetector
from .detectors.threat_intel_detector import ThreatIntelDetector
from .intel.threat_feeds import ThreatIntelService
from .capture.packet_capture import PacketCapture
from .capture.flow_ingest import ConntrackFlowSource, NetFlowCollector, FilterlogSource
from .capture.honeypot import HoneypotService
from .utils.geo import init_geo
from .utils.asn import init_asn
from .utils.watchdog import OperationalWatchdog

logger = logging.getLogger(__name__)


def setup_logging(config: Config) -> None:
    """
    Configure structured logging with console + rotating file output.

    Uses Python's standard logging — no external log framework required.
    """
    log_dir = Path(config.logging.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    level = getattr(logging, config.logging.level.upper(), logging.INFO)

    # Root logger
    root = logging.getLogger()
    root.setLevel(level)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    root.addHandler(console_handler)

    # Rotating file handler
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / "sentinelpi.log",
            maxBytes=config.logging.max_bytes,
            backupCount=config.logging.backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        root.addHandler(file_handler)
    except OSError as exc:
        logger.warning("Cannot open log file: %s — logging to console only.", exc)


def build_detector_thread(
    detector_instance,
    alert_manager: "AlertManager",
    stop_event: threading.Event,
    poll_interval: int = 60,
    name: Optional[str] = None,
) -> threading.Thread:
    """
    Wrap a detector's poll() method in a daemon thread.

    The thread calls poll() every `poll_interval` seconds and passes any
    returned alerts to the explicitly-provided alert manager.
    """
    def _run():
        logger.info("%s thread started.", detector_instance.name)
        while not stop_event.is_set():
            try:
                alerts = detector_instance.poll()
                if alerts:
                    alert_manager.process(alerts)
            except Exception as exc:
                logger.error("%s poll error: %s", detector_instance.name, exc, exc_info=True)
            stop_event.wait(timeout=poll_interval)
        logger.info("%s thread stopped.", detector_instance.name)

    thread = threading.Thread(
        target=_run,
        name=name or detector_instance.name,
        daemon=True,
    )
    return thread


class SentinelPi:
    """
    Main application class. Initializes all subsystems and manages lifecycle.
    """

    def __init__(self, config_path: Optional[str] = None) -> None:
        self.config = load_config(config_path)
        setup_logging(self.config)
        logger.info("=" * 60)
        logger.info("SentinelPi starting up...")
        logger.info("Config: %s", self.config._source_path or "built-in defaults")
        logger.info("=" * 60)
        self._log_capabilities()

        self._stop_event = threading.Event()
        self._threads: List[threading.Thread] = []

        # Initialize core subsystems
        self._db = Database(
            db_path=self.config.storage.db_path,
            retention_days=self.config.storage.retention_days,
        )
        self._baseline = BaselineEngine(self.config, self._db)
        self._device_tracker = DeviceTracker(self.config, self._db)
        self._alert_manager = AlertManager(self.config, self._db, self._device_tracker)

        # Optional GeoIP
        if self.config.monitoring.geo_enabled:
            init_geo(self.config.monitoring.geo_db_path)
        if self.config.monitoring.asn_reputation_enabled:
            init_asn(self.config.monitoring.asn_db_path)

        # Register notifiers
        self._ntfy_notifier: Optional[NtfyNotifier] = None
        self._setup_notifiers()

        # Active-response orchestrator (Phase 2) — fully inert unless enabled.
        self._responder_manager: Optional[ResponderManager] = None
        self._setup_responders()

        # Initialize detectors
        detector_kwargs: dict[str, Any] = dict(
            config=self.config,
            db=self._db,
            baseline=self._baseline,
            device_tracker=self._device_tracker,
        )
        self._arp_detector = ARPDetector(**detector_kwargs)
        self._beacon_detector = BeaconDetector(**detector_kwargs)
        self._connection_detector = ConnectionDetector(**detector_kwargs)
        self._dns_detector = DNSDetector(**detector_kwargs)
        self._lateral_detector = LateralMovementDetector(**detector_kwargs)
        self._auth_detector = AuthLogDetector(**detector_kwargs)

        # Encrypted-DNS bypass detector (event-driven, no extra deps).
        self._doh_detector: Optional[DoHDetector] = None
        if self.config.monitoring.doh_detection_enabled:
            self._doh_detector = DoHDetector(**detector_kwargs)

        # New-country detector — only useful when GeoIP is available.
        self._geo_country_detector: Optional[GeoCountryDetector] = None
        if self.config.monitoring.geo_enabled:
            self._geo_country_detector = GeoCountryDetector(**detector_kwargs)

        # ASN reputation detector — only useful when the ASN DB is available.
        self._asn_detector: Optional[ASNReputationDetector] = None
        if self.config.monitoring.asn_reputation_enabled:
            self._asn_detector = ASNReputationDetector(**detector_kwargs)

        # Per-host active-hours anomaly detector.
        self._active_hours_detector: Optional[ActiveHoursDetector] = None
        if self.config.monitoring.active_hours_detection_enabled:
            self._active_hours_detector = ActiveHoursDetector(**detector_kwargs)

        # Per-host behaviour profile detector (ports / internal peers).
        self._host_profile_detector: Optional[HostProfileDetector] = None
        if self.config.monitoring.host_profile_detection_enabled:
            self._host_profile_detector = HostProfileDetector(**detector_kwargs)

        # Threat-intelligence service + detector (opt-in). The service loads any
        # cached feeds now; a background thread refreshes them (see _start_threat_intel).
        self._intel_service: Optional[ThreatIntelService] = None
        self._threat_intel_detector: Optional[ThreatIntelDetector] = None
        if self.config.threat_intel.enabled:
            self._intel_service = ThreatIntelService(self.config.threat_intel)
            self._intel_service.load()
            self._threat_intel_detector = ThreatIntelDetector(
                intel=self._intel_service, **detector_kwargs
            )

        # Packet capture event queue and router
        self._capture_queue: queue.Queue = queue.Queue(maxsize=50_000)
        self._packet_capture: Optional[PacketCapture] = None
        self._honeypot: Optional[HoneypotService] = None

        # Flow ingestion sources (conntrack / NetFlow / IPFIX) feed the same
        # queue; the event router is shared and started once by whichever source
        # comes up (packet capture and/or flow ingest).
        self._flow_sources: List[Any] = []
        self._event_router_started = False

        # Dashboard
        self._dashboard_server: Optional["DashboardServer"] = None
        self._watchdog: Optional[OperationalWatchdog] = None

    def _log_capabilities(self) -> None:
        """
        Log which optional features are active vs. degraded at startup.

        Every optional dependency is imported behind an *_AVAILABLE flag and the
        tool runs in a reduced mode without it. Surfacing this once makes "why
        am I not seeing packet-level alerts?" answerable from the log.
        """
        from .capture.packet_capture import SCAPY_AVAILABLE
        from .ui.dashboard import FLASK_AVAILABLE, WAITRESS_AVAILABLE
        from .utils.geo import MAXMINDDB_AVAILABLE

        features = [
            ("Packet capture (scapy)", SCAPY_AVAILABLE,
             "real-time ARP/DNS/connection events; proc polling only without it"),
            ("Web dashboard (flask)", FLASK_AVAILABLE, "dashboard disabled without it"),
            ("Production server (waitress)", WAITRESS_AVAILABLE,
             "dashboard falls back to the dev server without it"),
            ("GeoIP (maxminddb)", MAXMINDDB_AVAILABLE,
             "country tagging disabled without it"),
        ]
        disabled = [(name, why) for name, ok, why in features if not ok]
        for name, ok, _why in features:
            logger.info("  feature %-32s %s", name, "enabled" if ok else "DISABLED")
        if disabled:
            logger.warning(
                "Running in degraded mode — %d optional feature(s) disabled: %s",
                len(disabled), "; ".join(f"{name} ({why})" for name, why in disabled),
            )

    def _setup_responders(self) -> None:
        """
        Wire up the active-response orchestrator. Fully inert unless
        response.enabled; even then dry-run by default (see ResponderManager).
        """
        rc = self.config.response
        if not rc.enabled:
            return
        manager = ResponderManager(self.config)
        if rc.firewall_block_enabled:
            manager.add_responder(FirewallResponder(self.config))
        if rc.dns_sinkhole_enabled:
            manager.add_responder(DNSSinkholeResponder(self.config))
        if rc.arp_restore_enabled:
            manager.add_responder(ARPRestoreResponder(self.config))
        if rc.killswitch_enabled:
            manager.add_responder(KillSwitchResponder(self.config))
        self._alert_manager.set_responder_manager(manager)
        self._responder_manager = manager
        # Close the approval loop: push Approve/Reject buttons to ntfy when an
        # action is queued for human approval.
        if self._ntfy_notifier is not None:
            manager.set_pending_notifier(self._ntfy_notifier.notify_pending)
            logger.info("ntfy actionable approvals wired to responder manager.")
        mode = "DRY-RUN" if rc.dry_run else "ARMED"
        logger.warning("Active response ENABLED (%s). Responders: %d.",
                       mode, len(manager._responders))

    def _setup_notifiers(self) -> None:
        """Register enabled notifiers with the alert manager."""
        from .models import Severity

        # Always: console output
        self._alert_manager.add_notifier(ConsoleNotifier(min_severity=Severity.INFO))

        # Always: JSON alerts file
        self._alert_manager.add_notifier(FileNotifier(
            log_path=self.config.logging.json_alerts_file,
            min_severity=Severity.INFO,
            max_bytes=self.config.logging.max_bytes,
            backup_count=self.config.logging.backup_count,
        ))

        # Optional: email
        if self.config.notifications.email_enabled:
            self._alert_manager.add_notifier(EmailNotifier(self.config))
            logger.info("Email notifications enabled.")

        # Optional: webhook
        if self.config.notifications.webhook_enabled and self.config.notifications.webhook_url:
            self._alert_manager.add_notifier(WebhookNotifier(self.config))
            logger.info("Webhook notifications enabled: %s", self.config.notifications.webhook_url)

        # Optional: ntfy (with Approve/Reject action buttons for pending responses)
        if self.config.notifications.ntfy_enabled and self.config.notifications.ntfy_topic:
            self._ntfy_notifier = NtfyNotifier(self.config)
            self._alert_manager.add_notifier(self._ntfy_notifier)
            logger.info("ntfy notifications enabled: %s/%s",
                        self.config.notifications.ntfy_server.rstrip("/"),
                        self.config.notifications.ntfy_topic)

        # Optional: SMS via Twilio
        if self.config.notifications.sms_enabled:
            self._alert_manager.add_notifier(TwilioSMSNotifier(self.config))
            logger.info("Twilio SMS notifications enabled for %d recipient(s).",
                        len(self.config.notifications.sms_to))

        # Optional: SIEM export over syslog (ECS or CEF)
        if self.config.notifications.siem_enabled and self.config.notifications.siem_host:
            self._alert_manager.add_notifier(SyslogNotifier(self.config))
            logger.info("SIEM export enabled: %s syslog %s://%s:%d",
                        self.config.notifications.siem_format,
                        self.config.notifications.siem_transport,
                        self.config.notifications.siem_host,
                        self.config.notifications.siem_port)

        # Optional: OpenTelemetry logs export via OTLP/HTTP
        if self.config.notifications.otlp_enabled and self.config.notifications.otlp_endpoint:
            self._alert_manager.add_notifier(OTLPNotifier(self.config))
            logger.info("OpenTelemetry export enabled: OTLP/HTTP to %s",
                        self.config.notifications.otlp_endpoint)

        # Sensor mode: forward alerts to a central collector (Phase 3).
        if self.config.cluster.role == "sensor" and self.config.cluster.collector_url:
            self._alert_manager.add_notifier(ForwardNotifier(self.config))
            logger.info("Sensor mode: forwarding alerts to collector %s",
                        self.config.cluster.collector_url)

    def _start_packet_capture(self) -> None:
        """Start scapy packet capture and event routing thread."""
        if not self.config.monitoring.packet_capture_enabled:
            logger.info("Packet capture disabled in config.")
            return

        mirror = self.config.network.mirror_mode
        self._packet_capture = PacketCapture(
            interfaces=self.config.network.interfaces,
            event_queue=self._capture_queue,
            promisc=True,   # required for SPAN/mirror visibility and full LAN coverage
        )
        if mirror:
            logger.info(
                "Mirror/SPAN-port mode enabled — capturing all subnet traffic "
                "promiscuously on %s.", ", ".join(self.config.network.interfaces),
            )
        ok = self._packet_capture.start()
        if not ok:
            logger.warning("Packet capture unavailable — using proc polling only.")
            return

        self._ensure_event_router()

    def _build_event_detectors(self) -> list:
        """Ordered list of detectors that consume packet-capture/flow events."""
        event_detectors = [
            self._arp_detector,
            self._dns_detector,
            self._beacon_detector,
            self._connection_detector,
            self._lateral_detector,
        ]
        for optional in (
            self._doh_detector,
            self._geo_country_detector,
            self._asn_detector,
            self._active_hours_detector,
            self._host_profile_detector,
            self._threat_intel_detector,
        ):
            if optional is not None:
                event_detectors.append(optional)
        return event_detectors

    def _ensure_event_router(self) -> None:
        """
        Start the event router thread (idempotent). The router reads the shared
        capture queue and dispatches each event to every detector. It's started
        by whichever event source comes up first — packet capture or flow
        ingest — so flow ingestion works even when scapy capture is disabled.
        """
        if self._event_router_started:
            return

        event_detectors = self._build_event_detectors()

        def _route_events():
            logger.info("Event router started.")
            while not self._stop_event.is_set():
                try:
                    event = self._capture_queue.get(timeout=1.0)
                    if self._watchdog is not None:
                        self._watchdog.record_event()
                    for det in event_detectors:
                        try:
                            alerts = det.process_event(event)
                            if alerts:
                                self._alert_manager.process(alerts)
                        except Exception as exc:
                            logger.error("Detector %s event error: %s", det.name, exc)
                except queue.Empty:
                    continue
                except Exception as exc:
                    logger.error("Event router error: %s", exc)
            logger.info("Event router stopped.")

        router_thread = threading.Thread(target=_route_events, daemon=True, name="EventRouter")
        self._threads.append(router_thread)
        router_thread.start()
        self._event_router_started = True
        if self._watchdog is not None:
            self._watchdog.set_event_sources_active(True)

    def _start_flow_ingest(self) -> None:
        """
        Start router/firewall flow ingestion (Phase 3). Both sources are opt-in
        and feed the shared capture queue, so every connection detector sees
        flows the Pi can't sniff directly. Starts the event router if a source
        comes up and packet capture didn't already.
        """
        fc = self.config.flow
        started = []

        if fc.conntrack_enabled:
            src = ConntrackFlowSource(
                self._capture_queue,
                interval_seconds=fc.conntrack_interval_seconds,
                command=fc.conntrack_command,
                stop_event=self._stop_event,
            )
            if src.start():
                self._flow_sources.append(src)
                started.append("conntrack")
            else:
                logger.warning(
                    "conntrack flow ingest unavailable — '%s' and %s both unreadable.",
                    fc.conntrack_command, ConntrackFlowSource.PROC_PATH,
                )

        if fc.netflow_enabled:
            collector = NetFlowCollector(
                self._capture_queue,
                bind_host=fc.netflow_bind_host,
                bind_port=fc.netflow_port,
                stop_event=self._stop_event,
            )
            if collector.start():
                self._flow_sources.append(collector)
                started.append(f"netflow/ipfix:{fc.netflow_port}")

        if fc.filterlog_enabled:
            flog = FilterlogSource(
                self._capture_queue,
                path=fc.filterlog_path,
                interval_seconds=fc.filterlog_interval_seconds,
                stop_event=self._stop_event,
            )
            if flog.start():
                self._flow_sources.append(flog)
                started.append("filterlog")
            else:
                logger.warning(
                    "filterlog flow ingest unavailable — %s not readable.", fc.filterlog_path,
                )

        if started:
            logger.info("Flow ingest active: %s", ", ".join(started))
            self._ensure_event_router()

    def _start_polling_threads(self) -> None:
        """Start all detector polling threads."""
        poll_configs = [
            (self._device_tracker, 30, "DeviceTracker"),
            (self._connection_detector, 60, "ConnectionDetector"),
            (self._auth_detector, 30, "AuthLogDetector"),
            (self._beacon_detector, 60, "BeaconDetector"),
            (self._lateral_detector, 60, "LateralMovementDetector"),
            (self._arp_detector, 60, "ARPDetector"),
        ]

        for det_or_tracker, interval, name in poll_configs:
            if hasattr(det_or_tracker, "run_forever"):
                # DeviceTracker has its own loop method
                t = threading.Thread(
                    target=det_or_tracker.run_forever,
                    args=(self._stop_event,),
                    name=name,
                    daemon=True,
                )
            else:
                t = build_detector_thread(
                    det_or_tracker, self._alert_manager, self._stop_event, interval, name
                )
            self._threads.append(t)
            t.start()
            logger.debug("Started thread: %s", name)

    def _start_threat_intel(self) -> None:
        """Refresh threat-intel feeds on startup, then on a daily cadence."""
        if self._intel_service is None:
            return

        interval = max(1, self.config.threat_intel.refresh_interval_hours) * 3600

        def _refresh_loop():
            logger.info("Threat-intel refresh thread started.")
            while not self._stop_event.is_set():
                try:
                    self._intel_service.refresh()
                    if self._watchdog is not None:
                        self._watchdog.record_threat_intel_refresh(success=True)
                    logger.info(
                        "Threat intel active: %d indicators loaded.",
                        self._intel_service.indicator_count,
                    )
                except Exception as exc:
                    logger.error("Threat-intel refresh failed: %s", exc)
                    if self._watchdog is not None:
                        self._watchdog.record_threat_intel_refresh(success=False, error=str(exc))
                self._stop_event.wait(timeout=interval)
            logger.info("Threat-intel refresh thread stopped.")

        t = threading.Thread(target=_refresh_loop, daemon=True, name="ThreatIntelRefresh")
        self._threads.append(t)
        t.start()

    def _start_honeypot(self) -> None:
        """Open canary ports if enabled; hits flow straight to the alert manager."""
        if not self.config.monitoring.honeypot_enabled:
            return
        self._honeypot = HoneypotService(self.config, on_alert=self._alert_manager.process_one)
        self._honeypot.start()

    def _start_dashboard(self) -> None:
        """Start the web dashboard if enabled."""
        if not self.config.dashboard.enabled:
            return

        from .ui.dashboard import create_app, DashboardServer, FLASK_AVAILABLE
        if not FLASK_AVAILABLE:
            logger.warning("Flask not installed — dashboard not available.")
            return

        app = create_app(
            config=self.config,
            db=self._db,
            device_tracker=self._device_tracker,
            baseline=self._baseline,
            alert_manager=self._alert_manager,
            responder_manager=self._responder_manager,
            watchdog=self._watchdog,
        )
        if app is None:
            logger.warning("Dashboard app could not be created — dashboard not started.")
            return
        self._dashboard_server = DashboardServer(app, self.config)
        self._dashboard_server.start()

    def _maintenance_loop(self) -> None:
        """
        Periodic maintenance: DB cleanup, vacuum, stats logging.

        Runs in the main thread to keep daemon threads alive.
        """
        last_vacuum = time.time()
        last_purge = time.time()
        last_stats_log = time.time()
        last_watchdog = 0.0
        vacuum_interval = self.config.storage.vacuum_interval_seconds
        watchdog_interval = max(1, self.config.monitoring.self_monitoring_interval_seconds)

        while not self._stop_event.is_set():
            now = time.time()

            if (
                self.config.monitoring.self_monitoring_enabled
                and self._watchdog is not None
                and now - last_watchdog >= watchdog_interval
            ):
                try:
                    alerts = self._watchdog.check()
                    if alerts:
                        self._alert_manager.process(alerts)
                except Exception as exc:
                    logger.error("Watchdog check failed: %s", exc, exc_info=True)
                last_watchdog = now

            # Purge old records every 6 hours
            if now - last_purge > 21600:
                try:
                    self._db.purge_old_records()
                except Exception as exc:
                    logger.error("Purge error: %s", exc)
                last_purge = now

            # Vacuum once per day
            if now - last_vacuum > vacuum_interval:
                try:
                    self._db.vacuum()
                except Exception as exc:
                    logger.error("Vacuum error: %s", exc)
                last_vacuum = now

            # Log operational stats every 15 minutes
            if now - last_stats_log > 900:
                stats = self._alert_manager.get_stats()
                logger.info(
                    "Stats: %d alerts processed, %d suppressed, %d fired. "
                    "Devices: %d. Queue: %d.",
                    stats["total_processed"],
                    stats["total_suppressed"],
                    stats["total_fired"],
                    self._device_tracker.get_device_count(),
                    self._capture_queue.qsize(),
                )
                last_stats_log = now

            self._stop_event.wait(timeout=60.0)

    def start(self) -> None:
        """Start all subsystems and enter the maintenance loop."""
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        logger.info("Starting packet capture...")
        self._start_packet_capture()

        logger.info("Starting flow ingestion...")
        self._start_flow_ingest()

        logger.info("Starting detector polling threads...")
        self._start_polling_threads()

        logger.info("Starting web dashboard...")
        self._watchdog = OperationalWatchdog(self.config, self._capture_queue, self._threads)
        self._watchdog.set_event_sources_active(self._event_router_started)
        self._start_dashboard()

        self._start_threat_intel()
        self._start_honeypot()

        # Emit a system startup alert
        from .models import Alert, AlertCategory, Severity
        self._alert_manager.process_one(Alert(
            severity=Severity.INFO,
            category=AlertCategory.SYSTEM,
            affected_host="localhost",
            title="SentinelPi started",
            description=(
                f"Monitoring started on interfaces: "
                f"{', '.join(self.config.network.interfaces)}. "
                f"Subnets: {', '.join(self.config.network.subnets)}. "
                f"Baseline learning phase: {self.config.monitoring.baseline_learning_hours}h."
            ),
            recommended_action="No action needed.",
            confidence=1.0,
            dedup_key="system:startup",
        ))

        logger.info("SentinelPi running. Press Ctrl+C to stop.")
        logger.info("Dashboard: http://%s:%d/", self.config.dashboard.host, self.config.dashboard.port)

        # Enter maintenance loop (blocks until stop_event is set)
        self._maintenance_loop()

        logger.info("Maintenance loop exited — shutting down.")
        self._shutdown()

    def _handle_signal(self, signum: int, frame) -> None:
        """Handle SIGTERM/SIGINT for graceful shutdown."""
        sig_name = signal.Signals(signum).name
        logger.info("Received %s — initiating graceful shutdown...", sig_name)
        self._stop_event.set()

    def _shutdown(self) -> None:
        """Clean up all resources on shutdown."""
        logger.info("Stopping packet capture...")
        if self._packet_capture:
            self._packet_capture.stop()

        for src in self._flow_sources:
            try:
                src.stop()
            except Exception as exc:
                logger.warning("Error stopping flow source %s: %s", type(src).__name__, exc)

        if self._honeypot:
            self._honeypot.stop()

        if self._dashboard_server:
            self._dashboard_server.stop()

        logger.info("Waiting for threads to finish...")
        for t in self._threads:
            t.join(timeout=5.0)
            if t.is_alive():
                logger.warning("Thread %s did not stop cleanly.", t.name)

        logger.info("Closing notifiers...")
        self._alert_manager.close_notifiers()

        logger.info("Closing database...")
        self._db.close()

        logger.info("SentinelPi stopped cleanly.")


def main() -> None:
    """Command-line entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="SentinelPi — Defensive network anomaly monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sentinelpi                           # Start with auto-detected config
  sentinelpi --config /etc/sentinelpi/sentinelpi.yaml
  sentinelpi --check-config            # Validate config and exit
  sentinelpi --check                   # Validate config and actively test outputs
  sentinelpi --backup /mnt/usb/snap.tar.gz    # Snapshot the database (safe while running)
  sentinelpi --restore /mnt/usb/snap.tar.gz   # Restore a snapshot (stop the service first)
  sentinelpi --version                 # Print version and exit
        """,
    )
    parser.add_argument(
        "--config", "-c",
        metavar="PATH",
        help="Path to configuration file",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Validate configuration and exit without starting",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate config, then actively test configured notifiers/responders",
    )
    parser.add_argument(
        "--backup",
        metavar="PATH",
        help="Write a snapshot of the database to PATH and exit (safe while running)",
    )
    parser.add_argument(
        "--restore",
        metavar="PATH",
        help="Restore the database from a snapshot at PATH and exit (stop the service first)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="With --restore, allow restoring a snapshot from a newer schema version",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print version and exit",
    )

    args = parser.parse_args()

    if args.version:
        from . import __version__
        print(f"SentinelPi {__version__}")
        sys.exit(0)

    if args.backup or args.restore:
        from .storage import backup as backup_mod
        config = load_config(args.config)
        db_path = config.storage.db_path
        try:
            if args.backup:
                manifest = backup_mod.create_backup(db_path, args.backup)
                print(f"Backup written to {args.backup}")
                print(f"  Source: {db_path}")
                print(f"  Schema: v{manifest['schema_version']}  "
                      f"SentinelPi: {manifest['sentinelpi_version']}")
                print(f"  Size:   {manifest['db_bytes']} bytes")
            else:
                manifest = backup_mod.restore_backup(args.restore, db_path, force=args.force)
                print(f"Restored {args.restore} to {db_path}")
                print(f"  Schema: v{manifest['schema_version']} "
                      f"(from SentinelPi {manifest.get('sentinelpi_version', '?')}, "
                      f"created {manifest.get('created_at', '?')})")
                if manifest.get("previous_db_saved_to"):
                    print(f"  Previous database saved to {manifest['previous_db_saved_to']}")
        except backup_mod.BackupError as exc:
            print(f"Error: {exc}")
            sys.exit(4)
        sys.exit(0)

    if args.check_config or args.check:
        config = load_config(args.config)
        issues = validate_config(config)
        if issues:
            print(f"Configuration INVALID (loaded from: {config._source_path or 'defaults'})")
            for issue in issues:
                print(f"  - {issue}")
            sys.exit(2)
        print(f"Configuration OK (loaded from: {config._source_path or 'defaults'})")
        print(f"  Interfaces: {config.network.interfaces}")
        print(f"  Subnets: {config.network.subnets}")
        print(f"  Sensitivity: {config.monitoring.sensitivity_profile}")
        print(f"  Dashboard: {'enabled' if config.dashboard.enabled else 'disabled'} "
              f"at {config.dashboard.host}:{config.dashboard.port}")
        if args.check:
            print("\nPreflight checks:")
            results = run_preflight(config)
            for result in results:
                print(f"  [{result.status.upper():4}] {result.name}: {result.detail}")
            if any(result.failed for result in results):
                sys.exit(3)
        sys.exit(0)

    app = SentinelPi(config_path=args.config)
    app.start()


if __name__ == "__main__":
    main()
