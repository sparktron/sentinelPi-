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
  - DashboardServer thread: Flask dev server (if enabled).

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
import os
import queue
import signal
import sys
import threading
import time
from pathlib import Path
from typing import List, Optional

from .config.manager import Config, load_config
from .storage.database import Database
from .baseline.engine import BaselineEngine
from .inventory.device_tracker import DeviceTracker
from .alerts.manager import AlertManager
from .alerts.notifiers import ConsoleNotifier, FileNotifier, EmailNotifier, WebhookNotifier
from .detectors.arp_detector import ARPDetector
from .detectors.beacon_detector import BeaconDetector
from .detectors.connection_detector import ConnectionDetector
from .detectors.dns_detector import DNSDetector
from .detectors.lateral_movement_detector import LateralMovementDetector
from .detectors.auth_log_detector import AuthLogDetector
from .capture.packet_capture import PacketCapture
from .utils.geo import init_geo

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
    stop_event: threading.Event,
    poll_interval: int = 60,
    name: Optional[str] = None,
) -> threading.Thread:
    """
    Wrap a detector's poll() method in a daemon thread.

    The thread calls poll() every `poll_interval` seconds and passes
    any returned alerts to the alert manager via a closure.
    """
    def _run():
        logger.info("%s thread started.", detector_instance.name)
        while not stop_event.is_set():
            try:
                alerts = detector_instance.poll()
                if alerts:
                    detector_instance.config  # access config for alert_manager ref
                    # Alert manager reference is passed via _alert_manager attribute
                    am = getattr(detector_instance, "_alert_manager", None)
                    if am:
                        am.process(alerts)
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

        # Register notifiers
        self._setup_notifiers()

        # Initialize detectors
        detector_kwargs = dict(
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

        # Attach alert manager to each detector (needed in thread closures)
        for det in [
            self._arp_detector, self._beacon_detector, self._connection_detector,
            self._dns_detector, self._lateral_detector, self._auth_detector,
        ]:
            det._alert_manager = self._alert_manager  # type: ignore[attr-defined]

        # Packet capture event queue and router
        self._capture_queue: queue.Queue = queue.Queue(maxsize=50_000)
        self._packet_capture: Optional[PacketCapture] = None

        # Dashboard
        self._dashboard_server = None

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

    def _start_packet_capture(self) -> None:
        """Start scapy packet capture and event routing thread."""
        if not self.config.monitoring.packet_capture_enabled:
            logger.info("Packet capture disabled in config.")
            return

        self._packet_capture = PacketCapture(
            interfaces=self.config.network.interfaces,
            event_queue=self._capture_queue,
        )
        ok = self._packet_capture.start()
        if not ok:
            logger.warning("Packet capture unavailable — using proc polling only.")
            return

        # Event router: reads from capture queue and dispatches to detectors
        event_detectors = [
            self._arp_detector,
            self._dns_detector,
            self._beacon_detector,
            self._connection_detector,
            self._lateral_detector,
        ]

        def _route_events():
            logger.info("Event router started.")
            while not self._stop_event.is_set():
                try:
                    event = self._capture_queue.get(timeout=1.0)
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
                t = build_detector_thread(det_or_tracker, self._stop_event, interval, name)
            self._threads.append(t)
            t.start()
            logger.debug("Started thread: %s", name)

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
        )
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
        vacuum_interval = self.config.storage.vacuum_interval_seconds

        while not self._stop_event.is_set():
            now = time.time()

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

        logger.info("Starting detector polling threads...")
        self._start_polling_threads()

        logger.info("Starting web dashboard...")
        self._start_dashboard()

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

        logger.info("Waiting for threads to finish...")
        for t in self._threads:
            t.join(timeout=5.0)
            if t.is_alive():
                logger.warning("Thread %s did not stop cleanly.", t.name)

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
        "--version",
        action="store_true",
        help="Print version and exit",
    )

    args = parser.parse_args()

    if args.version:
        from . import __version__
        print(f"SentinelPi {__version__}")
        sys.exit(0)

    if args.check_config:
        config = load_config(args.config)
        print(f"Configuration OK (loaded from: {config._source_path or 'defaults'})")
        print(f"  Interfaces: {config.network.interfaces}")
        print(f"  Subnets: {config.network.subnets}")
        print(f"  Sensitivity: {config.monitoring.sensitivity_profile}")
        print(f"  Dashboard: {'enabled' if config.dashboard.enabled else 'disabled'} "
              f"at {config.dashboard.host}:{config.dashboard.port}")
        sys.exit(0)

    app = SentinelPi(config_path=args.config)
    app.start()


if __name__ == "__main__":
    main()
