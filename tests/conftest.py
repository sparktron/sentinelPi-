"""
tests/conftest.py - Shared pytest fixtures for all test modules.

Provides pre-configured instances of core components using
temporary directories so tests are fully isolated.
"""

from __future__ import annotations

import tempfile
import os
import pytest

from sentinelpi.config.manager import Config, AlertThresholds, MonitoringConfig, NetworkConfig
from sentinelpi.storage.database import Database
from sentinelpi.baseline.engine import BaselineEngine
from sentinelpi.inventory.device_tracker import DeviceTracker
from sentinelpi.alerts.manager import AlertManager


@pytest.fixture
def tmp_dir(tmp_path):
    return tmp_path


@pytest.fixture
def config(tmp_path):
    """Return a Config with aggressive thresholds and temp paths for testing."""
    cfg = Config()
    cfg.network = NetworkConfig(
        interfaces=["eth0"],
        subnets=["192.168.1.0/24"],
        gateway_ip="192.168.1.1",
        gateway_mac="aa:bb:cc:00:00:01",
    )
    cfg.monitoring = MonitoringConfig(
        baseline_learning_hours=0,     # No learning phase in tests
        packet_capture_enabled=False,  # No root required
        auth_log_enabled=False,
        sensitivity_profile="aggressive",
    )
    cfg.thresholds = AlertThresholds(
        port_scan_ports_per_minute=5,
        beacon_min_intervals=5,
        beacon_cv_threshold=0.20,
        ssh_failures_threshold=5,
        ssh_failures_window_seconds=60,
        lateral_movement_dest_threshold=3,
    )
    # Use temp files for storage
    cfg.storage.db_path = str(tmp_path / "test.db")
    cfg.logging.json_alerts_file = str(tmp_path / "alerts.json")
    return cfg


@pytest.fixture
def db(config):
    database = Database(db_path=config.storage.db_path, retention_days=7)
    yield database
    database.close()


@pytest.fixture
def baseline(config, db):
    return BaselineEngine(config, db)


@pytest.fixture
def device_tracker(config, db):
    return DeviceTracker(config, db)


@pytest.fixture
def alert_manager(config, db, device_tracker):
    am = AlertManager(config, db, device_tracker)
    # Don't add any notifiers in tests (no console spam)
    return am
