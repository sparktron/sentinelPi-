"""
tests/test_baseline.py - Tests for the baseline engine.

Tests:
- RunningStats Welford algorithm correctness
- Connection spike detection
- DNS domain recording and lookup
- Destination recording
- Learning phase suppression
"""

from __future__ import annotations

import math
import pytest
from datetime import datetime

from sentinelpi.baseline.engine import RunningStats, BaselineEngine


class TestRunningStats:

    def test_initial_state(self):
        stats = RunningStats()
        assert stats.n == 0
        assert stats.mean == 0.0
        assert stats.stddev == 0.0

    def test_single_update(self):
        stats = RunningStats()
        stats.update(10.0)
        assert stats.n == 1
        assert stats.mean == 10.0
        assert stats.stddev == 0.0

    def test_mean_converges(self):
        """Mean should converge to true mean after many updates."""
        stats = RunningStats()
        values = [1.0, 2.0, 3.0, 4.0, 5.0]
        for v in values:
            stats.update(v)
        assert abs(stats.mean - 3.0) < 1e-9
        assert stats.n == 5

    def test_stddev_known_set(self):
        """Stddev of [2, 4, 4, 4, 5, 5, 7, 9] = 2.0 (population)."""
        stats = RunningStats()
        for v in [2, 4, 4, 4, 5, 5, 7, 9]:
            stats.update(float(v))
        # Population stddev = 2.0
        assert abs(stats.stddev - 2.0) < 0.01

    def test_z_score_flat_baseline(self):
        """When stddev is near zero, z_score returns absolute deviation."""
        stats = RunningStats()
        for _ in range(10):
            stats.update(5.0)
        # Flat baseline — stddev ~ 0
        z = stats.z_score(5.0)
        assert z == 0.0

    def test_anomaly_detection(self):
        """Value 5 stddevs above mean should be flagged as anomalous."""
        stats = RunningStats()
        import random
        random.seed(42)
        for _ in range(100):
            stats.update(random.gauss(10.0, 1.0))  # Mean 10, stddev ~1

        # Value far above mean should be anomalous
        assert stats.is_anomalous(20.0, z_threshold=5.0)
        # Value near mean should not be
        assert not stats.is_anomalous(10.5, z_threshold=5.0)

    def test_not_anomalous_insufficient_samples(self):
        """With fewer than 5 samples, no anomaly should be flagged."""
        stats = RunningStats()
        for v in [1.0, 2.0, 3.0]:
            stats.update(v)
        assert not stats.is_anomalous(1000.0)


class TestBaselineEngine:

    def test_not_in_learning_phase_when_hours_zero(self, baseline):
        """Learning phase should be inactive when baseline_learning_hours=0."""
        assert not baseline.is_learning

    def test_dns_domain_first_seen_returns_true(self, baseline):
        """First time a domain is seen, record_dns_domain returns True."""
        is_new = baseline.record_dns_domain("example.com")
        assert is_new

    def test_dns_domain_second_seen_returns_false(self, baseline):
        """Second time same domain is seen, returns False."""
        baseline.record_dns_domain("example.com")
        is_new = baseline.record_dns_domain("example.com")
        assert not is_new

    def test_is_known_domain(self, baseline):
        """is_known_domain returns True after recording."""
        assert not baseline.is_known_domain("notrecorded.com")
        baseline.record_dns_domain("recorded.com")
        assert baseline.is_known_domain("recorded.com")

    def test_destination_tracking(self, baseline):
        """First destination is new; second is known."""
        is_new = baseline.record_destination("192.168.1.1", "8.8.8.8", 53, "udp")
        assert is_new
        is_new2 = baseline.record_destination("192.168.1.1", "8.8.8.8", 53, "udp")
        assert not is_new2

    def test_is_known_destination(self, baseline):
        assert not baseline.is_known_destination("192.168.1.1", "1.1.1.1", 443, "tcp")
        baseline.record_destination("192.168.1.1", "1.1.1.1", 443, "tcp")
        assert baseline.is_known_destination("192.168.1.1", "1.1.1.1", 443, "tcp")

    def test_connection_spike_no_data(self, baseline):
        """With no baseline data, no spike should be detected."""
        is_spike, z = baseline.check_connection_spike("192.168.1.100", 100)
        assert not is_spike

    def test_connection_spike_detected(self, baseline):
        """After building a baseline, a large spike should be detected."""
        ip = "192.168.1.100"
        # Build baseline: ~5 connections normally
        for _ in range(20):
            baseline.record_connection_count(ip, 5)
        # Now spike to 50 — 10x normal
        is_spike, z = baseline.check_connection_spike(ip, 50)
        assert is_spike
        assert z > 0

    def test_traffic_spike_no_data(self, baseline):
        """With no traffic baseline, no spike detected."""
        is_spike, z = baseline.check_traffic_spike("eth0", 1_000_000)
        assert not is_spike

    def test_summary_returns_dict(self, baseline):
        summary = baseline.get_summary()
        assert "is_learning" in summary
        assert "known_domains" in summary
        assert "known_destinations" in summary
        assert "known_listening_ports" in summary
