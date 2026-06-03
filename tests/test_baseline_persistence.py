"""
tests/test_baseline_persistence.py - Regression tests for CODE_REVIEW H4.

H4: update_hourly_baseline used a biased EWMA recurrence (mislabeled "Welford")
    and a non-atomic read-modify-write. It is now a pure atomic upsert that
    snapshots the correct in-memory RunningStats. These tests pin:
      - the persisted avg/stddev match the true population statistics, and
      - the upsert overwrites (idempotent) rather than accumulating.
"""

from __future__ import annotations

import statistics

from sentinelpi.baseline.engine import RunningStats


def _truth(values):
    mean = statistics.fmean(values)
    # Population variance (M2 / n), matching RunningStats.variance.
    pvar = statistics.pvariance(values)
    return mean, pvar ** 0.5


def test_running_stats_matches_population_statistics():
    values = [3, 7, 7, 19, 2, 11, 5, 5, 8, 13]
    rs = RunningStats()
    for v in values:
        rs.update(float(v))

    mean, stddev = _truth(values)
    assert abs(rs.mean - mean) < 1e-9
    assert abs(rs.stddev - stddev) < 1e-9


def test_snapshot_roundtrips_through_db(db):
    values = [10, 12, 9, 11, 30, 8, 10, 9, 11, 10]
    rs = RunningStats()
    for v in values:
        rs.update(float(v))

    db.update_hourly_baseline("192.168.1.5", 14, 2, rs.mean, rs.stddev, rs.n)

    row = db.get_hourly_baseline("192.168.1.5", 14, 2)
    assert row is not None
    assert abs(row["avg_conn"] - rs.mean) < 1e-9
    assert abs(row["stddev_conn"] - rs.stddev) < 1e-9
    assert row["sample_count"] == rs.n


def test_upsert_overwrites_not_accumulates(db):
    db.update_hourly_baseline("10.0.0.9", 0, 0, 5.0, 1.0, 10)
    db.update_hourly_baseline("10.0.0.9", 0, 0, 8.0, 2.0, 20)

    row = db.get_hourly_baseline("10.0.0.9", 0, 0)
    # Second write wins outright — no doubling of sample_count or drift in avg.
    assert row["avg_conn"] == 8.0
    assert row["stddev_conn"] == 2.0
    assert row["sample_count"] == 20
