"""
tests/test_memory_bounding.py - Regression tests for CODE_REVIEW H1.

H1: long-lived suppression / activity maps grew without bound for the life of
    the daemon. The AlertManager dedup cache and the per-detector _last_alert /
    activity-deque maps must evict entries that can no longer affect detection.

These tests poke the eviction helpers directly so they don't need the full
capture/poll plumbing.
"""

from __future__ import annotations

import threading
from collections import deque
from datetime import timedelta

from sentinelpi.detectors.base import BaseDetector
from sentinelpi.utils import clock


class _Bare(BaseDetector):
    """BaseDetector with just a lock, to reach the static eviction helpers."""

    def __init__(self) -> None:
        self._lock = threading.RLock()


def test_evict_expired_times_drops_only_old_keys():
    now = clock.now()
    time_map = {
        "fresh": now - timedelta(seconds=10),
        "stale": now - timedelta(seconds=400),
        "ancient": now - timedelta(days=2),
        "future_mute": now + timedelta(days=7),
    }
    evicted = _Bare._evict_expired_times(time_map, max_age_seconds=300)

    assert evicted == 2
    assert set(time_map) == {"fresh", "future_mute"}


def test_evict_idle_deques_handles_tuple_and_bare_entries():
    now = clock.now()
    deque_map = {
        "active_tuple": deque([(now - timedelta(seconds=5), 22)]),
        "idle_tuple": deque([(now - timedelta(seconds=120), 80)]),
        "active_bare": deque([now - timedelta(seconds=5)]),
        "idle_bare": deque([now - timedelta(seconds=120)]),
        "empty": deque(),
    }
    evicted = _Bare._evict_idle_deques(deque_map, max_age_seconds=60)

    assert evicted == 3
    assert set(deque_map) == {"active_tuple", "active_bare"}


def test_alert_manager_dedup_cache_is_bounded():
    """The dedup cache must not grow unbounded as distinct keys fire."""
    from sentinelpi.alerts import manager as mgr

    # Build a no-deps AlertManager: we only exercise the prune path.
    am = mgr.AlertManager.__new__(mgr.AlertManager)
    am._lock = threading.Lock()
    am._recent_dedup = {}

    old = clock.now() - timedelta(seconds=mgr._MAX_COOLDOWN_SECONDS + 600)
    # Fill well past the prune threshold with already-expired keys.
    for i in range(mgr._DEDUP_PRUNE_THRESHOLD + 500):
        am._recent_dedup[f"expired:{i}"] = old
    # A couple of fresh + mute entries that must survive.
    am._recent_dedup["fresh"] = clock.now()
    am._recent_dedup["mute"] = clock.now() + timedelta(days=7)

    am._prune_dedup()

    assert "fresh" in am._recent_dedup
    assert "mute" in am._recent_dedup
    # All the expired keys are gone -> cache collapsed back to the live set.
    assert len(am._recent_dedup) == 2
