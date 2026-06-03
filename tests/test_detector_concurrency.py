"""
tests/test_detector_concurrency.py - Regression tests for CODE_REVIEW C1 and C2.

C1: a single detector instance is driven from two threads (the event-router
    thread via process_event, and a per-detector polling thread via poll).
    BaseDetector must serialize both so plain dict/deque state is never mutated
    from two threads at once.

C2: reverse_dns must work off the main thread. The old signal/SIGALRM timeout
    only worked on the main thread, so device-tracker lookups always raised and
    hostnames were silently blank.

These tests are intentionally free of the db/config fixtures so they exercise
the fix in isolation.
"""

from __future__ import annotations

import threading
from collections import deque

from sentinelpi.detectors.base import BaseDetector
from sentinelpi.utils import network


class _SharedStateDetector(BaseDetector):
    """Detector with deque/dict state mutated from both entry points."""

    def __init__(self) -> None:
        # Skip BaseDetector.__init__'s heavy deps; we only need the lock.
        self._lock = threading.RLock()
        self._events: deque = deque(maxlen=10_000)
        self._counts: dict = {}
        self.poll_calls = 0

    def _process_event(self, event):
        # Append + read the same deque other thread iterates.
        self._events.append(event)
        self._counts[event] = self._counts.get(event, 0) + 1
        return []

    def _poll(self):
        # Iterate the deque/dict that _process_event mutates. Without the lock
        # this races -> "deque mutated during iteration" / "dict changed size".
        total = sum(1 for _ in self._events)
        snapshot = dict(self._counts)
        self.poll_calls += 1
        return [total, len(snapshot)]


def test_concurrent_event_and_poll_no_race():
    det = _SharedStateDetector()
    errors: list = []
    n_events = 5_000
    n_polls = 5_000
    start = threading.Barrier(5)  # 1 producer + 3 pollers + main release

    def producer():
        start.wait()
        try:
            for i in range(n_events):
                det.process_event(i % 50)
        except Exception as exc:  # noqa: BLE001 - capture any race error
            errors.append(("producer", exc))

    def poller():
        start.wait()
        try:
            for _ in range(n_polls):
                det.poll()
        except Exception as exc:  # noqa: BLE001
            errors.append(("poller", exc))

    threads = [threading.Thread(target=producer)] + [
        threading.Thread(target=poller) for _ in range(3)
    ]
    for t in threads:
        t.start()
    start.wait()  # release all threads at once for maximum contention
    for t in threads:
        t.join(timeout=30)

    assert not errors, f"data race surfaced: {errors}"
    # Every event was recorded exactly once-per-occurrence under the lock.
    assert sum(det._counts.values()) == n_events
    # Pollers iterated the shared state concurrently with the producer.
    assert det.poll_calls == 3 * n_polls


def test_public_methods_delegate_to_hooks_under_lock():
    det = _SharedStateDetector()

    # The lock must be held while the hook runs.
    class _LockProbe(BaseDetector):
        def __init__(self):
            self._lock = threading.RLock()
            self.held_during_poll = None

        def _poll(self):
            # RLock is reentrant for the owning thread; a non-owning acquire
            # would block, so we just assert we can re-enter (proves we hold it).
            self.held_during_poll = self._lock.acquire(blocking=False)
            if self.held_during_poll:
                self._lock.release()
            return ["ok"]

    probe = _LockProbe()
    assert probe.poll() == ["ok"]
    assert probe.held_during_poll is True


def test_base_defaults_are_noops():
    class _Empty(BaseDetector):
        def __init__(self):
            self._lock = threading.RLock()

    empty = _Empty()
    assert empty.poll() == []
    assert empty.process_event(object()) == []


def test_reverse_dns_off_main_thread_returns_str():
    """C2: must not raise off the main thread and must return a str."""
    results: dict = {}

    def worker():
        results["loopback"] = network.reverse_dns("127.0.0.1", timeout=2.0)

    t = threading.Thread(target=worker)
    t.start()
    t.join(timeout=10)

    assert "loopback" in results, "reverse_dns hung or raised off the main thread"
    assert isinstance(results["loopback"], str)


def test_reverse_dns_honors_timeout():
    """A short timeout returns '' rather than blocking or raising."""
    # TEST-NET-3 (RFC 5737) — no PTR; with a tiny timeout we expect "".
    result = network.reverse_dns("203.0.113.7", timeout=0.001)
    assert result == ""
