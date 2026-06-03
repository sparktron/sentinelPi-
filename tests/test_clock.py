"""
tests/test_clock.py - Tests for the timezone-aware clock abstraction (CODE_REVIEW M1).

The clock exists to (a) make every "now" timezone-aware UTC so naive/aware
comparisons can't blow up, and (b) make time injectable so detection is
deterministic in tests.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sentinelpi.utils import clock


def test_now_is_timezone_aware_utc():
    n = clock.now()
    assert n.tzinfo is not None
    assert n.utcoffset() == timezone.utc.utcoffset(None)


def test_utcnow_iso_carries_explicit_offset():
    iso = clock.utcnow_iso()
    # Aware ISO-8601 ends with an offset, never a bare timestamp or a "Z" tack-on.
    assert iso.endswith("+00:00")
    # Round-trips back to an aware datetime.
    assert datetime.fromisoformat(iso).tzinfo is not None


def test_fixed_clock_freezes_time():
    instant = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    with clock.use_clock(clock.FixedClock(instant)):
        assert clock.now() == instant
        assert clock.now() == instant  # does not advance
    # Restored afterwards.
    assert clock.now() != instant


def test_fixed_clock_coerces_naive_instant_to_utc():
    naive = datetime(2026, 1, 2, 3, 4, 5)
    fc = clock.FixedClock(naive)
    assert fc.now().tzinfo is not None
    assert fc.now() == naive.replace(tzinfo=timezone.utc)


def test_use_clock_restores_previous_on_exception():
    sentinel = clock.FixedClock(datetime(2000, 1, 1, tzinfo=timezone.utc))
    try:
        with clock.use_clock(sentinel):
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    # The default real clock is back — now() is current, not year 2000.
    assert clock.now().year >= 2026


def test_alert_timestamp_uses_injected_clock():
    """Alert default_factory routes through the clock, so it is controllable."""
    from sentinelpi.models import Alert, AlertCategory, Severity

    instant = datetime(2026, 6, 2, 12, 0, 0, tzinfo=timezone.utc)
    with clock.use_clock(clock.FixedClock(instant)):
        alert = Alert(
            severity=Severity.LOW,
            category=AlertCategory.SYSTEM,
            affected_host="192.168.1.10",
            title="t",
        )
    assert alert.timestamp == instant
