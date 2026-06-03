"""
utils/clock.py - Single, timezone-aware source of "now".

Why this exists
---------------
SentinelPi sprinkled ``clock.now()`` across detectors, the alert manager,
and storage. ``utcnow()`` returns a *naive* datetime (no tzinfo) and is
deprecated in 3.12+. Mixing naive and aware datetimes raises
``TypeError: can't compare offset-naive and offset-aware datetimes`` — a latent
bug waiting in any comparison between an alert timestamp and a cutoff.

Routing every "now" through one chokepoint gives two things:

1. **Consistency.** Everything is timezone-aware UTC, and ISO-8601 output
   carries an explicit ``+00:00`` offset (no more ``isoformat() + "Z"`` double
   labeling).
2. **Determinism in tests.** Swap in a :class:`FixedClock` (or monkeypatch
   :func:`now`) and detection becomes reproducible — no sleeping, no flakiness.

Usage
-----
Production code calls :func:`now` (or :func:`utcnow_iso`)::

    from ..utils import clock
    ts = clock.now()

Tests pin time with :func:`use_clock` / :class:`FixedClock`::

    with clock.use_clock(clock.FixedClock(some_instant)):
        ...

Note: wall-clock-local logic (e.g. user-facing "quiet hours") intentionally does
NOT go through here — that wants the operator's local time, not UTC.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator


class Clock:
    """Default clock: real timezone-aware UTC wall time."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class FixedClock(Clock):
    """
    Clock frozen at a fixed instant, for deterministic tests.

    The instant is coerced to timezone-aware UTC so it never mixes with the
    aware datetimes the rest of the system produces.
    """

    def __init__(self, instant: datetime) -> None:
        if instant.tzinfo is None:
            instant = instant.replace(tzinfo=timezone.utc)
        self._instant = instant.astimezone(timezone.utc)

    def now(self) -> datetime:
        return self._instant


# Module-level active clock. Swappable so tests can pin time process-wide.
_clock: Clock = Clock()


def now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return _clock.now()


def utcnow_iso() -> str:
    """Current time as an ISO-8601 string with an explicit UTC offset."""
    return now().isoformat()


def set_clock(clock: Clock) -> Clock:
    """Install a new active clock, returning the previous one."""
    global _clock
    previous, _clock = _clock, clock
    return previous


def reset_clock() -> None:
    """Restore the default real clock."""
    global _clock
    _clock = Clock()


@contextmanager
def use_clock(clock: Clock) -> Iterator[Clock]:
    """Temporarily install ``clock`` for the duration of the ``with`` block."""
    previous = set_clock(clock)
    try:
        yield clock
    finally:
        set_clock(previous)
