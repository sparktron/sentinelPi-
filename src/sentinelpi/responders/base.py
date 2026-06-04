"""
responders/base.py - Pluggable active-response interface.

A Responder mirrors a Notifier, but instead of telling someone about an alert it
*acts* on it (block an IP, sinkhole a domain, …). The design is safety-first:

- A responder never decides on its own whether it's allowed to run. It only
  knows how to (a) recognise alerts it *could* act on (``can_handle``) and
  (b) describe the action as a :class:`ResponderAction` (``plan``). The
  ResponderManager owns the gating (master switch, dry-run, per-category opt-in)
  and is the only thing that calls ``execute``.
- ``plan`` must be side-effect-free, so an action can always be shown/logged
  before anything happens.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from ..models import Alert
from ..utils import clock


# Lifecycle of an action:
#   planned   - dry-run only, never executes
#   pending   - armed but awaiting human approval
#   executed  - ran successfully
#   failed    - ran but errored
#   rejected  - a human declined it
PLANNED = "planned"
PENDING = "pending"
EXECUTED = "executed"
FAILED = "failed"
REJECTED = "rejected"


@dataclass
class ResponderAction:
    """A single intended (or performed) response action."""
    responder: str               # responder name
    target: str                  # what it acts on (e.g. an IP)
    description: str             # human summary of the intended action
    commands: List[List[str]] = field(default_factory=list)  # argv(s) that would run, if any
    action_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=clock.now)
    status: str = PLANNED        # see lifecycle constants above
    dry_run: bool = True         # was this only planned, not executed?
    executed: bool = False       # did execute() actually run?
    success: bool = False        # did execution succeed?
    error: str = ""              # error message if execution failed
    alert_id: str = ""           # the alert that triggered this action


class BaseResponder(ABC):
    """Abstract base for active responders."""

    def __init__(self, config) -> None:
        self.config = config

    @property
    def name(self) -> str:
        return self.__class__.__name__

    @abstractmethod
    def can_handle(self, alert: Alert) -> bool:
        """Return True if this responder is applicable to ``alert``."""
        raise NotImplementedError

    @abstractmethod
    def plan(self, alert: Alert) -> Optional[ResponderAction]:
        """
        Build the action this responder *would* take for ``alert``, without any
        side effects. Return None if, on inspection, there's nothing to do.
        """
        raise NotImplementedError

    @abstractmethod
    def execute(self, action: ResponderAction) -> None:
        """
        Carry out ``action`` (mutating it in place: set executed/success/error).
        Only ever called by the manager when execution is permitted.
        """
        raise NotImplementedError
