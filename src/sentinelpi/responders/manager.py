"""
responders/manager.py - Orchestrates responders with safety gating.

The ResponderManager is the *only* component that decides whether an action
actually runs. Responders just describe what they could do; the manager applies
the two-key safety model:

    execute  ⇔  response.enabled  AND  NOT response.dry_run

When either key is missing the action is still *planned and recorded* (so the
dashboard/logs show "what would have happened"), but never executed. This makes
dry-run the honest default: you can watch the responder make decisions for days
before ever arming it.
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from typing import Deque, List

from .base import BaseResponder, ResponderAction
from ..models import Alert

logger = logging.getLogger(__name__)


class ResponderManager:
    """Runs applicable responders for an alert, under explicit safety gating."""

    def __init__(self, config) -> None:
        self.config = config
        self._responders: List[BaseResponder] = []
        self._lock = threading.Lock()
        # Recent actions (planned or executed) for the dashboard / audit.
        self._recent: Deque[ResponderAction] = deque(maxlen=200)

    def add_responder(self, responder: BaseResponder) -> None:
        with self._lock:
            self._responders.append(responder)
        logger.debug("Registered responder: %s", responder.name)

    def handle(self, alert: Alert) -> List[ResponderAction]:
        """
        Plan (and, if armed, execute) responses for ``alert``.

        Returns the actions taken/planned. A no-op returning [] when the master
        switch is off — nothing is even planned, so the system is fully inert.
        """
        if not self.config.response.enabled:
            return []

        dry_run = self.config.response.dry_run
        actions: List[ResponderAction] = []

        for responder in list(self._responders):
            try:
                if not responder.can_handle(alert):
                    continue
                action = responder.plan(alert)
                if action is None:
                    continue
                action.dry_run = dry_run
                if dry_run:
                    logger.warning(
                        "[DRY-RUN] %s would act on %s: %s",
                        responder.name, action.target, action.description,
                    )
                else:
                    responder.execute(action)
                actions.append(action)
            except Exception as exc:
                logger.error("Responder %s failed on alert %s: %s", responder.name, alert.alert_id, exc)

        if actions:
            with self._lock:
                self._recent.extend(actions)
        return actions

    def recent_actions(self, limit: int = 50) -> List[ResponderAction]:
        with self._lock:
            items = list(self._recent)
        return items[-limit:]
