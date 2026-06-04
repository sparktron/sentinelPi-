"""
capture/honeypot.py - Canary / honeypot TCP ports.

Opens a handful of fake "service" ports that nothing legitimate should ever
touch. Any inbound connection to one is high-fidelity evidence of someone
scanning or probing the network from the inside — there are no false positives
the way there are with heuristic detectors, so these alerts are HIGH.

Each port gets a listener socket and an accept loop in a daemon thread. On a
connection we record the source, immediately close it (we serve nothing), and
hand a built Alert to the ``on_alert`` callback (normally AlertManager.process_one).

Binding ports < 1024 needs root; a port that fails to bind is logged and skipped
so one unavailable port never stops the others.
"""

from __future__ import annotations

import logging
import socket
import threading
from typing import Callable, List, Optional

from ..models import Alert, AlertCategory, Severity

logger = logging.getLogger(__name__)

AlertCallback = Callable[[Alert], None]


class HoneypotService:
    """Listens on canary ports and raises a HIGH alert on any connection."""

    def __init__(self, config, on_alert: AlertCallback) -> None:
        self.config = config
        self._on_alert = on_alert
        self._sockets: List[socket.socket] = []
        self._threads: List[threading.Thread] = []
        self._running = False

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> bool:
        """Bind and start listening on each configured port. Returns True if any port came up."""
        mon = self.config.monitoring
        host = mon.honeypot_bind_host
        self._running = True
        bound = 0
        for port in mon.honeypot_ports:
            sock = self._bind(host, port)
            if sock is None:
                continue
            self._sockets.append(sock)
            t = threading.Thread(target=self._accept_loop, args=(sock, port),
                                 daemon=True, name=f"Honeypot:{port}")
            t.start()
            self._threads.append(t)
            bound += 1
        if bound:
            logger.warning("Honeypot listening on %d canary port(s): %s", bound, mon.honeypot_ports)
        else:
            logger.warning("Honeypot enabled but no ports could be bound.")
        return bound > 0

    def _bind(self, host: str, port: int) -> Optional[socket.socket]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.listen(8)
            sock.settimeout(1.0)  # so the accept loop can notice shutdown
            return sock
        except OSError as exc:
            logger.warning("Honeypot could not bind %s:%d (%s) — skipping.", host, port, exc)
            return None

    def _accept_loop(self, sock: socket.socket, port: int) -> None:
        while self._running:
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                src_ip = addr[0]
                conn.close()  # we serve nothing — slam it shut
                self._handle_hit(src_ip, port)
            except Exception as exc:
                logger.debug("Honeypot hit handling error on port %d: %s", port, exc)

    def stop(self) -> None:
        self._running = False
        for sock in self._sockets:
            try:
                sock.close()
            except OSError:
                pass
        self._sockets.clear()

    # ------------------------------------------------------------------ alerting
    def _handle_hit(self, src_ip: str, port: int) -> None:
        """Build and emit the alert for a connection to a canary port (testable)."""
        logger.warning("Honeypot hit: %s connected to canary port %d.", src_ip, port)
        alert = Alert(
            severity=Severity.HIGH,
            category=AlertCategory.HONEYPOT,
            affected_host=src_ip,
            related_host="",
            title=f"Honeypot triggered: {src_ip} probed canary port {port}",
            description=(
                f"{src_ip} connected to canary port {port}, a fake service that no legitimate "
                "client should ever touch. This is high-fidelity evidence of internal scanning "
                "or lateral movement from a likely-compromised host."
            ),
            recommended_action=(
                f"Investigate {src_ip} immediately — identify the device and the process making "
                "these connections. Consider isolating it from the network."
            ),
            confidence=0.95,
            confidence_rationale="Direct connection to a canary port with no legitimate purpose.",
            dedup_key=f"honeypot:{src_ip}:{port}",
            extra={"canary_port": port, "source": src_ip},
        )
        try:
            self._on_alert(alert)
        except Exception as exc:
            logger.error("Honeypot alert callback failed: %s", exc)
