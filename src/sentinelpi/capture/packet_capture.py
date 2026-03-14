"""
capture/packet_capture.py - Optional scapy-based packet capture.

This module provides passive packet sniffing via scapy. It requires
CAP_NET_RAW (typically root or a dedicated capability on the sentinelpi user).

Design:
- Runs in a dedicated daemon thread.
- Uses a BPF filter to limit captured traffic to what the detectors need.
- Publishes parsed events to a thread-safe queue for consumers.
- Never stores raw packet data to disk to protect privacy and limit storage.
- Gracefully degrades if scapy is unavailable or permissions are denied.

Privacy note: This tool is designed for home/lab network self-monitoring.
Do not deploy on networks where you do not have authorization to monitor.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, List, Optional

logger = logging.getLogger(__name__)

# Try to import scapy — it's an optional dependency for packet capture.
# The tool still works without it (using proc_reader instead).
try:
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS, DNSQR
    from scapy.sendrecv import AsyncSniffer
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("scapy not available — packet-level capture disabled. Using proc polling only.")


@dataclass
class CapturedARP:
    """ARP packet observed on the wire."""
    timestamp: datetime
    op: int           # 1=request, 2=reply
    src_mac: str
    src_ip: str
    dst_mac: str
    dst_ip: str


@dataclass
class CapturedDNS:
    """DNS query/response observed on the wire."""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    query_name: str
    query_type: str
    is_response: bool
    response_ip: str = ""
    is_nxdomain: bool = False


@dataclass
class CapturedConnection:
    """TCP SYN or first UDP packet — represents a new connection attempt."""
    timestamp: datetime
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str     # "tcp" | "udp" | "icmp"
    flags: str = ""   # TCP flags e.g. "S", "SA", "R"
    size: int = 0


# Union type for queued events
CaptureEvent = CapturedARP | CapturedDNS | CapturedConnection

# BPF filter: capture ARP, DNS (UDP 53), and TCP SYNs only.
# This keeps CPU load minimal while feeding the detectors what they need.
DEFAULT_BPF_FILTER = (
    "arp or "
    "(udp port 53) or "
    "(tcp[tcpflags] & tcp-syn != 0)"
)


class PacketCapture:
    """
    Passive packet sniffer that publishes parsed events to a queue.

    Usage:
        cap = PacketCapture(interfaces=["eth0"], event_queue=q)
        cap.start()
        ...
        cap.stop()
    """

    def __init__(
        self,
        interfaces: List[str],
        event_queue: "queue.Queue[CaptureEvent]",
        bpf_filter: str = DEFAULT_BPF_FILTER,
        max_queue_size: int = 10_000,
    ) -> None:
        self.interfaces = interfaces
        self.event_queue = event_queue
        self.bpf_filter = bpf_filter
        self._sniffer: Optional["AsyncSniffer"] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._dropped_count = 0

    def start(self) -> bool:
        """
        Start packet capture.

        Returns True if capture started successfully, False if unavailable.
        """
        if not SCAPY_AVAILABLE:
            logger.warning("Packet capture skipped: scapy not installed.")
            return False

        if self._running:
            logger.warning("PacketCapture already running.")
            return True

        self._running = True
        self._thread = threading.Thread(
            target=self._run,
            name="PacketCapture",
            daemon=True,
        )
        self._thread.start()
        logger.info("Packet capture started on interfaces: %s", self.interfaces)
        return True

    def stop(self) -> None:
        """Gracefully stop packet capture."""
        self._running = False
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)
        logger.info("Packet capture stopped. Dropped %d events (queue full).", self._dropped_count)

    def _run(self) -> None:
        """Main capture loop — runs in a dedicated thread."""
        while self._running:
            try:
                self._sniffer = AsyncSniffer(
                    iface=self.interfaces if len(self.interfaces) > 1 else self.interfaces[0],
                    filter=self.bpf_filter,
                    prn=self._handle_packet,
                    store=False,       # Never store packets in memory
                    quiet=True,
                )
                self._sniffer.start()
                # Wait until stopped externally
                while self._running:
                    time.sleep(1.0)
                    # Check sniffer is still alive
                    if not self._sniffer.running:
                        break
            except PermissionError:
                logger.error(
                    "Packet capture requires root or CAP_NET_RAW. "
                    "Run: sudo setcap cap_net_raw+eip $(which python3)"
                )
                self._running = False
                return
            except OSError as exc:
                logger.error("Packet capture error: %s — retrying in 10s", exc)
                time.sleep(10.0)
            except Exception as exc:
                logger.error("Unexpected capture error: %s — retrying in 30s", exc)
                time.sleep(30.0)
            finally:
                if self._sniffer and self._sniffer.running:
                    try:
                        self._sniffer.stop()
                    except Exception:
                        pass

    def _handle_packet(self, pkt: "scapy.packet.Packet") -> None:
        """
        Callback invoked for each captured packet.

        Parses the packet into a typed event and enqueues it.
        Never raises — exceptions here would kill the sniff thread.
        """
        try:
            now = datetime.utcnow()
            event: Optional[CaptureEvent] = None

            if pkt.haslayer(ARP):
                event = self._parse_arp(pkt, now)
            elif pkt.haslayer(DNS):
                event = self._parse_dns(pkt, now)
            elif pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
                event = self._parse_connection(pkt, now)

            if event is not None:
                self._enqueue(event)

        except Exception as exc:
            logger.debug("Error parsing packet: %s", exc)

    def _parse_arp(self, pkt: "scapy.packet.Packet", now: datetime) -> Optional[CapturedARP]:
        arp = pkt[ARP]
        return CapturedARP(
            timestamp=now,
            op=arp.op,
            src_mac=arp.hwsrc.lower(),
            src_ip=arp.psrc,
            dst_mac=arp.hwdst.lower(),
            dst_ip=arp.pdst,
        )

    def _parse_dns(self, pkt: "scapy.packet.Packet", now: datetime) -> Optional[CapturedDNS]:
        dns = pkt[DNS]
        ip = pkt[IP]

        # We care mainly about queries (qr==0) and their responses (qr==1)
        query_name = ""
        query_type = ""
        if dns.qdcount > 0 and dns.qd:
            try:
                query_name = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".")
                query_type = {1: "A", 28: "AAAA", 15: "MX", 16: "TXT",
                              2: "NS", 5: "CNAME", 12: "PTR"}.get(dns.qd.qtype, str(dns.qd.qtype))
            except Exception:
                query_name = str(dns.qd.qname)

        if not query_name:
            return None

        response_ip = ""
        is_nxdomain = bool(dns.rcode == 3)  # NXDOMAIN

        if dns.qr == 1 and dns.ancount > 0 and dns.an:
            try:
                if hasattr(dns.an, "rdata"):
                    response_ip = str(dns.an.rdata)
            except Exception:
                pass

        return CapturedDNS(
            timestamp=now,
            src_ip=ip.src,
            dst_ip=ip.dst,
            query_name=query_name,
            query_type=query_type,
            is_response=(dns.qr == 1),
            response_ip=response_ip,
            is_nxdomain=is_nxdomain,
        )

    def _parse_connection(self, pkt: "scapy.packet.Packet", now: datetime) -> Optional[CapturedConnection]:
        ip = pkt[IP]
        proto = "tcp"
        flags = ""
        sport = dport = 0
        size = len(pkt)

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            sport = tcp.sport
            dport = tcp.dport
            # Represent flags as a compact string
            flag_bits = {"F": tcp.flags & 0x01, "S": tcp.flags & 0x02,
                         "R": tcp.flags & 0x04, "P": tcp.flags & 0x08,
                         "A": tcp.flags & 0x10}
            flags = "".join(k for k, v in flag_bits.items() if v)
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            sport = udp.sport
            dport = udp.dport
            proto = "udp"

        return CapturedConnection(
            timestamp=now,
            src_ip=ip.src,
            src_port=sport,
            dst_ip=ip.dst,
            dst_port=dport,
            protocol=proto,
            flags=flags,
            size=size,
        )

    def _enqueue(self, event: CaptureEvent) -> None:
        """Non-blocking enqueue; drop and count if queue is full."""
        try:
            self.event_queue.put_nowait(event)
        except queue.Full:
            self._dropped_count += 1
            if self._dropped_count % 1000 == 0:
                logger.warning("Capture queue full — dropped %d events total.", self._dropped_count)
