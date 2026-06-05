"""
capture/flow_ingest.py - Router/firewall flow ingestion (Phase 3).

Passive packet capture only sees traffic that crosses the Pi's own segment
(its host stack plus whatever broadcast/local traffic it can sniff). To protect
*the network*, SentinelPi can also ingest flow data from the gateway/router.
Two sources, both optional and off by default:

- ConntrackFlowSource: polls the Linux connection-tracking table (the Pi acting
  as a gateway, or any host whose conntrack is worth watching) and emits each
  NEW flow once.
- NetFlowCollector: a UDP listener that accepts NetFlow v5 / v9 / IPFIX exports
  from a router or managed switch and turns each flow record into an event.

Both convert flows into the same ``CapturedConnection`` events the
packet-capture pipeline already produces, so every connection-based detector
(connection, beacon, lateral-movement, geo, ASN, threat-intel, active-hours)
works on them unchanged.

Privacy note: only flow metadata (5-tuple + byte counts) is handled; no packet
payloads are stored. Operate only on networks you are authorized to monitor.
"""

from __future__ import annotations

import logging
import os
import queue
import re
import socket
import struct
import subprocess
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from ..utils import clock
from .packet_capture import CapturedConnection

logger = logging.getLogger(__name__)

# IP-protocol number -> name, matching CapturedConnection.protocol values.
_PROTO_NAMES: Dict[int, str] = {1: "icmp", 6: "tcp", 17: "udp"}


def _proto_name(num: int) -> str:
    """Map an IP protocol number to a detector-friendly name (fallback: str)."""
    return _PROTO_NAMES.get(num, str(num))


@dataclass(frozen=True)
class FlowRecord:
    """A normalized flow observed by a flow source (pre-CapturedConnection)."""
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    size: int = 0

    @property
    def key(self) -> Tuple[str, int, str, int, str]:
        """Stable identity for dedup (the connection 5-tuple)."""
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol)


def _to_event(flow: FlowRecord, now: datetime) -> CapturedConnection:
    """Convert a normalized flow into the pipeline's CapturedConnection event."""
    return CapturedConnection(
        timestamp=now,
        src_ip=flow.src_ip,
        src_port=flow.src_port,
        dst_ip=flow.dst_ip,
        dst_port=flow.dst_port,
        protocol=flow.protocol,
        flags="",      # flow records don't carry per-packet TCP flags
        size=flow.size,
    )


def _enqueue(event_queue: "queue.Queue", flow: FlowRecord) -> bool:
    """Non-blocking enqueue of a flow as a CapturedConnection. True if accepted."""
    try:
        event_queue.put_nowait(_to_event(flow, clock.now()))
        return True
    except queue.Full:
        return False


# ---------------------------------------------------------------------------
# conntrack
# ---------------------------------------------------------------------------

# conntrack -L and /proc/net/nf_conntrack both encode the original-direction
# tuple as the first src=/dst=/sport=/dport= occurrences on the line, prefixed
# by a protocol name token. /proc adds a leading l3proto field (e.g. "ipv4 2")
# but the regexes below pick the first L4 proto + first tuple either way.
_PROTO_RE = re.compile(r"\b(tcp|udp|icmp)\b")
_SRC_RE = re.compile(r"\bsrc=(\S+)")
_DST_RE = re.compile(r"\bdst=(\S+)")
_SPORT_RE = re.compile(r"\bsport=(\d+)")
_DPORT_RE = re.compile(r"\bdport=(\d+)")


def parse_conntrack_line(line: str) -> Optional[FlowRecord]:
    """
    Parse a single conntrack line (``conntrack -L`` or ``/proc/net/nf_conntrack``)
    into a FlowRecord using the original-direction tuple. Returns None for lines
    we can't interpret (unknown protocol, no addresses).
    """
    proto_m = _PROTO_RE.search(line)
    src_m = _SRC_RE.search(line)
    dst_m = _DST_RE.search(line)
    if not (proto_m and src_m and dst_m):
        return None
    sport_m = _SPORT_RE.search(line)
    dport_m = _DPORT_RE.search(line)
    return FlowRecord(
        src_ip=src_m.group(1),
        src_port=int(sport_m.group(1)) if sport_m else 0,
        dst_ip=dst_m.group(1),
        dst_port=int(dport_m.group(1)) if dport_m else 0,
        protocol=proto_m.group(1),
    )


class ConntrackFlowSource:
    """
    Polls the kernel connection-tracking table and emits each NEW flow once.

    Each poll diffs the current table against the previous snapshot: flows that
    appear are emitted, flows that vanish are forgotten (so a later reconnect
    with the same 5-tuple emits again). The first poll only primes the snapshot,
    so pre-existing established connections don't cause a startup alert storm.
    """

    PROC_PATH = "/proc/net/nf_conntrack"

    def __init__(
        self,
        event_queue: "queue.Queue",
        interval_seconds: int = 10,
        command: str = "conntrack",
        stop_event: Optional[threading.Event] = None,
    ) -> None:
        self._queue = event_queue
        self._interval = max(1, int(interval_seconds))
        self._command = command
        self._global_stop = stop_event or threading.Event()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._seen: set = set()
        self._primed = False
        self.emitted = 0
        self.dropped = 0

    def start(self) -> bool:
        """
        Probe that the conntrack table is readable, then start the poll thread.
        Returns False (without starting a thread) if neither the conntrack
        command nor /proc/net/nf_conntrack is available.
        """
        if self._read_conntrack() is None:
            return False
        self._thread = threading.Thread(
            target=self._run, name="ConntrackFlowSource", daemon=True
        )
        self._thread.start()
        logger.info("conntrack flow source started (interval=%ds).", self._interval)
        return True

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def _run(self) -> None:
        while not self._stop.is_set() and not self._global_stop.is_set():
            try:
                self.poll_once()
            except Exception as exc:  # never let a parse hiccup kill the thread
                logger.debug("conntrack poll error: %s", exc)
            # Interruptible sleep — wakes immediately on stop.
            if self._stop.wait(self._interval) or self._global_stop.is_set():
                break
        logger.info("conntrack flow source stopped.")

    def poll_once(self) -> int:
        """
        Read the table once, emit newly-appeared flows, return the count emitted.
        Exposed (non-underscore) so tests can drive a single iteration.
        """
        lines = self._read_conntrack()
        if lines is None:
            return 0
        current: Dict[tuple, FlowRecord] = {}
        for line in lines:
            flow = parse_conntrack_line(line)
            if flow is not None:
                current[flow.key] = flow

        if not self._primed:
            # First poll: adopt the snapshot without emitting existing flows.
            self._seen = set(current.keys())
            self._primed = True
            return 0

        emitted = 0
        for key, flow in current.items():
            if key not in self._seen:
                if _enqueue(self._queue, flow):
                    emitted += 1
                    self.emitted += 1
                else:
                    self.dropped += 1
        self._seen = set(current.keys())
        return emitted

    def _read_conntrack(self) -> Optional[List[str]]:
        """
        Return current conntrack lines, preferring the ``conntrack`` command and
        falling back to /proc/net/nf_conntrack. Returns None if neither works.
        """
        try:
            result = subprocess.run(
                [self._command, "-L"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode == 0 and result.stdout:
                return result.stdout.splitlines()
            logger.debug(
                "conntrack command exited %d; falling back to %s.",
                result.returncode, self.PROC_PATH,
            )
        except (FileNotFoundError, OSError, subprocess.SubprocessError) as exc:
            logger.debug("conntrack command unavailable (%s); trying %s.", exc, self.PROC_PATH)

        try:
            with open(self.PROC_PATH, "r") as fh:
                return fh.read().splitlines()
        except OSError as exc:
            logger.debug("Could not read %s: %s", self.PROC_PATH, exc)
            return None


# ---------------------------------------------------------------------------
# NetFlow v5 / v9 / IPFIX
# ---------------------------------------------------------------------------

# Field types we decode from v9/IPFIX templates (IANA IPFIX information elements,
# shared with NetFlow v9). Everything else in a record is skipped by length.
_IE_OCTETS = 1            # byte count
_IE_PROTOCOL = 4
_IE_SRC_PORT = 7
_IE_SRC_IPV4 = 8
_IE_DST_PORT = 11
_IE_DST_IPV4 = 12
_IE_SRC_IPV6 = 27
_IE_DST_IPV6 = 28

_NETFLOW_V5_HEADER = struct.Struct("!HHIIIIBBH")   # 24 bytes
_NETFLOW_V5_RECORD = struct.Struct("!IIIHHIIIIHHBBBBHHBBH")  # 48 bytes


def parse_netflow_v5(data: bytes) -> List[FlowRecord]:
    """Parse a NetFlow v5 export packet (fixed 48-byte records, no templates)."""
    if len(data) < _NETFLOW_V5_HEADER.size:
        return []
    version, count = struct.unpack("!HH", data[:4])
    if version != 5:
        return []
    flows: List[FlowRecord] = []
    offset = _NETFLOW_V5_HEADER.size
    for _ in range(count):
        end = offset + _NETFLOW_V5_RECORD.size
        if end > len(data):
            break
        rec = _NETFLOW_V5_RECORD.unpack(data[offset:end])
        srcaddr, dstaddr = rec[0], rec[1]
        d_octets = rec[6]
        srcport, dstport = rec[9], rec[10]
        prot = rec[13]
        flows.append(FlowRecord(
            src_ip=socket.inet_ntoa(struct.pack("!I", srcaddr)),
            src_port=srcport,
            dst_ip=socket.inet_ntoa(struct.pack("!I", dstaddr)),
            dst_port=dstport,
            protocol=_proto_name(prot),
            size=d_octets,
        ))
        offset = end
    return flows


def _decode_v9_record(fields: List[Tuple[int, int]], raw: bytes) -> Optional[FlowRecord]:
    """Decode one data record given its template's (type, length) field list."""
    off = 0
    src_ip = dst_ip = ""
    src_port = dst_port = proto_num = size = 0
    for ftype, flen in fields:
        chunk = raw[off:off + flen]
        off += flen
        if len(chunk) < flen:
            return None
        if ftype == _IE_SRC_IPV4 and flen == 4:
            src_ip = socket.inet_ntoa(chunk)
        elif ftype == _IE_DST_IPV4 and flen == 4:
            dst_ip = socket.inet_ntoa(chunk)
        elif ftype == _IE_SRC_IPV6 and flen == 16:
            src_ip = socket.inet_ntop(socket.AF_INET6, chunk)
        elif ftype == _IE_DST_IPV6 and flen == 16:
            dst_ip = socket.inet_ntop(socket.AF_INET6, chunk)
        elif ftype == _IE_SRC_PORT:
            src_port = int.from_bytes(chunk, "big")
        elif ftype == _IE_DST_PORT:
            dst_port = int.from_bytes(chunk, "big")
        elif ftype == _IE_PROTOCOL:
            proto_num = int.from_bytes(chunk, "big")
        elif ftype == _IE_OCTETS:
            size = int.from_bytes(chunk, "big")
    if not src_ip or not dst_ip:
        return None
    return FlowRecord(
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=_proto_name(proto_num),
        size=size,
    )


def _parse_template_fields(body: bytes, ipfix: bool) -> Tuple[Dict[int, List[Tuple[int, int]]], int]:
    """
    Parse one template set body into {template_id: [(type, length), ...]}.
    Skips enterprise-specific fields (IPFIX, high bit of type set) by advancing
    past their 4-byte enterprise number. Returns (templates, bytes_consumed).
    """
    templates: Dict[int, List[Tuple[int, int]]] = {}
    off = 0
    n = len(body)
    while off + 4 <= n:
        template_id, field_count = struct.unpack("!HH", body[off:off + 4])
        off += 4
        fields: List[Tuple[int, int]] = []
        ok = True
        for _ in range(field_count):
            if off + 4 > n:
                ok = False
                break
            ftype, flen = struct.unpack("!HH", body[off:off + 4])
            off += 4
            if ipfix and (ftype & 0x8000):
                # Enterprise field: skip its 4-byte enterprise number.
                ftype &= 0x7FFF
                off += 4
            fields.append((ftype, flen))
        if ok and field_count > 0:
            templates[template_id] = fields
    return templates, off


def _parse_v9_like(
    data: bytes,
    templates: Dict[int, List[Tuple[int, int]]],
    header_len: int,
    template_set_id: int,
    options_set_id: int,
) -> List[FlowRecord]:
    """
    Shared NetFlow-v9 / IPFIX flowset walker. ``templates`` is mutated in place
    so template definitions persist across packets (they're sent periodically;
    data records reference them by id). Data records for an unknown template are
    skipped until its template arrives.
    """
    flows: List[FlowRecord] = []
    off = header_len
    n = len(data)
    while off + 4 <= n:
        set_id, set_len = struct.unpack("!HH", data[off:off + 4])
        if set_len < 4 or off + set_len > n:
            break
        body = data[off + 4:off + set_len]
        if set_id == template_set_id:
            new_templates, _ = _parse_template_fields(body, ipfix=(template_set_id == 2))
            templates.update(new_templates)
        elif set_id == options_set_id:
            pass  # options templates carry metadata, not flows — ignore
        elif set_id >= 256:
            fields = templates.get(set_id)
            if fields:
                record_len = sum(flen for _, flen in fields)
                if record_len > 0:
                    count = len(body) // record_len
                    for i in range(count):
                        rec = _decode_v9_record(fields, body[i * record_len:(i + 1) * record_len])
                        if rec is not None:
                            flows.append(rec)
        off += set_len
    return flows


def parse_netflow_v9(data: bytes, templates: Dict[int, List[Tuple[int, int]]]) -> List[FlowRecord]:
    """Parse a NetFlow v9 export packet. Template set id 0, options id 1."""
    if len(data) < 20:
        return []
    return _parse_v9_like(data, templates, header_len=20, template_set_id=0, options_set_id=1)


def parse_ipfix(data: bytes, templates: Dict[int, List[Tuple[int, int]]]) -> List[FlowRecord]:
    """Parse an IPFIX (NetFlow v10) export packet. Template set id 2, options id 3."""
    if len(data) < 16:
        return []
    return _parse_v9_like(data, templates, header_len=16, template_set_id=2, options_set_id=3)


def parse_netflow(data: bytes, templates: Dict[int, List[Tuple[int, int]]]) -> List[FlowRecord]:
    """Dispatch a flow-export datagram to the right parser by version word."""
    if len(data) < 2:
        return []
    version = struct.unpack("!H", data[:2])[0]
    if version == 5:
        return parse_netflow_v5(data)
    if version == 9:
        return parse_netflow_v9(data, templates)
    if version == 10:
        return parse_ipfix(data, templates)
    logger.debug("Ignoring unsupported NetFlow version %d.", version)
    return []


class NetFlowCollector:
    """
    UDP listener that turns NetFlow v5/v9/IPFIX exports into flow events.

    v9/IPFIX templates are cached per (exporter, source/observation id) so data
    records that reference a template sent in an earlier packet still decode.
    """

    def __init__(
        self,
        event_queue: "queue.Queue",
        bind_host: str = "0.0.0.0",
        bind_port: int = 2055,
        stop_event: Optional[threading.Event] = None,
    ) -> None:
        self._queue = event_queue
        self._host = bind_host
        self._port = bind_port
        self._global_stop = stop_event or threading.Event()
        self._stop = threading.Event()
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        # template cache keyed by (exporter_ip, source_id) -> {template_id: fields}
        self._templates: Dict[Tuple[str, int], Dict[int, List[Tuple[int, int]]]] = {}
        self.emitted = 0
        self.dropped = 0

    def start(self) -> bool:
        """Bind the UDP socket and start the receive thread. False on bind error."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self._host, self._port))
            sock.settimeout(1.0)
        except OSError as exc:
            logger.error("NetFlow collector failed to bind %s:%d: %s", self._host, self._port, exc)
            return False
        self._sock = sock
        self._thread = threading.Thread(target=self._run, name="NetFlowCollector", daemon=True)
        self._thread.start()
        logger.info("NetFlow/IPFIX collector listening on %s:%d (udp).", self._host, self._port)
        return True

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def _run(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set() and not self._global_stop.is_set():
            try:
                data, addr = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break  # socket closed during shutdown
            self._handle_datagram(data, addr[0])
        logger.info("NetFlow/IPFIX collector stopped.")

    def _handle_datagram(self, data: bytes, exporter: str) -> int:
        """Parse one datagram and enqueue its flows. Returns count emitted."""
        # Templates persist per exporter; source/observation id lives in the
        # header but a single key per exporter is sufficient for home use.
        templates = self._templates.setdefault((exporter, 0), {})
        try:
            flows = parse_netflow(data, templates)
        except Exception as exc:
            logger.debug("Malformed flow packet from %s: %s", exporter, exc)
            return 0
        emitted = 0
        for flow in flows:
            if _enqueue(self._queue, flow):
                emitted += 1
                self.emitted += 1
            else:
                self.dropped += 1
        return emitted


# ---------------------------------------------------------------------------
# pfSense / OPNsense filterlog
# ---------------------------------------------------------------------------

# pfSense/OPNsense write firewall events via filterlog as a CSV after the syslog
# tag. The leading fields are protocol-independent; the IP-version field then
# selects an IPv4 or IPv6 field layout. We extract the original 5-tuple of each
# logged packet (pass or block — a blocked attempt is itself worth seeing).
# Field reference: https://docs.netgate.com/pfsense/en/latest/monitoring/logs/raw-filter-format.html
_FL_IPVER = 8        # ip version ("4" | "6")
# IPv4 layout (0-based): ...,15 proto_id,16 proto,17 length,18 src,19 dst,20 sport,21 dport
_FL4_PROTO = 16
_FL4_SRC = 18
_FL4_DST = 19
_FL4_SPORT = 20
_FL4_DPORT = 21
# IPv6 layout (0-based): ...,12 proto,13 proto_id,14 length,15 src,16 dst,17 sport,18 dport
_FL6_PROTO = 12
_FL6_SRC = 15
_FL6_DST = 16
_FL6_SPORT = 17
_FL6_DPORT = 18


def parse_filterlog_line(line: str) -> Optional[FlowRecord]:
    """
    Parse one pfSense/OPNsense filterlog line into a FlowRecord. Accepts either a
    full syslog line (with the ``filterlog[pid]:`` prefix) or a bare CSV body.
    Returns None for non-filterlog lines or ones we can't interpret.
    """
    idx = line.find("filterlog")
    if idx != -1:
        rest = line[idx:]
        csv = rest.split(":", 1)[1].strip() if ":" in rest else ""
    else:
        csv = line.strip()
    if not csv:
        return None

    f = csv.split(",")
    if len(f) <= _FL_IPVER:
        return None
    ipver = f[_FL_IPVER]

    def _port(fields, i, proto):
        if proto in ("tcp", "udp") and len(fields) > i and fields[i].isdigit():
            return int(fields[i])
        return 0

    if ipver == "4":
        if len(f) <= _FL4_DST:
            return None
        proto = f[_FL4_PROTO].lower()
        src_ip, dst_ip = f[_FL4_SRC], f[_FL4_DST]
        src_port = _port(f, _FL4_SPORT, proto)
        dst_port = _port(f, _FL4_DPORT, proto)
    elif ipver == "6":
        if len(f) <= _FL6_DST:
            return None
        proto = f[_FL6_PROTO].lower()
        src_ip, dst_ip = f[_FL6_SRC], f[_FL6_DST]
        src_port = _port(f, _FL6_SPORT, proto)
        dst_port = _port(f, _FL6_DPORT, proto)
    else:
        return None

    if not src_ip or not dst_ip:
        return None
    return FlowRecord(src_ip, src_port, dst_ip, dst_port, proto)


class FilterlogSource:
    """
    Tails a pfSense/OPNsense filterlog file and emits each logged flow.

    The firewall logs live on the firewall, so point ``path`` at a file the Pi
    can read — typically syslog forwarded from the firewall to the Pi and
    written out by rsyslog. Starts at end-of-file (no history replay) and follows
    rotation/truncation. Each log line is a distinct event, so no dedup is
    applied (unlike conntrack's snapshot diffing).
    """

    def __init__(
        self,
        event_queue: "queue.Queue",
        path: str = "/var/log/filter.log",
        interval_seconds: int = 5,
        stop_event: Optional[threading.Event] = None,
    ) -> None:
        self._queue = event_queue
        self._path = path
        self._interval = max(1, int(interval_seconds))
        self._global_stop = stop_event or threading.Event()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._offset = 0
        self._inode: Optional[int] = None
        self._buf = ""
        self.emitted = 0
        self.dropped = 0

    def start(self) -> bool:
        """Seek to end of the log and start tailing. False if the file is absent."""
        try:
            st = os.stat(self._path)
        except OSError:
            return False
        self._offset = st.st_size
        self._inode = st.st_ino
        self._thread = threading.Thread(target=self._run, name="FilterlogSource", daemon=True)
        self._thread.start()
        logger.info("filterlog source started (%s, interval=%ds).", self._path, self._interval)
        return True

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def _run(self) -> None:
        while not self._stop.is_set() and not self._global_stop.is_set():
            try:
                self.poll_once()
            except Exception as exc:
                logger.debug("filterlog poll error: %s", exc)
            if self._stop.wait(self._interval) or self._global_stop.is_set():
                break
        logger.info("filterlog source stopped.")

    def poll_once(self) -> int:
        """Read new lines, emit parsed flows, return the count emitted."""
        emitted = 0
        for line in self._read_new_lines():
            flow = parse_filterlog_line(line)
            if flow is not None:
                if _enqueue(self._queue, flow):
                    emitted += 1
                    self.emitted += 1
                else:
                    self.dropped += 1
        return emitted

    def _read_new_lines(self) -> List[str]:
        try:
            st = os.stat(self._path)
        except OSError:
            return []
        # Rotation (new inode) or truncation (shrank) -> start from the top.
        if self._inode is not None and st.st_ino != self._inode:
            self._offset = 0
            self._buf = ""
        elif st.st_size < self._offset:
            self._offset = 0
            self._buf = ""
        self._inode = st.st_ino
        if st.st_size == self._offset:
            return []
        try:
            with open(self._path, "r", errors="replace") as fh:
                fh.seek(self._offset)
                data = fh.read()
                self._offset = fh.tell()
        except OSError as exc:
            logger.debug("Could not read %s: %s", self._path, exc)
            return []
        self._buf += data
        if "\n" not in self._buf:
            return []          # only a partial line so far — wait for more
        *complete, self._buf = self._buf.split("\n")
        return complete
