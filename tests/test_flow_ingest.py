"""
tests/test_flow_ingest.py - Router/firewall flow ingestion (Phase 3).

Covers the conntrack line parsers (both `conntrack -L` and
/proc/net/nf_conntrack formats), NEW-flow dedup/priming, the NetFlow
v5/v9/IPFIX parsers (with template persistence), conversion into the shared
CapturedConnection pipeline, and graceful degradation when no source is usable.
"""

from __future__ import annotations

import queue
import socket
import struct

import pytest

from sentinelpi.capture.flow_ingest import (
    ConntrackFlowSource,
    NetFlowCollector,
    FilterlogSource,
    FlowRecord,
    parse_conntrack_line,
    parse_filterlog_line,
    parse_netflow,
    parse_netflow_v5,
    parse_netflow_v9,
    parse_ipfix,
)
from sentinelpi.capture.packet_capture import CapturedConnection


# ----------------------------------------------------------------- conntrack
CONNTRACK_L_TCP = (
    "tcp      6 431999 ESTABLISHED src=192.168.1.10 dst=93.184.216.34 "
    "sport=51234 dport=443 src=93.184.216.34 dst=192.168.1.10 sport=443 "
    "dport=51234 [ASSURED] mark=0 use=1"
)
CONNTRACK_L_UDP = (
    "udp      17 29 src=192.168.1.10 dst=8.8.8.8 sport=51234 dport=53 "
    "[UNREPLIED] src=8.8.8.8 dst=192.168.1.10 sport=53 dport=51234 mark=0 use=1"
)
PROC_NF_TCP = (
    "ipv4     2 tcp      6 299 ESTABLISHED src=10.0.0.5 dst=140.82.112.3 "
    "sport=44444 dport=443 src=140.82.112.3 dst=10.0.0.5 sport=443 "
    "dport=44444 [ASSURED] mark=0 zone=0 use=2"
)


def test_parse_conntrack_l_tcp_uses_original_direction():
    flow = parse_conntrack_line(CONNTRACK_L_TCP)
    assert flow == FlowRecord("192.168.1.10", 51234, "93.184.216.34", 443, "tcp")


def test_parse_conntrack_l_udp():
    flow = parse_conntrack_line(CONNTRACK_L_UDP)
    assert flow.protocol == "udp"
    assert flow.dst_ip == "8.8.8.8"
    assert flow.dst_port == 53


def test_parse_proc_nf_conntrack_format():
    # /proc adds a leading l3proto field ("ipv4 2"); parser still picks the L4
    # proto and the first original-direction tuple.
    flow = parse_conntrack_line(PROC_NF_TCP)
    assert flow == FlowRecord("10.0.0.5", 44444, "140.82.112.3", 443, "tcp")


def test_parse_conntrack_garbage_returns_none():
    assert parse_conntrack_line("conntrack v1.4.6: 5 flow entries have been shown.") is None
    assert parse_conntrack_line("") is None


def test_conntrack_source_primes_then_emits_new(monkeypatch):
    q: "queue.Queue" = queue.Queue()
    src = ConntrackFlowSource(q, interval_seconds=1)

    lines = [CONNTRACK_L_TCP, CONNTRACK_L_UDP]
    monkeypatch.setattr(src, "_read_conntrack", lambda: list(lines))

    # First poll primes the snapshot without emitting pre-existing flows.
    assert src.poll_once() == 0
    assert q.empty()

    # No change -> nothing new.
    assert src.poll_once() == 0

    # A brand-new flow appears -> emitted exactly once.
    lines.append(
        "tcp      6 120 SYN_SENT src=192.168.1.20 dst=1.1.1.1 sport=40000 "
        "dport=8080 [UNREPLIED] src=1.1.1.1 dst=192.168.1.20 sport=8080 dport=40000"
    )
    assert src.poll_once() == 1
    assert src.poll_once() == 0  # already seen

    event = q.get_nowait()
    assert isinstance(event, CapturedConnection)
    assert event.dst_ip == "1.1.1.1"
    assert event.dst_port == 8080
    assert event.protocol == "tcp"


def test_conntrack_source_reemits_after_flow_disappears(monkeypatch):
    q: "queue.Queue" = queue.Queue()
    src = ConntrackFlowSource(q)
    state = {"lines": [CONNTRACK_L_TCP]}
    monkeypatch.setattr(src, "_read_conntrack", lambda: list(state["lines"]))

    src.poll_once()                       # prime
    state["lines"] = []                   # flow closed/expired
    assert src.poll_once() == 0
    state["lines"] = [CONNTRACK_L_TCP]    # same 5-tuple reconnects
    assert src.poll_once() == 1           # forgotten -> emits again


def test_conntrack_source_start_false_when_unavailable(monkeypatch):
    src = ConntrackFlowSource(queue.Queue())
    monkeypatch.setattr(src, "_read_conntrack", lambda: None)
    assert src.start() is False
    assert src._thread is None


# ------------------------------------------------------------------- NetFlow v5
def _build_v5(records):
    header = struct.pack("!HHIIIIBBH", 5, len(records), 0, 0, 0, 0, 0, 0, 0)
    body = b""
    for r in records:
        body += struct.pack(
            "!IIIHHIIIIHHBBBBHHBBH",
            struct.unpack("!I", socket.inet_aton(r["src"]))[0],
            struct.unpack("!I", socket.inet_aton(r["dst"]))[0],
            0, 0, 0,                     # nexthop, input, output
            r.get("pkts", 1), r.get("bytes", 0),
            0, 0,                        # first, last
            r["sport"], r["dport"],
            0, 0,                        # pad, tcp_flags
            r["proto"],
            0, 0, 0, 0, 0, 0,            # tos, src_as, dst_as, src_mask, dst_mask, pad2
        )
    return header + body


def test_parse_netflow_v5():
    pkt = _build_v5([
        {"src": "192.168.1.10", "dst": "93.184.216.34", "sport": 51234,
         "dport": 443, "proto": 6, "bytes": 1500},
        {"src": "192.168.1.11", "dst": "8.8.8.8", "sport": 5000,
         "dport": 53, "proto": 17, "bytes": 90},
    ])
    flows = parse_netflow_v5(pkt)
    assert len(flows) == 2
    assert flows[0] == FlowRecord("192.168.1.10", 51234, "93.184.216.34", 443, "tcp", 1500)
    assert flows[1].protocol == "udp"
    assert flows[1].size == 90


def test_parse_netflow_v5_truncated_record_stops_cleanly():
    pkt = _build_v5([{"src": "1.1.1.1", "dst": "2.2.2.2", "sport": 1,
                      "dport": 2, "proto": 6}])
    # Claim 5 records in the header but only ship one record's worth of bytes.
    bad = struct.pack("!HH", 5, 5) + pkt[4:]
    flows = parse_netflow_v5(bad)
    assert len(flows) == 1


# --------------------------------------------------------------- NetFlow v9/IPFIX
_V9_FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4)]


def _v9_template_flowset(template_id, set_id):
    body = struct.pack("!HH", template_id, len(_V9_FIELDS))
    for t, length in _V9_FIELDS:
        body += struct.pack("!HH", t, length)
    return struct.pack("!HH", set_id, 4 + len(body)) + body


def _v9_data_flowset(template_id, records):
    data = b""
    for r in records:
        data += socket.inet_aton(r["src"]) + socket.inet_aton(r["dst"])
        data += struct.pack("!HHB", r["sport"], r["dport"], r["proto"])
        data += struct.pack("!I", r.get("bytes", 0))
    return struct.pack("!HH", template_id, 4 + len(data)) + data


def _build_v9(records, template_id=256, with_template=True):
    header = struct.pack("!HHIIII", 9, 0, 0, 0, 0, 0)
    body = b""
    if with_template:
        body += _v9_template_flowset(template_id, set_id=0)
    body += _v9_data_flowset(template_id, records)
    return header + body


def _build_ipfix(records, template_id=256, with_template=True):
    header = struct.pack("!HHIII", 10, 0, 0, 0, 0)
    body = b""
    if with_template:
        # IPFIX template set id == 2.
        tbody = struct.pack("!HH", template_id, len(_V9_FIELDS))
        for t, length in _V9_FIELDS:
            tbody += struct.pack("!HH", t, length)
        body += struct.pack("!HH", 2, 4 + len(tbody)) + tbody
    body += _v9_data_flowset(template_id, records)
    return header + body


def test_parse_netflow_v9_template_plus_data():
    pkt = _build_v9([
        {"src": "10.0.0.5", "dst": "140.82.112.3", "sport": 44444,
         "dport": 443, "proto": 6, "bytes": 2048},
    ])
    flows = parse_netflow_v9(pkt, {})
    assert flows == [FlowRecord("10.0.0.5", 44444, "140.82.112.3", 443, "tcp", 2048)]


def test_parse_netflow_v9_data_before_template_is_skipped():
    templates: dict = {}
    # Data only, no template yet -> nothing decodable.
    data_only = _build_v9([{"src": "1.1.1.1", "dst": "2.2.2.2", "sport": 1,
                            "dport": 2, "proto": 6}], with_template=False)
    assert parse_netflow_v9(data_only, templates) == []
    # Template arrives in a later packet; cache persists, then data decodes.
    template_only = struct.pack("!HHIIII", 9, 0, 0, 0, 0, 0) + _v9_template_flowset(256, 0)
    assert parse_netflow_v9(template_only, templates) == []
    flows = parse_netflow_v9(data_only, templates)
    assert len(flows) == 1 and flows[0].src_ip == "1.1.1.1"


def test_parse_ipfix():
    pkt = _build_ipfix([
        {"src": "172.16.0.9", "dst": "1.1.1.1", "sport": 33000,
         "dport": 853, "proto": 6, "bytes": 700},
    ])
    flows = parse_ipfix(pkt, {})
    assert flows == [FlowRecord("172.16.0.9", 33000, "1.1.1.1", 853, "tcp", 700)]


def test_parse_netflow_dispatch_and_unknown_version():
    v5 = _build_v5([{"src": "1.1.1.1", "dst": "2.2.2.2", "sport": 1,
                     "dport": 2, "proto": 17}])
    assert parse_netflow(v5, {})[0].protocol == "udp"
    assert parse_netflow(struct.pack("!H", 7) + b"\x00" * 30, {}) == []
    assert parse_netflow(b"", {}) == []


# --------------------------------------------------------------- NetFlowCollector
def test_collector_handle_datagram_emits_events():
    q: "queue.Queue" = queue.Queue()
    collector = NetFlowCollector(q)
    pkt = _build_v5([{"src": "192.168.1.10", "dst": "9.9.9.9", "sport": 5,
                      "dport": 443, "proto": 6, "bytes": 64}])
    assert collector._handle_datagram(pkt, "192.168.1.1") == 1
    event = q.get_nowait()
    assert isinstance(event, CapturedConnection)
    assert event.dst_ip == "9.9.9.9"
    assert collector.emitted == 1


def test_collector_template_persists_across_datagrams():
    q: "queue.Queue" = queue.Queue()
    collector = NetFlowCollector(q)
    exporter = "10.0.0.1"
    template_only = struct.pack("!HHIIII", 9, 0, 0, 0, 0, 0) + _v9_template_flowset(256, 0)
    data_only = _build_v9([{"src": "10.0.0.5", "dst": "8.8.4.4", "sport": 1,
                            "dport": 53, "proto": 17}], with_template=False)

    assert collector._handle_datagram(template_only, exporter) == 0
    assert collector._handle_datagram(data_only, exporter) == 1
    assert q.get_nowait().dst_ip == "8.8.4.4"


def test_collector_malformed_datagram_is_ignored():
    collector = NetFlowCollector(queue.Queue())
    assert collector._handle_datagram(b"\xff\xff\x00\x01garbage", "1.2.3.4") == 0


# ------------------------------------------------------------------- filterlog
FL_V4_TCP = (
    "100,,,1000000103,igb1,match,pass,out,4,0x0,,64,12345,0,DF,6,tcp,60,"
    "192.168.1.10,140.82.112.3,51000,443,0,S,..."
)
FL_V6_UDP = (
    "5,,,1000000105,igb0,match,block,in,6,0x00,0x00000,64,udp,17,53,"
    "fe80::1,fe80::2,5353,5353"
)
FL_V4_ICMP = (
    "1,,,123,igb1,match,block,in,4,0x0,,64,0,0,none,1,icmp,84,10.0.0.1,10.0.0.2,8,0"
)
FL_SYSLOG = (
    "Jun  5 10:00:00 fw filterlog[12345]: " + FL_V4_TCP
)


def test_parse_filterlog_ipv4_tcp():
    flow = parse_filterlog_line(FL_V4_TCP)
    assert flow == FlowRecord("192.168.1.10", 51000, "140.82.112.3", 443, "tcp")


def test_parse_filterlog_ipv6_udp():
    flow = parse_filterlog_line(FL_V6_UDP)
    assert flow == FlowRecord("fe80::1", 5353, "fe80::2", 5353, "udp")


def test_parse_filterlog_icmp_has_no_ports():
    flow = parse_filterlog_line(FL_V4_ICMP)
    assert flow == FlowRecord("10.0.0.1", 0, "10.0.0.2", 0, "icmp")


def test_parse_filterlog_strips_syslog_prefix():
    flow = parse_filterlog_line(FL_SYSLOG)
    assert flow.src_ip == "192.168.1.10" and flow.dst_port == 443


def test_parse_filterlog_ignores_non_filterlog_lines():
    assert parse_filterlog_line("Jun 5 sshd[1]: accepted password for root") is None
    assert parse_filterlog_line("") is None
    assert parse_filterlog_line("100,,,t,igb1,match,pass,out") is None  # too short


def test_filterlog_source_tails_new_lines(tmp_path):
    log = tmp_path / "filter.log"
    log.write_text("Jun  5 09:59:59 fw filterlog[1]: " + FL_V6_UDP + "\n")  # pre-existing

    q: "queue.Queue" = queue.Queue()
    src = FilterlogSource(q, path=str(log))
    assert src.start() is True          # seeks to end; existing line is not replayed
    try:
        assert q.empty()
        with log.open("a") as fh:
            fh.write(FL_SYSLOG + "\n")
        assert src.poll_once() == 1
        event = q.get_nowait()
        assert isinstance(event, CapturedConnection)
        assert event.dst_ip == "140.82.112.3"
    finally:
        src.stop()


def test_filterlog_source_partial_line_buffered(tmp_path):
    log = tmp_path / "filter.log"
    log.write_text("")
    src = FilterlogSource(queue.Queue(), path=str(log))
    src.start()
    try:
        with log.open("a") as fh:
            fh.write(FL_V4_TCP)           # no trailing newline yet
        assert src.poll_once() == 0       # held as partial
        with log.open("a") as fh:
            fh.write("\n")                # line now complete
        assert src.poll_once() == 1
    finally:
        src.stop()


def test_filterlog_source_start_false_when_missing(tmp_path):
    src = FilterlogSource(queue.Queue(), path=str(tmp_path / "nope.log"))
    assert src.start() is False
