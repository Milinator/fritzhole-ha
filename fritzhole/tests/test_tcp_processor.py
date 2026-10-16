import struct

from fritzhole.pcap import PcapRecord
from fritzhole.processor import Processor
from fritzhole.tcpreasm import TcpReassembler
from pkt import dns_query, dns_response, eth, ipv4, tcp, v4_udp, v6_udp

BOX, CLI = "192.168.178.1", "192.168.178.20"
SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01


def rec(frame, ts=1000.0, truncated=False):
    return PcapRecord(ts=ts, data=frame if not truncated else frame[:50], orig_len=len(frame))


def framed(msg):
    return struct.pack("!H", len(msg)) + msg


# ------------------------------------------------------------------ TCP reassembly
def test_tcp_in_order_split_segments():
    r = TcpReassembler()
    k = ("a", 1, "b", 53)
    m = framed(dns_response(1, "x.example", 1, ["1.2.3.4"]))
    assert r.feed(k, 100, SYN, b"") == []
    assert r.feed(k, 101, ACK, m[:5]) == []
    out = r.feed(k, 106, ACK, m[5:])
    assert out == [m[2:]]


def test_tcp_out_of_order_and_retransmit():
    r = TcpReassembler()
    k = ("a", 1, "b", 53)
    m1 = framed(dns_response(1, "a.example", 1, ["1.1.1.1"]))
    m2 = framed(dns_response(2, "b.example", 1, ["0.0.0.0"]))
    data = m1 + m2
    r.feed(k, 0, SYN, b"")
    assert r.feed(k, 1 + 10, ACK, data[10:]) == []          # später Teil zuerst
    assert r.feed(k, 1, ACK, data[:4]) == []
    out = r.feed(k, 1, ACK, data[:10])                       # Retransmission mit Überlappung
    assert out == [m1[2:], m2[2:]]


def test_tcp_seq_wraparound():
    r = TcpReassembler()
    k = ("a", 1, "b", 53)
    m = framed(dns_response(9, "w.example", 1, ["1.2.3.4"]))
    isn = 2**32 - 3
    r.feed(k, isn, SYN, b"")
    assert r.feed(k, (isn + 1) % 2**32, ACK, m[:6]) == []
    assert r.feed(k, (isn + 7) % 2**32, ACK, m[6:]) == [m[2:]]


def test_tcp_unsynced_flow_ignored():
    r = TcpReassembler()
    m = framed(dns_response(1, "x.example", 1, ["1.2.3.4"]))
    assert r.feed(("a", 1, "b", 53), 5000, ACK, m) == []
    assert r.stats["unsynced_segments"] == 1


def test_tcp_truncated_segment_drops_flow():
    r = TcpReassembler()
    k = ("a", 1, "b", 53)
    r.feed(k, 0, SYN, b"")
    assert r.feed(k, 1, ACK, b"\x00\x10abc", truncated=True) == []
    assert k not in r.flows and r.stats["dropped_flows"] == 1


# ------------------------------------------------------------------ processor
def test_udp_query_response_correlation():
    p = Processor(1)
    q = v4_udp(CLI, BOX, 5353, 53, dns_query(42, "ads.example"), dmac="3c:a6:2f:00:00:fe", smac="aa:bb:cc:00:00:01")
    r = v4_udp(BOX, CLI, 53, 5353, dns_response(42, "ads.example", 1, ["0.0.0.0"]))
    assert p.feed(rec(q, 1000.0)) == []
    [ev] = p.feed(rec(r, 1000.025))
    assert ev.status == "blocked" and ev.client_ip == CLI and ev.server_ip == BOX
    assert ev.client_mac == "aa:bb:cc:00:00:01" and ev.qtype == "A" and ev.answers == "0.0.0.0"
    assert abs(ev.latency_ms - 25.0) < 0.01


def test_duplicate_response_suppressed():
    p = Processor(1)
    r = v4_udp(BOX, CLI, 53, 5353, dns_response(42, "x.example", 1, ["1.2.3.4"]))
    assert len(p.feed(rec(r, 1.0))) == 1
    assert p.feed(rec(r, 1.001)) == []
    assert p.stats["duplicates"] == 1


def test_unanswered_query_times_out():
    p = Processor(1)
    p.feed(rec(v4_udp(CLI, BOX, 6000, 53, dns_query(1, "slow.example")), 100.0))
    assert p.expire(105.0) == []
    [ev] = p.expire(111.0)
    assert ev.status == "no_answer" and ev.qname == "slow.example"


def test_ipv6_aaaa_blocked():
    p = Processor(1)
    [ev] = p.feed(rec(v6_udp("fd00::1", "fd00::20", 53, 7000, dns_response(5, "t.example", 28, ["::"]))))
    assert ev.status == "blocked" and ev.qtype == "AAAA" and ev.client_ip == "fd00::20"


def test_truncated_udp_and_malformed_counted():
    p = Processor(1)
    f = v4_udp(BOX, CLI, 53, 1, dns_response(1, "a.example", 1, ["1.2.3.4"]))
    assert p.feed(rec(f, truncated=True)) == []
    assert p.feed(rec(v4_udp(BOX, CLI, 53, 1, b"\x00\x01garbage"))) == []
    assert p.stats["truncated"] == 1 and p.stats["malformed"] == 1


def test_non_dns_ignored():
    p = Processor(1)
    assert p.feed(rec(v4_udp(BOX, CLI, 123, 123, b"ntp"))) == []


def test_tcp_dns_end_to_end():
    p = Processor(1)
    resp = framed(dns_response(77, "big.example", 1, ["0.0.0.0"]))

    def seg(seq, flags, payload=b""):
        return rec(eth(ipv4(BOX, CLI, 6, tcp(53, 40000, seq, flags, payload))))

    assert p.feed(seg(500, SYN | ACK)) == []
    assert p.feed(seg(501, ACK | PSH, resp[:3])) == []
    [ev] = p.feed(seg(504, ACK | PSH, resp[3:]))
    assert ev.transport == "tcp" and ev.status == "blocked" and ev.qname == "big.example"


def test_tcp_disabled():
    p = Processor(1, tcp_enabled=False)
    f = eth(ipv4(BOX, CLI, 6, tcp(53, 40000, 1, SYN)))
    assert p.feed(rec(f)) == []
