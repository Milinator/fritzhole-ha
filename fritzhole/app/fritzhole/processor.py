"""PCAP records -> correlated DNS events."""
from __future__ import annotations

import logging
from collections import OrderedDict
from dataclasses import dataclass, asdict

from . import dnsparse, netparse
from .pcap import PcapRecord
from .tcpreasm import TcpReassembler

log = logging.getLogger(__name__)

DNS_PORT = 53
QUERY_TIMEOUT = 10.0
DEDUP_WINDOW = 2.0
MAX_PENDING = 20_000


@dataclass(slots=True)
class DnsEvent:
    ts: float
    client_ip: str
    client_mac: str | None
    server_ip: str
    transport: str
    qname: str
    qtype: str
    status: str  # allowed | blocked | nxdomain | error | no_answer
    rcode: int | None
    answers: str
    latency_ms: float | None

    def as_dict(self) -> dict:
        return asdict(self)


class Processor:
    def __init__(self, linktype: int, tcp_enabled: bool = True):
        self.linktype = linktype
        self.tcp_enabled = tcp_enabled
        self.tcp = TcpReassembler()
        self.pending: OrderedDict[tuple, tuple[float, str | None]] = OrderedDict()
        self.recent: OrderedDict[tuple, float] = OrderedDict()
        self.last_ts = 0.0
        self.stats = dict(frames=0, dns=0, malformed=0, truncated=0, fragments=0,
                          ignored=0, events=0, duplicates=0, unmatched=0, tcp_messages=0)

    # ------------------------------------------------------------------ input
    def feed(self, rec: PcapRecord) -> list[DnsEvent]:
        self.stats["frames"] += 1
        self.last_ts = max(self.last_ts, rec.ts)
        try:
            pkt = netparse.decode(rec.data, self.linktype)
        except netparse.Skip:
            self.stats["fragments"] += 1
            return []
        except (ValueError, IndexError):
            self.stats["malformed"] += 1
            return []
        if pkt is None or DNS_PORT not in (pkt.sport, pkt.dport):
            self.stats["ignored"] += 1
            return []
        if pkt.proto == "udp":
            if rec.truncated:
                self.stats["truncated"] += 1
                return []
            return self._message(rec.ts, pkt, pkt.payload)
        if not self.tcp_enabled:
            self.stats["ignored"] += 1
            return []
        key = (pkt.src, pkt.sport, pkt.dst, pkt.dport)
        out: list[DnsEvent] = []
        for m in self.tcp.feed(key, pkt.seq, pkt.flags, pkt.payload, rec.truncated):
            self.stats["tcp_messages"] += 1
            out += self._message(rec.ts, pkt, m)
        return out

    # -------------------------------------------------------------- messages
    def _message(self, ts: float, pkt: netparse.Packet, payload: bytes) -> list[DnsEvent]:
        try:
            msg = dnsparse.parse(payload)
        except (dnsparse.DnsError, ValueError, IndexError):
            self.stats["malformed"] += 1
            return []
        if msg.opcode != 0:
            self.stats["ignored"] += 1
            return []
        self.stats["dns"] += 1
        if not msg.is_response:
            if pkt.dport != DNS_PORT:
                return []
            key = (pkt.src, pkt.sport, pkt.dst, msg.txid, msg.qname, msg.qtype, pkt.proto)
            if key not in self.pending:
                self.pending[key] = (ts, pkt.src_mac)
                if len(self.pending) > MAX_PENDING:
                    self.pending.popitem(last=False)
            return []
        if pkt.sport != DNS_PORT:
            return []
        key = (pkt.dst, pkt.dport, pkt.src, msg.txid, msg.qname, msg.qtype, pkt.proto)
        prev = self.recent.get(key)
        if prev is not None and ts - prev < DEDUP_WINDOW:
            self.stats["duplicates"] += 1
            return []
        self.recent[key] = ts
        self.recent.move_to_end(key)
        q = self.pending.pop(key, None)
        latency = None
        mac = pkt.dst_mac
        if q:
            latency = max(0.0, (ts - q[0]) * 1000.0)
            mac = mac or q[1]
        else:
            self.stats["unmatched"] += 1
        answers = ", ".join(a.value for a in msg.answers if a.value)
        if not answers and msg.rcode:
            answers = dnsparse.RCODES.get(msg.rcode, f"rcode={msg.rcode}")
        ev = DnsEvent(
            ts=ts, client_ip=pkt.dst, client_mac=mac, server_ip=pkt.src, transport=pkt.proto,
            qname=msg.qname, qtype=dnsparse.qtype_name(msg.qtype), status=dnsparse.classify(msg),
            rcode=msg.rcode, answers=answers[:512], latency_ms=latency,
        )
        self.stats["events"] += 1
        return [ev]

    # ----------------------------------------------------------- housekeeping
    def expire(self, now: float | None = None) -> list[DnsEvent]:
        """Emit no_answer events for timed-out queries; prune caches.

        `now` ist Capture-Zeit (Zeitstempel der FRITZ!Box), nicht lokale Uhr.
        """
        now = self.last_ts if now is None else now
        out = []
        while self.pending:
            key, (ts, mac) = next(iter(self.pending.items()))
            if now - ts < QUERY_TIMEOUT:
                break
            self.pending.popitem(last=False)
            client, _port, server, _txid, qname, qtype, proto = key
            out.append(DnsEvent(ts, client, mac, server, proto, qname, dnsparse.qtype_name(qtype),
                                "no_answer", None, "", None))
            self.stats["events"] += 1
        while self.recent:
            key, ts = next(iter(self.recent.items()))
            if now - ts < DEDUP_WINDOW * 5 and len(self.recent) < 50_000:
                break
            self.recent.popitem(last=False)
        self.tcp.housekeeping()
        return out

    def flush(self) -> list[DnsEvent]:
        """Bei Stream-Ende: offene Anfragen nicht als no_answer werten (Ursache unklar)."""
        self.pending.clear()
        self.recent.clear()
        return []

