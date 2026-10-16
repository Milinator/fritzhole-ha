"""DNS-over-TCP stream reassembly (RFC 1035 4.2.2 / RFC 7766).

Konservativ: Ein Flow wird nur ausgewertet, wenn sein Anfang (SYN) gesehen wurde.
Bei Lücken, abgeschnittenen Segmenten oder Überlauf wird der Flow verworfen,
statt halbe Nachrichten zu interpretieren.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

SYN, FIN, RST = 0x02, 0x01, 0x04
MOD = 1 << 32

MAX_FLOWS = 256
MAX_BUFFER = 128 * 1024
MAX_PENDING_SEGMENTS = 64
FLOW_TIMEOUT = 120.0


def _diff(a: int, b: int) -> int:
    """Signed distance a-b in 32-bit sequence space."""
    d = (a - b) % MOD
    return d - MOD if d >= MOD // 2 else d


@dataclass
class _Flow:
    next_seq: int
    buf: bytearray = field(default_factory=bytearray)
    pending: dict[int, bytes] = field(default_factory=dict)
    last_seen: float = 0.0


class TcpReassembler:
    def __init__(self, clock=time.monotonic):
        self.flows: dict[tuple, _Flow] = {}
        self.clock = clock
        self.stats = {"messages": 0, "dropped_flows": 0, "unsynced_segments": 0}

    def _drop(self, key):
        if self.flows.pop(key, None) is not None:
            self.stats["dropped_flows"] += 1

    def feed(self, key: tuple, seq: int, flags: int, payload: bytes, truncated: bool = False) -> list[bytes]:
        """Feed one segment; returns complete DNS messages (without length prefix)."""
        now = self.clock()
        if flags & RST:
            self._drop(key)
            return []
        flow = self.flows.get(key)
        if flags & SYN:
            if len(self.flows) >= MAX_FLOWS:
                self._expire(now, force=True)
            flow = _Flow(next_seq=(seq + 1) % MOD, last_seen=now)
            self.flows[key] = flow
            seq = (seq + 1) % MOD  # Payload hinter SYN (TFO) beginnt bei seq+1
        if flow is None:
            if payload:
                self.stats["unsynced_segments"] += 1
            return []
        flow.last_seen = now
        if truncated:
            self._drop(key)
            return []
        if payload:
            d = _diff(seq, flow.next_seq)
            if d > 0:
                if len(flow.pending) >= MAX_PENDING_SEGMENTS:
                    self._drop(key)
                    return []
                flow.pending.setdefault(seq, payload)
            else:
                self._append(flow, payload[-d:] if d < 0 else payload)  # Überlappung kürzen
                # ausstehende Segmente nachziehen
                progressed = True
                while progressed and flow.pending:
                    progressed = False
                    for pseq in list(flow.pending):
                        pd = _diff(pseq, flow.next_seq)
                        if pd <= 0:
                            data = flow.pending.pop(pseq)
                            if -pd < len(data):
                                self._append(flow, data[-pd:] if pd < 0 else data)
                            progressed = True
            if len(flow.buf) > MAX_BUFFER:
                self._drop(key)
                return []
        out = self._extract(flow)
        if flags & FIN and not flow.pending:
            self.flows.pop(key, None)
        return out

    @staticmethod
    def _append(flow: _Flow, data: bytes):
        flow.buf += data
        flow.next_seq = (flow.next_seq + len(data)) % MOD

    def _extract(self, flow: _Flow) -> list[bytes]:
        msgs = []
        while len(flow.buf) >= 2:
            n = (flow.buf[0] << 8) | flow.buf[1]
            if len(flow.buf) < 2 + n:
                break
            msgs.append(bytes(flow.buf[2:2 + n]))
            del flow.buf[:2 + n]
        self.stats["messages"] += len(msgs)
        return msgs

    def _expire(self, now: float, force: bool = False):
        for k, f in list(self.flows.items()):
            if now - f.last_seen > FLOW_TIMEOUT:
                self._drop(k)
        if force and len(self.flows) >= MAX_FLOWS:
            oldest = min(self.flows, key=lambda k: self.flows[k].last_seen)
            self._drop(oldest)

    def housekeeping(self):
        self._expire(self.clock())
