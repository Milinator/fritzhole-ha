"""Minimal, defensive DNS message parser (RFC 1035, AAAA: RFC 3596)."""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field

QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY",
}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
BLOCK_ADDRS = frozenset({"0.0.0.0", "::"})

MAX_RR = 100


class DnsError(ValueError):
    pass


@dataclass(slots=True)
class Answer:
    name: str
    rtype: int
    ttl: int
    value: str | None  # IP für A/AAAA, Ziel für CNAME, sonst None


@dataclass(slots=True)
class DnsMessage:
    txid: int
    is_response: bool
    opcode: int
    rcode: int
    qname: str
    qtype: int
    answers: list[Answer] = field(default_factory=list)
    truncated: bool = False  # TC-Flag

    @property
    def addresses(self) -> list[str]:
        return [a.value for a in self.answers if a.rtype in (1, 28) and a.value]


def qtype_name(t: int) -> str:
    return QTYPES.get(t, f"TYPE{t}")


def read_name(buf: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    visited: set[int] = set()
    next_offset: int | None = None
    total = 0
    for _ in range(128):
        if offset >= len(buf) or offset in visited:
            raise DnsError("Ungültiger DNS-Name (Schleife/Überlauf)")
        visited.add(offset)
        n = buf[offset]
        if n & 0xC0 == 0xC0:
            if offset + 1 >= len(buf):
                raise DnsError("DNS-Pointer abgeschnitten")
            if next_offset is None:
                next_offset = offset + 2
            offset = ((n & 0x3F) << 8) | buf[offset + 1]
            continue
        if n & 0xC0:
            raise DnsError("Ungültiges DNS-Label")
        offset += 1
        if n == 0:
            return ".".join(labels), (next_offset if next_offset is not None else offset)
        if offset + n > len(buf):
            raise DnsError("DNS-Label abgeschnitten")
        total += n + 1
        if total > 255:
            raise DnsError("DNS-Name zu lang")
        labels.append(buf[offset:offset + n].decode("ascii", errors="replace"))
        offset += n
    raise DnsError("DNS-Name zu lang")


def parse(payload: bytes) -> DnsMessage:
    if len(payload) < 12:
        raise DnsError("DNS-Header abgeschnitten")
    txid, flags, qd, an, _ns, _ar = struct.unpack_from("!HHHHHH", payload)
    if qd != 1:
        raise DnsError(f"Nicht unterstützte Anzahl Fragen: {qd}")
    qname, off = read_name(payload, 12)
    if off + 4 > len(payload):
        raise DnsError("DNS-Frage abgeschnitten")
    qtype, _qclass = struct.unpack_from("!HH", payload, off)
    off += 4
    msg = DnsMessage(
        txid=txid,
        is_response=bool(flags & 0x8000),
        opcode=(flags >> 11) & 0xF,
        rcode=flags & 0xF,
        qname=qname.lower().rstrip("."),
        qtype=qtype,
        truncated=bool(flags & 0x0200),
    )
    if not msg.is_response:
        return msg
    for _ in range(min(an, MAX_RR)):
        name, off = read_name(payload, off)
        if off + 10 > len(payload):
            raise DnsError("Resource Record abgeschnitten")
        rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", payload, off)
        off += 10
        if off + rdlen > len(payload):
            raise DnsError("RDATA abgeschnitten")
        rdata = payload[off:off + rdlen]
        value = None
        if rclass == 1 and rtype == 1 and rdlen == 4:
            value = str(ipaddress.IPv4Address(rdata))
        elif rclass == 1 and rtype == 28 and rdlen == 16:
            value = str(ipaddress.IPv6Address(rdata))
        elif rtype == 5:
            value, _ = read_name(payload, off)
        msg.answers.append(Answer(name.lower(), rtype, ttl, value))
        off += rdlen
    return msg


def classify(msg: DnsMessage) -> str:
    """allowed | blocked | nxdomain | error

    Die FRITZ!Box beantwortet gefilterte Domains mit 0.0.0.0 bzw. :: (PoC-Befund).
    """
    if msg.rcode == 0:
        if any(a in BLOCK_ADDRS for a in msg.addresses):
            return "blocked"
        return "allowed"
    if msg.rcode == 3:
        return "nxdomain"
    return "error"
