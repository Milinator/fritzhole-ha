"""Streaming PCAP reader incl. AVM/Kuznetsov variant.

FRITZ!OS liefert den Mitschnitt im "modified pcap"-Format (Magic 0xa1b2cd34,
Kuznetsov-Patch). Jeder Record-Header ist dort 24 statt 16 Byte lang:
ts_sec, ts_usec, caplen, len, ifindex(4), protocol(2), pkt_type(1), pad(1).
Der PoC hat diese 8 Zusatzbytes dem Frame vorangestellt; hier werden sie sauber
aus dem Record-Header entfernt und separat bereitgestellt.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator

MAX_RECORD = 262_144  # Obergrenze gegen kaputte Längenfelder

# magic bytes (as on the wire) -> (endian, nanosecond, kuznetsov_ext)
MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", False, False),
    b"\xa1\xb2\xc3\xd4": (">", False, False),
    b"\x4d\x3c\xb2\xa1": ("<", True, False),
    b"\xa1\xb2\x3c\x4d": (">", True, False),
    b"\x34\xcd\xb2\xa1": ("<", False, True),  # AVM / Kuznetsov
    b"\xa1\xb2\xcd\x34": (">", False, True),
}


class PcapError(Exception):
    """Unrecoverable stream format error."""


@dataclass(slots=True)
class PcapRecord:
    ts: float
    data: bytes
    orig_len: int
    ifindex: int | None = None

    @property
    def truncated(self) -> bool:
        return len(self.data) < self.orig_len


def read_exact(stream: BinaryIO, size: int) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        chunk = stream.read(size - len(buf))
        if not chunk:
            if not buf:
                raise EOFError("Mitschnitt-Stream beendet")
            raise EOFError(f"Mitschnitt-Stream mitten im Record beendet ({len(buf)}/{size} Byte)")
        buf.extend(chunk)
    return bytes(buf)


class PcapReader:
    def __init__(self, stream: BinaryIO):
        self.stream = stream
        hdr = read_exact(stream, 24)
        fmt = MAGICS.get(hdr[:4])
        if fmt is None:
            raise PcapError("Unbekannter PCAP-Header: " + hdr[:4].hex())
        self.endian, self.nano, self.ext = fmt
        self.version = struct.unpack_from(self.endian + "HH", hdr, 4)
        self.snaplen, self.linktype = struct.unpack_from(self.endian + "II", hdr, 16)
        self.linktype &= 0x0FFFFFFF  # obere Bits: FCS-Info
        self._rec_len = 24 if self.ext else 16

    @property
    def variant(self) -> str:
        return "avm-kuznetsov" if self.ext else ("pcap-ns" if self.nano else "pcap")

    def __iter__(self) -> Iterator[PcapRecord]:
        return self

    def __next__(self) -> PcapRecord:
        try:
            rh = read_exact(self.stream, self._rec_len)
        except EOFError as exc:
            if "mitten" in str(exc):
                raise
            raise StopIteration from None
        ts_sec, ts_frac, incl, orig = struct.unpack_from(self.endian + "IIII", rh)
        if incl > MAX_RECORD:
            raise PcapError(f"Ungültige Paketlänge {incl} – Stream nicht synchron")
        ifindex = struct.unpack_from(self.endian + "I", rh, 16)[0] if self.ext else None
        data = read_exact(self.stream, incl) if incl else b""
        ts = ts_sec + ts_frac / (1e9 if self.nano else 1e6)
        return PcapRecord(ts=ts, data=data, orig_len=orig, ifindex=ifindex)
