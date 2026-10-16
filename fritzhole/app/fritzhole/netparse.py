"""Link/IP/UDP/TCP decoding for captured frames (IPv4 + IPv6)."""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
VLAN_TAGS = (0x8100, 0x88A8, 0x9100)

LT_ETHERNET = 1
LT_RAW = (12, 14, 101)
LT_IPV4 = 228
LT_IPV6 = 229
LT_SLL = 113
LT_SLL2 = 276
LT_AVM_FRELAY = 2048  # laut PoC: 2-Byte-Präfix + Ethernet


@dataclass(slots=True)
class Packet:
    src: str
    dst: str
    proto: str  # "udp" | "tcp"
    sport: int
    dport: int
    payload: bytes
    src_mac: str | None = None
    dst_mac: str | None = None
    seq: int = 0
    flags: int = 0  # TCP flags


class Skip(Exception):
    """Frame is valid but not relevant (fragment, other protocol ...)."""


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _ip_plausible(frame: bytes, off: int, ethertype: int) -> bool:
    if ethertype == ETH_IPV4:
        return len(frame) >= off + 20 and frame[off] >> 4 == 4 and (frame[off] & 15) >= 5
    if ethertype == ETH_IPV6:
        return len(frame) >= off + 40 and frame[off] >> 4 == 6
    return False


def _eth_at(frame: bytes, l2: int):
    """Ethernet header at offset l2 -> (ethertype, l3_offset, src_mac, dst_mac) or None."""
    if len(frame) < l2 + 14:
        return None
    et = struct.unpack_from("!H", frame, l2 + 12)[0]
    off = l2 + 14
    for _ in range(2):  # bis zu 2 VLAN-Tags (QinQ)
        if et in VLAN_TAGS and len(frame) >= off + 4:
            et = struct.unpack_from("!H", frame, off + 2)[0]
            off += 4
    if not _ip_plausible(frame, off, et):
        return None
    return et, off, _mac(frame[l2 + 6:l2 + 12]), _mac(frame[l2:l2 + 6])


def locate_l3(frame: bytes, linktype: int):
    """Return (ethertype, offset, src_mac, dst_mac) or None."""
    if linktype == LT_ETHERNET:
        # 8: PoC-Fallback für Frames mit vorangestelltem AVM-Präfix (17 00 00 00 ...)
        candidates = [0, 8]
    elif linktype == LT_AVM_FRELAY:
        candidates = [2, 0, 10]
    elif linktype in LT_RAW or linktype in (LT_IPV4, LT_IPV6):
        if not frame:
            return None
        et = {4: ETH_IPV4, 6: ETH_IPV6}.get(frame[0] >> 4)
        if et and _ip_plausible(frame, 0, et):
            return et, 0, None, None
        return None
    elif linktype == LT_SLL:
        if len(frame) < 16:
            return None
        et = struct.unpack_from("!H", frame, 14)[0]
        return (et, 16, None, None) if _ip_plausible(frame, 16, et) else None
    elif linktype == LT_SLL2:
        if len(frame) < 20:
            return None
        et = struct.unpack_from("!H", frame, 0)[0]
        return (et, 20, None, None) if _ip_plausible(frame, 20, et) else None
    else:
        candidates = [0, 2]
    for l2 in candidates:
        r = _eth_at(frame, l2)
        if r:
            return r
    return None


def decode(frame: bytes, linktype: int) -> Packet | None:
    """Decode a frame to a UDP/TCP packet. Returns None if not IP/UDP/TCP.

    Raises Skip for fragments, ValueError for malformed headers.
    """
    loc = locate_l3(frame, linktype)
    if loc is None:
        return None
    et, off, smac, dmac = loc
    if et == ETH_IPV4:
        ihl = (frame[off] & 15) * 4
        total = struct.unpack_from("!H", frame, off + 2)[0]
        if total < ihl or len(frame) < off + ihl:
            raise ValueError("IPv4-Header ungültig")
        frag = struct.unpack_from("!H", frame, off + 6)[0]
        if frag & 0x3FFF:  # MF-Flag oder Offset
            raise Skip("IPv4-Fragment")
        proto = frame[off + 9]
        src = str(ipaddress.IPv4Address(frame[off + 12:off + 16]))
        dst = str(ipaddress.IPv4Address(frame[off + 16:off + 20]))
        end = min(len(frame), off + total)  # Ethernet-Padding abschneiden
        off += ihl
    else:
        plen = struct.unpack_from("!H", frame, off + 4)[0]
        nh = frame[off + 6]
        src = str(ipaddress.IPv6Address(frame[off + 8:off + 24]))
        dst = str(ipaddress.IPv6Address(frame[off + 24:off + 40]))
        end = min(len(frame), off + 40 + plen)
        off += 40
        for _ in range(8):
            if nh == 44:
                raise Skip("IPv6-Fragment")
            if nh not in (0, 43, 60):
                break
            if end < off + 2:
                raise ValueError("IPv6-Extension-Header abgeschnitten")
            nh, off = frame[off], off + (frame[off + 1] + 1) * 8
        proto = nh
    if proto == 17:
        if end < off + 8:
            raise ValueError("UDP-Header abgeschnitten")
        sport, dport, ulen = struct.unpack_from("!HHH", frame, off)
        pend = min(end, off + ulen) if ulen >= 8 else end
        return Packet(src, dst, "udp", sport, dport, bytes(frame[off + 8:pend]), smac, dmac)
    if proto == 6:
        if end < off + 20:
            raise ValueError("TCP-Header abgeschnitten")
        sport, dport, seq = struct.unpack_from("!HHI", frame, off)
        doff = (frame[off + 12] >> 4) * 4
        flags = frame[off + 13]
        if doff < 20 or end < off + doff:
            raise ValueError("TCP-Header ungültig")
        return Packet(src, dst, "tcp", sport, dport, bytes(frame[off + doff:end]), smac, dmac, seq, flags)
    return None
