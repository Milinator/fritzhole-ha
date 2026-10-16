"""Test helpers: build DNS/UDP/TCP/IP/Ethernet frames and PCAP streams."""
import ipaddress
import struct

CLIENT_MAC = "aa:bb:cc:00:00:01"
BOX_MAC = "3c:a6:2f:00:00:fe"


def name(n: str) -> bytes:
    out = b""
    for label in n.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def dns_query(txid: int, qname: str, qtype: int = 1) -> bytes:
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + name(qname) + struct.pack("!HH", qtype, 1)


def dns_response(txid: int, qname: str, qtype: int = 1, answers=(), rcode: int = 0, cname: str | None = None) -> bytes:
    rrs = b""
    count = 0
    owner = b"\xc0\x0c"  # Pointer auf QNAME
    if cname:
        rd = name(cname)
        rrs += owner + struct.pack("!HHIH", 5, 1, 60, len(rd)) + rd
        owner = struct.pack("!H", 0xC000 | (12 + len(name(qname)) + 4 + 12))  # Pointer auf CNAME-Ziel
        count += 1
    for value in answers:
        ip = ipaddress.ip_address(value)
        t = 1 if ip.version == 4 else 28
        rrs += owner + struct.pack("!HHIH", t, 1, 300, len(ip.packed)) + ip.packed
        count += 1
    flags = 0x8180 | rcode
    return struct.pack("!HHHHHH", txid, flags, 1, count, 0, 0) + name(qname) + struct.pack("!HH", qtype, 1) + rrs


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport, seq, flags, payload=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 65535, 0, 0) + payload


def ipv4(src, dst, proto, payload, frag=0):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, frag, 64, proto, 0,
                      ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    return hdr + payload


def ipv6(src, dst, nh, payload, hopbyhop=False):
    if hopbyhop:
        payload = bytes([nh, 0]) + b"\x00" * 6 + payload
        nh = 0
    return struct.pack("!IHBB16s16s", 0x60000000, len(payload), nh, 64,
                       ipaddress.IPv6Address(src).packed, ipaddress.IPv6Address(dst).packed) + payload


def mac(m):
    return bytes(int(x, 16) for x in m.split(":"))


def eth(payload, ethertype=0x0800, dmac=CLIENT_MAC, smac=BOX_MAC, vlan=None):
    hdr = mac(dmac) + mac(smac)
    if vlan is not None:
        hdr += struct.pack("!HH", 0x8100, vlan)
    frame = hdr + struct.pack("!H", ethertype) + payload
    return frame + b"\x00" * max(0, 60 - len(frame))  # Ethernet-Padding


def v4_udp(src, dst, sport, dport, dns, **kw):
    return eth(ipv4(src, dst, 17, udp(sport, dport, dns)), **kw)


def v6_udp(src, dst, sport, dport, dns, **kw):
    hop = kw.pop("hopbyhop", False)
    return eth(ipv6(src, dst, 17, udp(sport, dport, dns), hopbyhop=hop), ethertype=0x86DD, **kw)


MAGIC = {
    "avm": (b"\x34\xcd\xb2\xa1", "<", 1e6, True),
    "std": (b"\xd4\xc3\xb2\xa1", "<", 1e6, False),
    "ns": (b"\x4d\x3c\xb2\xa1", "<", 1e9, False),
    "be": (b"\xa1\xb2\xc3\xd4", ">", 1e6, False),
}


def pcap(frames, kind="avm", linktype=1, ifindex=23, t0=1_760_000_000.0, step=0.01, truncate=None):
    magic, e, scale, ext = MAGIC[kind]
    out = magic + struct.pack(e + "HHiII", 2, 4, 0, 0, 1600) + struct.pack(e + "I", linktype)
    for i, f in enumerate(frames):
        ts = t0 + i * step
        if isinstance(f, tuple):
            ts, f = f
        sec = int(ts)
        frac = int(round((ts - sec) * scale))
        data = f if truncate is None else f[:truncate]
        out += struct.pack(e + "IIII", sec, frac, len(data), len(f))
        if ext:
            out += struct.pack(e + "IHBB", ifindex, 0x0800, 0, 0)
        out += data
    return out
