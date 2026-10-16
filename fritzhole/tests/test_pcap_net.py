import io

import pytest

from fritzhole import netparse
from fritzhole.pcap import PcapError, PcapReader
from pkt import (CLIENT_MAC, BOX_MAC, dns_response, eth, ipv4, ipv6, pcap, udp, v4_udp, v6_udp)

RESP = dns_response(7, "ads.example", 1, ["0.0.0.0"])


@pytest.mark.parametrize("kind", ["avm", "std", "ns", "be"])
def test_reader_variants(kind):
    data = pcap([v4_udp("192.168.178.1", "192.168.178.20", 53, 5000, RESP)] * 2, kind=kind)
    r = PcapReader(io.BytesIO(data))
    recs = list(r)
    assert r.linktype == 1 and len(recs) == 2
    assert abs(recs[0].ts - 1_760_000_000.0) < 1e-5
    assert abs(recs[1].ts - recs[0].ts - 0.01) < 1e-5
    assert (recs[0].ifindex == 23) == (kind == "avm")
    pkt = netparse.decode(recs[0].data, r.linktype)
    assert pkt.src == "192.168.178.1" and pkt.dst == "192.168.178.20" and pkt.sport == 53
    assert pkt.dst_mac == CLIENT_MAC and pkt.src_mac == BOX_MAC
    assert pkt.payload == RESP  # Ethernet-Padding entfernt


def test_unknown_magic():
    with pytest.raises(PcapError):
        PcapReader(io.BytesIO(b"\x00" * 24))


def test_truncated_stream_mid_record():
    data = pcap([v4_udp("192.168.178.1", "192.168.178.20", 53, 5000, RESP)])
    r = PcapReader(io.BytesIO(data[:-5]))
    with pytest.raises(EOFError):
        list(r)


def test_insane_length_raises():
    data = bytearray(pcap([v4_udp("192.168.178.1", "192.168.178.20", 53, 5000, RESP)], kind="std"))
    data[24 + 8:24 + 12] = (10_000_000).to_bytes(4, "little")
    with pytest.raises(PcapError):
        list(PcapReader(io.BytesIO(bytes(data))))


def test_snaplen_truncated_record_flagged():
    data = pcap([v4_udp("192.168.178.1", "192.168.178.20", 53, 5000, RESP)], truncate=40)
    rec = next(iter(PcapReader(io.BytesIO(data))))
    assert rec.truncated


def test_ipv6_with_extension_header():
    f = v6_udp("fd00::1", "fd00::abcd", 53, 40000, RESP, hopbyhop=True)
    pkt = netparse.decode(f, 1)
    assert pkt.src == "fd00::1" and pkt.dst == "fd00::abcd" and pkt.payload == RESP


def test_vlan_tagged():
    f = eth(ipv4("192.168.178.1", "192.168.178.30", 17, udp(53, 1234, RESP)), vlan=7)
    assert netparse.decode(f, 1).dst == "192.168.178.30"


def test_raw_ip_linktype():
    f = ipv4("192.168.178.1", "192.168.178.30", 17, udp(53, 1234, RESP))
    pkt = netparse.decode(f, 101)
    assert pkt.dst == "192.168.178.30" and pkt.dst_mac is None


def test_poc_prefixed_ethernet_fallback():
    # Frame mit 8-Byte-AVM-Präfix (wie vom PoC behandelt)
    f = b"\x17\x00\x00\x00\x00\x08\x00\x00" + v4_udp("192.168.178.1", "192.168.178.30", 53, 1, RESP)
    assert netparse.decode(f, 1).dst == "192.168.178.30"


def test_avm_linktype_2048():
    f = b"\x00\x00" + v4_udp("192.168.178.1", "192.168.178.30", 53, 1, RESP)
    assert netparse.decode(f, 2048).dst == "192.168.178.30"


def test_fragment_skipped():
    f = eth(ipv4("192.168.178.1", "192.168.178.30", 17, udp(53, 1, RESP), frag=0x2000))
    with pytest.raises(netparse.Skip):
        netparse.decode(f, 1)


def test_non_ip_and_garbage():
    assert netparse.decode(eth(b"\x00" * 30, ethertype=0x0806), 1) is None  # ARP
    assert netparse.decode(b"\x01\x02", 1) is None
    bad = bytearray(v4_udp("192.168.178.1", "192.168.178.30", 53, 1, RESP))
    bad[14 + 2:14 + 4] = (5).to_bytes(2, "big")  # total length < IHL
    with pytest.raises(ValueError):
        netparse.decode(bytes(bad), 1)
