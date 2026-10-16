import pytest

from fritzhole import dnsparse
from pkt import dns_query, dns_response


def test_query_parsed():
    m = dnsparse.parse(dns_query(0x1234, "Example.COM."))
    assert not m.is_response and m.txid == 0x1234 and m.qname == "example.com" and m.qtype == 1


def test_blocked_ipv4():
    m = dnsparse.parse(dns_response(1, "ads.example", 1, ["0.0.0.0"]))
    assert m.addresses == ["0.0.0.0"]
    assert dnsparse.classify(m) == "blocked"


def test_blocked_ipv6():
    m = dnsparse.parse(dns_response(1, "ads.example", 28, ["::"]))
    assert dnsparse.classify(m) == "blocked"


def test_allowed_with_cname_chain():
    m = dnsparse.parse(dns_response(2, "www.example.org", 1, ["93.184.215.14"], cname="edge.cdn.net"))
    assert [a.rtype for a in m.answers] == [5, 1]
    assert m.answers[0].value == "edge.cdn.net"
    assert m.answers[1].name == "edge.cdn.net"
    assert dnsparse.classify(m) == "allowed"


def test_blocked_behind_cname():
    m = dnsparse.parse(dns_response(2, "track.example", 1, ["0.0.0.0"], cname="x.tracker.net"))
    assert dnsparse.classify(m) == "blocked"


def test_nxdomain_and_servfail():
    assert dnsparse.classify(dnsparse.parse(dns_response(3, "nope.example", rcode=3))) == "nxdomain"
    assert dnsparse.classify(dnsparse.parse(dns_response(3, "x.example", rcode=2))) == "error"


def test_nodata_is_allowed():
    assert dnsparse.classify(dnsparse.parse(dns_response(4, "v4only.example", 28, []))) == "allowed"


@pytest.mark.parametrize("payload", [
    b"",
    b"\x00" * 11,
    dns_response(1, "a.example", 1, ["1.2.3.4"])[:-3],          # RDATA abgeschnitten
    dns_response(1, "a.example", 1, ["1.2.3.4"])[:20],          # Name abgeschnitten
    b"\x00\x01\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c",  # Pointer-Schleife
    b"\x00\x01\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00\x80abc",    # ungültiges Label
    b"\x00\x01\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00",          # keine Frage
])
def test_malformed_raises(payload):
    with pytest.raises(dnsparse.DnsError):
        dnsparse.parse(payload)


def test_name_too_long():
    long = ".".join(["a" * 63] * 5)
    with pytest.raises(dnsparse.DnsError):
        dnsparse.parse(dns_query(1, long))
