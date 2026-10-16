import hashlib
import logging
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from fritzhole import capture as capmod
from fritzhole.capture import CaptureService
from fritzhole.config import RedactFilter
from fritzhole.fritzbox import FritzBox, capture_query, compute_response, parse_host_list, split_host
from pkt import dns_query, dns_response, pcap, v4_udp, v6_udp

PASSWORD = "geheim-Passw0rt"
SID = "0123456789abcdef"
CHALLENGE = "2$10$" + "aa" * 16 + "$10$" + "bb" * 16
WORKING_FILTER = "filter=udp%20port%2053%20or%20tcp%20port%2053"


def test_capture_query_uses_percent20_not_plus():
    q = capture_query(SID, "1-lan")
    assert WORKING_FILTER in q
    assert "+" not in q
    assert q == f"sid={SID}&capture=Start&snaplen=1600&{WORKING_FILTER}&ifaceorminor=1-lan"
    assert capture_query(SID, "1-lan", start=False) == f"sid={SID}&capture=Stop&ifaceorminor=1-lan"


def test_compute_response_pbkdf2_and_md5():
    r = compute_response(CHALLENGE, PASSWORD)
    h1 = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), bytes.fromhex("aa" * 16), 10)
    h2 = hashlib.pbkdf2_hmac("sha256", h1, bytes.fromhex("bb" * 16), 10)
    assert r == "bb" * 16 + "$" + h2.hex()


def test_pbkdf2_avm_reference_vector():
    # Beispiel aus der AVM Technical Note "Session ID"
    r = compute_response("2$10000$5A1711$2000$5A1722", "1example!")
    assert r == "5A1722$1798a1672bca7c6463d6b245f82b53703b0f50813401b03e4045a5861e689adb"
    md5 = compute_response("1234abcd", "äbc")
    assert md5 == "1234abcd-" + hashlib.md5("1234abcd-äbc".encode("utf-16le")).hexdigest()


@pytest.mark.parametrize("raw,exp", [("192.168.178.1", ("192.168.178.1", 80)), ("http://fritz.box/", ("fritz.box", 80)),
                                     ("fritz.box:8080", ("fritz.box", 8080)), ("[fd00::1]", ("fd00::1", 80))])
def test_split_host(raw, exp):
    assert split_host(raw) == exp


def test_repr_hides_password():
    assert PASSWORD not in repr(FritzBox("1.2.3.4", "u", PASSWORD))


def test_host_list_parse():
    xml = (b"<List><Item><Index>1</Index><IPAddress>192.168.178.20</IPAddress><MACAddress>AA:BB:CC:00:00:01"
           b"</MACAddress><Active>1</Active><HostName>iPhone</HostName></Item><Item><IPAddress/><MACAddress/>"
           b"</Item></List>")
    [h] = parse_host_list(xml)
    assert (h.ip, h.mac, h.name, h.active) == ("192.168.178.20", "aa:bb:cc:00:00:01", "iPhone", True)


def test_redact_filter():
    f = RedactFilter([PASSWORD])
    rec = logging.LogRecord("x", logging.INFO, "", 0, "GET /x?sid=%s&response=%s pw=%s", (SID, "abc", PASSWORD), None)
    f.filter(rec)
    msg = rec.getMessage()
    assert SID not in msg and PASSWORD not in msg and "abc" not in msg


# ---------------------------------------------------------------- fake FRITZ!Box
class FakeBox:
    def __init__(self, stream: bytes, fail_logins=0):
        self.stream = stream
        self.requests: list[str] = []
        self.fail_logins = fail_logins
        box = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                box.requests.append(self.path)
                path, _, raw = self.path.partition("?")
                q = urllib.parse.parse_qs(raw)
                if path == "/login_sid.lua":
                    if "logout" in q:
                        return self._xml(f"<SessionInfo><SID>{'0' * 16}</SID></SessionInfo>")
                    if "response" in q:
                        ok = q["response"][0] == compute_response(CHALLENGE, PASSWORD) and box.fail_logins <= 0
                        box.fail_logins -= 1
                        return self._xml(f"<SessionInfo><SID>{SID if ok else '0' * 16}</SID><BlockTime>0</BlockTime>"
                                         "</SessionInfo>")
                    return self._xml(f"<SessionInfo><SID>{'0' * 16}</SID><Challenge>{CHALLENGE}</Challenge>"
                                     "<BlockTime>0</BlockTime></SessionInfo>")
                if path == "/cgi-bin/capture_notimeout":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.end_headers()
                    # Verhalten der echten Box: '+' im Filter -> kein PCAP
                    if "capture=Start" in raw and WORKING_FILTER in raw and q.get("sid") == [SID]:
                        self.wfile.write(box.stream)
                        self.wfile.flush()
                        time.sleep(0.3)
                    return
                self.send_error(404)

            def _xml(self, s):
                b = s.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/xml")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


@pytest.fixture
def fast_backoff(monkeypatch):
    monkeypatch.setattr(capmod, "BACKOFF_MIN", 0.05)
    monkeypatch.setattr(capmod, "AUTH_BACKOFF", 0.05)


def _wait(cond, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


def test_capture_end_to_end_with_reconnect(fast_backoff, caplog):
    caplog.set_level(logging.DEBUG)
    frames = [
        v4_udp("192.168.178.20", "192.168.178.1", 5000, 53, dns_query(1, "ads.example"),
               dmac="3c:a6:2f:00:00:fe", smac="aa:bb:cc:00:00:01"),
        v4_udp("192.168.178.1", "192.168.178.20", 53, 5000, dns_response(1, "ads.example", 1, ["0.0.0.0"])),
        v6_udp("fd00::1", "fd00::20", 53, 5001, dns_response(2, "ok.example", 28, ["2001:db8::1"])),
    ]
    box = FakeBox(pcap(frames, kind="avm"), fail_logins=1)
    got = []
    svc = CaptureService(FritzBox(f"127.0.0.1:{box.port}", "user", PASSWORD), "1-lan", got.extend, debug=True)
    try:
        svc.start()
        assert _wait(lambda: len(got) >= 4)  # zwei Sessions (Stream-Ende -> Reconnect)
    finally:
        svc.stop()
        box.close()
    assert [e.status for e in got[:2]] == ["blocked", "allowed"]
    assert got[0].client_mac == "aa:bb:cc:00:00:01" and got[0].latency_ms is not None
    starts = [r for r in box.requests if "capture=Start" in r]
    assert starts and all(WORKING_FILTER in r for r in starts)
    assert any("capture=Stop" in r for r in box.requests)
    assert any("logout=1" in r for r in box.requests)
    assert svc.sessions >= 2
    assert PASSWORD not in caplog.text


def test_plus_encoded_filter_yields_no_stream(fast_backoff):
    """Regression: so sähe es aus, wenn die Kodierung kaputt wäre (FakeBox liefert dann nichts)."""
    import urllib.request
    box = FakeBox(pcap([], kind="avm"))
    try:
        bad = urllib.parse.urlencode({"sid": SID, "capture": "Start", "filter": "udp port 53 or tcp port 53"})
        with urllib.request.urlopen(f"http://127.0.0.1:{box.port}/cgi-bin/capture_notimeout?{bad}") as r:
            assert r.read() == b""
    finally:
        box.close()


def test_auth_error_state(fast_backoff):
    box = FakeBox(b"", fail_logins=100)
    svc = CaptureService(FritzBox(f"127.0.0.1:{box.port}", "user", "falsch"), "1-lan", lambda e: None)
    try:
        svc.start()
        assert _wait(lambda: svc.state == "auth_error")
        assert "Anmeldung fehlgeschlagen" in svc.last_error
    finally:
        svc.stop()
        box.close()


def test_empty_capture_stream_message(fast_backoff):
    box = FakeBox(b"")  # Box antwortet 200 ohne Daten (paralleler Mitschnitt)
    svc = CaptureService(FritzBox(f"127.0.0.1:{box.port}", "user", PASSWORD), "1-lan", lambda e: None)
    try:
        svc.start()
        assert _wait(lambda: svc.last_error and "keine Mitschnittdaten" in svc.last_error)
        assert svc.state == "backoff"
    finally:
        svc.stop()
        box.close()
