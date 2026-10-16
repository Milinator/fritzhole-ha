import json
import logging

import pytest
from starlette.testclient import TestClient

from fakeapi import API, PASSWORD, FakeFritzApi
from fritzhole.api import create_app
from fritzhole.db import Store
from fritzhole.dnsfilter import PAUSE_KEY, DnsFilterService, FilterError, normalize_domain
from fritzhole.fritzbox import ApiError, FritzBox, RestSession
from fritzhole.pipeline import LiveHub

H = {"X-FritzHole-Confirm": "1"}


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def box():
    b = FakeFritzApi()
    yield b
    b.close()


@pytest.fixture
def store(tmp_path):
    s = Store(str(tmp_path / "f.db"))
    yield s
    s.close()


def make(box, store, clock=None, writable=True, password=PASSWORD):
    rest = RestSession(FritzBox(f"127.0.0.1:{box.port}", "fritzhole", password), timeout=3)
    return DnsFilterService(rest, store, writable=writable, clock=clock or Clock())


# ------------------------------------------------------------------ validation
@pytest.mark.parametrize("raw,exp", [("Ads.Example.COM.", "ads.example.com"), ("*.tracker.net", "*.tracker.net"),
                                     ("bücher.de", "xn--bcher-kva.de"), ("_dmarc.x.de", "_dmarc.x.de")])
def test_normalize_domain_ok(raw, exp):
    assert normalize_domain(raw) == exp


@pytest.mark.parametrize("raw", ["", " ", "a b.de", "http://x.de", "x..de", "-x.de", "a.*.de", "x" * 300, "<script>.de"])
def test_normalize_domain_rejects(raw):
    with pytest.raises(FilterError):
        normalize_domain(raw)


# ------------------------------------------------------------------ API calls
def test_read_config_uses_avm_headers(box, store):
    svc = make(box, store)
    st = svc.state()
    assert st["available"] and st["config"]["enabled"] is True
    assert st["config"]["domains"][0] == {"uid": "domain1", "domain": "example.org", "action": "allow",
                                          "enabled": True, "comment": "Test"}
    assert st["config"]["filterlist_entries"] == 123456
    method, path, _, headers = box.requests[0]
    assert (method, path) == ("GET", API)
    assert headers["Authorization"].startswith("AVM-SID ") and headers["Client-Name"] == "WebGUI"


def test_cache_avoids_repeated_requests(box, store):
    svc = make(box, store)
    svc.state()
    svc.state()
    assert len(box.requests) == 1
    svc.state(max_age=0)
    assert len(box.requests) == 2


def test_add_edit_delete_verified(box, store):
    svc = make(box, store)
    svc.add_domain("Ads.Tracker.NET", "deny", "aus Live-Log")
    method, path, body, headers = box.requests[-2]
    assert (method, path) == ("POST", API + "/domains")
    assert body == {"enabled": True, "domain": "ads.tracker.net", "comment": "aus Live-Log", "action": "deny"}
    assert headers["Content-Type"] == "application/json" and headers["Origin"].startswith("http://127.0.0.1")
    assert box.requests[-1][0] == "GET"  # Verifikation
    uid = next(e["UID"] for e in box.cfg["domains"] if e["domain"] == "ads.tracker.net")

    svc.edit_domain(uid, action="allow", comment="doch erlaubt")
    assert box.requests[-2][2] == {"domain": "ads.tracker.net", "comment": "doch erlaubt", "action": "allow"}

    svc.delete_domain(uid)
    assert box.requests[-2][:2] == ("DELETE", API + "/domains/" + uid)
    assert all(e["UID"] != uid for e in box.cfg["domains"])


def test_add_duplicate_and_unknown_uid(box, store):
    svc = make(box, store)
    with pytest.raises(FilterError, match="Whitelist"):
        svc.add_domain("example.org", "deny")
    with pytest.raises(FilterError) as exc:
        svc.delete_domain("gibtsnicht")
    assert exc.value.status == 404
    with pytest.raises(FilterError):
        svc.add_domain("x.de", "block")


def test_uid_is_url_encoded(box, store):
    box.cfg["domains"].append({"UID": "a b/c", "domain": "z.de", "action": "deny", "enabled": True, "comment": ""})
    svc = make(box, store)
    svc.delete_domain("a b/c")
    assert ("DELETE", API + "/domains/a%20b%2Fc") in [(m, p) for m, p, *_ in box.requests]
    assert all(e["UID"] != "a b/c" for e in box.cfg["domains"])


def test_toggle_keeps_automatic_update(box, store):
    box.cfg["automaticUpdate"] = {"enabled": False, "interval": "weekly"}
    svc = make(box, store)
    svc.set_enabled(False)
    put = [b for m, p, b, _ in box.requests if m == "PUT"][-1]
    assert put == {"enabled": False, "automaticUpdate": {"interval": "weekly", "enabled": False}}
    assert box.cfg["enabled"] is False
    svc.set_enabled(True)
    assert box.cfg["enabled"] is True and box.cfg["automaticUpdate"] == {"enabled": False, "interval": "weekly"}


def test_toggle_refuses_incomplete_automatic_update(box, store):
    box.cfg["automaticUpdate"] = {"enabled": True}
    with pytest.raises(FilterError, match="automaticUpdate"):
        make(box, store).set_enabled(False)
    assert box.cfg["enabled"] is True


def test_verification_failure_is_reported(box, store):
    box.ignore_writes = True
    svc = make(box, store)
    with pytest.raises(FilterError) as exc:
        svc.add_domain("neu.de", "deny")
    assert exc.value.status == 502 and "nicht bestätigt" in str(exc.value)


def test_expired_session_relogin(box, store):
    svc = make(box, store)
    svc.state()
    box.expire_next = True
    svc.add_domain("relogin.de", "deny")
    assert box.logins == 2
    assert any(e["domain"] == "relogin.de" for e in box.cfg["domains"])


def test_expired_session_http400_code3001_relogin(box, store):
    """Regression: echte FRITZ!Box meldet abgelaufene SID als HTTP 400 'permission denied' (code 3001)."""
    box.expired_status = 400
    svc = make(box, store)
    svc.state()
    box.sids.clear()                       # SID über Nacht verfallen
    st = svc.state(max_age=0)
    assert st["available"] and st["error"] is None and box.logins == 2


def test_permission_denied_after_relogin_is_clear_error(box, store):
    box.expired_status = 400
    svc = make(box, store)
    svc.state()
    box.revoked = True                     # Login klappt, Session hat aber keine Rechte
    st = svc.state(max_age=0)
    assert box.logins == 2                 # genau ein Neuanmelde-Versuch, keine Schleife
    assert not st["available"] and st.get("stale")
    assert "auch nach erneuter Anmeldung" in st["error"] and "permission denied" in st["error"]
    assert "[{" not in st["error"]


def test_http_error_and_unreachable(box, store):
    box.fail_put_enabled = 1
    svc = make(box, store)
    with pytest.raises(ApiError) as exc:
        svc.set_enabled(False)
    assert exc.value.status == 500 and exc.value.transient
    dead = DnsFilterService(RestSession(FritzBox("127.0.0.1:9", "u", "p"), timeout=1), store)
    st = dead.state()
    assert not st["available"] and "nicht erreichbar" in st["error"]


def test_read_only_mode(box, store):
    svc = make(box, store, writable=False)
    with pytest.raises(FilterError) as exc:
        svc.add_domain("x.de", "deny")
    assert exc.value.status == 403 and not box.requests


# ------------------------------------------------------------------ pause / resume
def test_pause_persists_and_resumes_after_restart(box, store):
    clock = Clock()
    svc = make(box, store, clock)
    svc.pause_for(15)
    assert box.cfg["enabled"] is False
    saved = json.loads(store.get_meta(PAUSE_KEY))
    assert saved["resume_at"] == clock.t + 900
    assert svc.pause_info()["remaining"] == 900

    clock.t += 300
    assert svc.tick() == 30.0           # noch nicht fällig
    assert box.cfg["enabled"] is False

    # "Neustart": neue Instanz, Zeit überfällig
    clock.t += 3600
    svc2 = make(box, store, clock)
    assert svc2.pause is not None
    svc2.tick()
    assert box.cfg["enabled"] is True
    assert store.get_meta(PAUSE_KEY) is None and svc2.pause is None


def test_resume_retries_on_transient_error(box, store, caplog):
    clock = Clock()
    svc = make(box, store, clock)
    svc.pause_for(5)
    clock.t += 301
    box.fail_put_enabled = 2
    with caplog.at_level(logging.ERROR):
        assert svc.tick() == 30.0
    p = svc.pause_info()
    assert p["attempts"] == 1 and "HTTP 500" in p["last_error"]
    assert "Reaktivierung fehlgeschlagen" in caplog.text
    assert json.loads(store.get_meta(PAUSE_KEY))["attempts"] == 1   # Fehlerzustand persistent
    assert svc._due_wait() == pytest.approx(30.0)                    # wartet auf next_retry
    clock.t += 30
    assert svc._due_wait() == 60.0                                   # 2. Fehlschlag, Backoff
    clock.t += 60
    svc._due_wait()
    assert box.cfg["enabled"] is True and svc.pause is None


def test_manual_resume_and_switch_clear_pause(box, store):
    svc = make(box, store)
    svc.pause_for(30)
    svc.resume_now()
    assert box.cfg["enabled"] is True and svc.pause is None
    svc.pause_for(30)
    svc.set_enabled(False)  # bewusst dauerhaft aus -> keine automatische Reaktivierung
    assert svc.pause is None and box.cfg["enabled"] is False


def test_pause_rules(box, store):
    svc = make(box, store)
    with pytest.raises(FilterError):
        svc.pause_for(0)
    with pytest.raises(FilterError):
        svc.pause_for("abc")
    box.cfg["enabled"] = False
    with pytest.raises(FilterError, match="bereits ausgeschaltet"):
        svc.pause_for(5)
    assert svc.pause is None


def test_pause_extend(box, store):
    clock = Clock()
    svc = make(box, store, clock)
    svc.pause_for(5)
    svc.pause_for(30)
    assert svc.pause_info()["remaining"] == 1800 and box.cfg["enabled"] is False
    box.cfg["enabled"] = True            # extern in der FRITZ!Box wieder eingeschaltet
    svc.pause_for(10)
    assert box.cfg["enabled"] is False and svc.pause_info()["remaining"] == 600


def test_failed_disable_keeps_no_dangling_pause(box, store):
    box.fail_put_enabled = 1
    svc = make(box, store)
    with pytest.raises(ApiError):
        svc.pause_for(5)
    assert box.cfg["enabled"] is True and svc.pause is None and store.get_meta(PAUSE_KEY) is None


def test_scheduler_thread_resumes(box, store):
    import time as _t
    svc = make(box, store, clock=_t.time)
    svc.pause_for(1)
    svc.pause = {**svc.pause, "resume_at": _t.time() - 1}  # sofort fällig
    svc.start()
    try:
        for _ in range(100):
            if box.cfg["enabled"]:
                break
            _t.sleep(0.05)
        assert box.cfg["enabled"] is True
    finally:
        svc.stop()


# ------------------------------------------------------------------ HTTP-API
def test_http_endpoints(box, store, caplog):
    caplog.set_level(logging.DEBUG)
    svc = make(box, store)
    app = create_app(store, LiveHub(), dnsfilter=svc, allow_all=False)
    with TestClient(app) as c:
        st = c.get("/api/dnsfilter").json()
        assert st["available"] and st["writable"]
        assert c.post("/api/dnsfilter/domains", json={"domain": "x.de", "action": "deny"}).status_code == 403
        r = c.post("/api/dnsfilter/domains", json={"domain": "x.de", "action": "deny", "comment": "c"}, headers=H)
        assert r.status_code == 200
        uid = next(d["uid"] for d in r.json()["config"]["domains"] if d["domain"] == "x.de")
        assert c.post("/api/dnsfilter/domains", json={"domain": "x.de", "action": "deny"}, headers=H).status_code == 409
        r = c.put(f"/api/dnsfilter/domains/{uid}", json={"action": "allow"}, headers=H)
        assert r.status_code == 200
        assert c.delete(f"/api/dnsfilter/domains/{uid}", headers=H).status_code == 200
        assert c.put("/api/dnsfilter/enabled", json={"enabled": "nein"}, headers=H).status_code == 422
        r = c.post("/api/dnsfilter/pause", json={"minutes": 15}, headers=H).json()
        assert r["pause"]["remaining"] > 0 and r["config"]["enabled"] is False
        r = c.post("/api/dnsfilter/resume", headers=H).json()
        assert r["pause"] is None and r["config"]["enabled"] is True
        body = json.dumps(c.get("/api/dnsfilter?fresh=1").json())
    sids = {f"{i:016x}" for i in range(1, box.logins + 1)}
    for secret in sids | {PASSWORD}:
        assert secret not in body and secret not in caplog.text


def test_http_without_service(store):
    app = create_app(store, LiveHub(), allow_all=False)
    with TestClient(app) as c:
        assert c.get("/api/dnsfilter").status_code == 503
