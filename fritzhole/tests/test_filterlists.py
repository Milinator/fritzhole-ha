import pytest
from starlette.testclient import TestClient

from fakeapi import API, FakeFritzApi
from fritzhole.api import create_app
from fritzhole.db import Store
from fritzhole.dnsfilter import FilterError
from fritzhole.filterlists import list_health, to_epoch, update_progress
from fritzhole.pipeline import LiveHub
from test_dnsfilter import Clock, H, make


@pytest.fixture
def box():
    b = FakeFritzApi()
    yield b
    b.close()


@pytest.fixture
def store(tmp_path):
    s = Store(str(tmp_path / "fl.db"))
    yield s
    s.close()


def writes(box):
    return [(m, p, b) for m, p, b, _ in box.requests if m != "GET"]


# ------------------------------------------------------------------ helpers
@pytest.mark.parametrize("raw,exp", [(1760000000, 1760000000.0), (1760000000123, 1760000000.123),
                                     ("1760000000", 1760000000.0), ("2026-10-16T10:00:00Z", 1792144800.0),
                                     (0, None), (None, None), ("kaputt", None), (True, None)])
def test_to_epoch(raw, exp):
    assert to_epoch(raw) == (pytest.approx(exp) if exp else None)


def test_health_error_3643():
    fl = {"enabled": True, "status": {"isReady": False, "entryCount": 0},
          "latestUpdate": {"status": "error", "timestamp": 1, "cause": "manual",
                           "error": {"code": 3643, "message": "download failed"}}}
    h = list_health(fl)
    assert h["state"] == "error" and h["error_code"] == 3643 and h["entry_count"] == 0 and h["cause"] == "manual"


@pytest.mark.parametrize("fl,state", [
    ({"enabled": False, "status": {"isReady": True}}, "disabled"),
    ({"enabled": True, "status": {"isReady": True}, "latestUpdate": {"status": "success"}}, "ready"),
    ({"enabled": True, "status": {"isReady": False}}, "not_ready"),
    ({"enabled": True, "latestUpdate": {"status": "running"}}, "updating"),
    ({"enabled": True}, "unknown"),
])
def test_health_states(fl, state):
    assert list_health(fl)["state"] == state


def test_state_contains_detail(box, store):
    st = make(box, store).state()
    d = {x["uid"]: x for x in st["filterlists_detail"]}
    assert d["filterlist1"]["health"]["state"] == "ready" and d["filterlist1"]["url"].startswith("https://")
    assert d["filterlist2"]["health"]["error_code"] == 3643
    assert st["manual_update"] is None and st["manual_last"] == 1760000000


# ------------------------------------------------------------------ CRUD
def test_add_list_verified(box, store):
    svc = make(box, store)
    svc.add_list("OISD", "https://big.oisd.nl/", enabled=False)
    assert writes(box)[-1] == ("POST", API + "/filterlists",
                               {"enabled": False, "name": "OISD", "url": "https://big.oisd.nl/"})
    assert box.requests[-1][0] == "GET"


@pytest.mark.parametrize("name,url,msg", [
    ("hagezi multi pro", "https://neu.example/x", "Namen"),        # Name (case-insensitiv)
    ("Neu", "https://EXAMPLE.net/hagezi.txt/", "URL"),            # gleiche URL
])
def test_add_duplicate_rejected(box, store, name, url, msg):
    with pytest.raises(FilterError, match=msg) as exc:
        make(box, store).add_list(name, url)
    assert exc.value.status == 409 and not writes(box)


@pytest.mark.parametrize("url", ["http://x.de/l.txt", "https://user:pw@x.de/l", "ftp://x.de", "https://", "https://x.de/a b"])
def test_add_invalid_url(box, store, url):
    with pytest.raises(FilterError, match="HTTPS"):
        make(box, store).add_list("X", url)


def test_edit_keeps_unchanged_properties(box, store):
    svc = make(box, store)
    svc.edit_list("filterlist1", enabled=False)
    assert writes(box)[-1] == ("PUT", API + "/filterlists/filterlist1",
                               {"enabled": False, "name": "HaGeZi Multi PRO", "url": "https://example.net/hagezi.txt"})
    svc.edit_list("filterlist1", name="HaGeZi Pro")
    assert writes(box)[-1][2] == {"enabled": False, "name": "HaGeZi Pro", "url": "https://example.net/hagezi.txt"}


def test_edit_conflict_and_unknown(box, store):
    svc = make(box, store)
    with pytest.raises(FilterError) as exc:
        svc.edit_list("filterlist1", name="Testliste")
    assert exc.value.status == 409
    with pytest.raises(FilterError) as exc:
        svc.edit_list("gibtsnicht", enabled=True)
    assert exc.value.status == 404
    assert not writes(box)


def test_delete_list(box, store):
    make(box, store).delete_list("filterlist2")
    assert writes(box)[-1][:2] == ("DELETE", API + "/filterlists/filterlist2")
    assert [e["UID"] for e in box.cfg["filterlists"]] == ["filterlist1"]


def test_write_not_confirmed(box, store):
    box.ignore_writes = True
    with pytest.raises(FilterError, match="nicht bestätigt"):
        make(box, store).edit_list("filterlist1", enabled=False)


# ------------------------------------------------------------------ auto update
@pytest.mark.parametrize("preset,interval,enabled", [
    ("8h", 28800, True), ("daily", 86400, True), ("weekly", 604800, True),
    ("monthly", 2592000, True), ("never", 0, False)])
def test_auto_update_presets_match_fritzbox(box, store, preset, interval, enabled):
    svc = make(box, store)
    cfg = svc.set_auto_update(preset)
    assert writes(box)[-1][2] == {"enabled": True, "automaticUpdate": {"interval": interval, "enabled": enabled}}
    assert box.cfg["enabled"] is True                     # Hauptschalter unverändert
    assert svc.state(max_age=0)["auto_preset"] == preset
    assert cfg["automaticUpdate"] == {"interval": interval, "enabled": enabled}


def test_auto_update_from_never_back_to_daily(box, store):
    box.cfg["automaticUpdate"] = {"interval": 0, "enabled": False}  # so liefert die echte Box „Nie“
    svc = make(box, store)
    assert svc.state()["auto_preset"] == "never"
    svc.set_auto_update("daily")
    assert box.cfg["automaticUpdate"] == {"interval": 86400, "enabled": True}


def test_auto_update_during_pause_keeps_filter_off(box, store):
    svc = make(box, store, Clock())
    svc.pause_for(30)
    svc.set_auto_update("weekly")
    assert box.cfg["enabled"] is False and svc.pause is not None
    assert writes(box)[-1][2] == {"enabled": False, "automaticUpdate": {"interval": 604800, "enabled": True}}


@pytest.mark.parametrize("preset", ["", "hourly", "12", None, 86400])
def test_auto_update_rejects_unknown_preset(box, store, preset):
    with pytest.raises(FilterError):
        make(box, store).set_auto_update(preset)
    assert not writes(box)


def test_custom_interval_is_not_a_preset(box, store):
    box.cfg["automaticUpdate"] = {"interval": 43200, "enabled": True}   # z. B. per API gesetzt
    assert make(box, store).state()["auto_preset"] is None


def test_auto_update_refuses_unknown_shape(box, store):
    box.cfg["automaticUpdate"] = {"interval": "daily", "enabled": True}
    with pytest.raises(FilterError, match="unvollständig"):
        make(box, store).set_auto_update("daily")
    assert not writes(box)


# ------------------------------------------------------------------ manual update / progress
def test_manual_update_progress(box, store):
    clock = Clock(1_800_000_000.0)
    svc = make(box, store, clock)
    svc.trigger_update()
    assert writes(box)[-1] == ("PUT", API, {"manualUpdate": {"trigger": True}})
    st = svc.state(max_age=0)
    assert st["manual_update"]["phase"] == "requested"          # keine Erfolgsmeldung ohne Bestätigung

    box.set_update("filterlist1", "running", None)
    assert svc.state(max_age=0)["manual_update"]["phase"] == "running"

    box.set_update("filterlist1", "success", 1_800_000_050)
    assert svc.state(max_age=0)["manual_update"]["phase"] == "running"   # Liste 2 noch offen

    box.set_update("filterlist2", "success", 1_800_000_060)
    p = svc.state(max_age=0)["manual_update"]
    assert p["phase"] == "success" and p["finished"]


def test_manual_update_error_and_timeout(box, store):
    clock = Clock(1_800_000_000.0)
    svc = make(box, store, clock)
    svc.trigger_update()
    box.set_update("filterlist1", "success", 1_800_000_050)
    box.set_update("filterlist2", "error", 1_800_000_051, {"code": 3643, "message": "download failed"})
    p = svc.state(max_age=0)["manual_update"]
    assert p["phase"] == "error"
    assert {x["uid"]: x["state"] for x in p["lists"]} == {"filterlist1": "done", "filterlist2": "error"}

    svc.trigger_update()
    clock.t += 601
    assert svc.state(max_age=0)["manual_update"]["phase"] == "timeout"


def test_progress_ignores_disabled_lists():
    cfg = {"filterlists": [{"UID": "a", "enabled": True, "latestUpdate": {"status": "success", "timestamp": 2}},
                           {"UID": "b", "enabled": False, "latestUpdate": {"status": "error", "timestamp": 1}}]}
    p = update_progress({"requested_at": 0, "baseline": {"a": [1, "success"], "b": [1, "error"]}}, cfg, 10)
    assert p["phase"] == "success"


# ------------------------------------------------------------------ HTTP
def test_http_filterlists(box, store):
    app = create_app(store, LiveHub(), dnsfilter=make(box, store), allow_all=False)
    with TestClient(app) as c:
        assert c.post("/api/dnsfilter/filterlists", json={"name": "A", "url": "https://a.de/l"}).status_code == 403
        r = c.post("/api/dnsfilter/filterlists", json={"name": "A", "url": "https://a.de/l"}, headers=H)
        assert r.status_code == 200
        uid = next(x["uid"] for x in r.json()["filterlists_detail"] if x["name"] == "A")
        assert c.put(f"/api/dnsfilter/filterlists/{uid}", json={"enabled": "nein"}, headers=H).status_code == 422
        assert c.put(f"/api/dnsfilter/filterlists/{uid}", json={"enabled": False}, headers=H).status_code == 200
        assert c.delete(f"/api/dnsfilter/filterlists/{uid}", headers=H).status_code == 200
        r = c.post("/api/dnsfilter/update", headers=H).json()
        assert r["manual_update"]["phase"] == "requested"
        assert c.put("/api/dnsfilter/auto-update", json={"preset": 24}, headers=H).status_code == 422
        assert c.put("/api/dnsfilter/auto-update", json={"preset": "hourly"}, headers=H).status_code == 400
        r = c.put("/api/dnsfilter/auto-update", json={"preset": "never"}, headers=H)
        assert r.status_code == 200 and r.json()["auto_preset"] == "never"
        assert r.json()["config"]["automaticUpdate"] == {"interval": 0, "enabled": False}
