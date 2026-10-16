import time

import pytest
from starlette.testclient import TestClient

from fritzhole.api import create_app
from fritzhole.db import Store
from fritzhole.pipeline import LiveHub, Writer
from fritzhole.processor import DnsEvent

PASSWORD = "geheim-Passw0rt"
H = {"X-FritzHole-Confirm": "1"}


def ev(ts, qname, status, ip="192.168.178.20", mac="aa:bb:cc:00:00:01"):
    return DnsEvent(ts, ip, mac, "192.168.178.1", "udp", qname, "A", status, 0, "0.0.0.0", 2.0)


@pytest.fixture
def ctx(tmp_path):
    store = Store(str(tmp_path / "api.db"))
    now = time.time()
    store.insert_events([ev(now, "ads.example", "blocked"), ev(now, "ok.example", "allowed"),
                         ev(now, "ok.example", "allowed", ip="192.168.178.30", mac=None)])
    hub = LiveHub()

    def status():
        return {"capture": {"state": "running"}, "config": {"fritzbox_host": "x", "password_set": True}}

    app = create_app(store, hub, status, allow_all=False)
    with TestClient(app) as c:
        yield c, store, hub


def test_index_relative_paths(ctx):
    c, *_ = ctx
    r = c.get("/")
    assert r.status_code == 200
    html = r.text
    # Ingress: keine absoluten Root-Pfade
    assert 'src="/' not in html and 'href="/' not in html
    assert c.get("/static/app.js").status_code == 200


def test_summary_and_tops(ctx):
    c, *_ = ctx
    s = c.get("/api/summary", params={"from_ts": time.time() - 60}).json()
    assert s["total"] == 3 and s["blocked"] == 1 and s["devices"] == 2
    top = c.get("/api/top/domains").json()
    assert top[0]["domain"] == "ok.example" and top[0]["count"] == 2
    blocked = c.get("/api/top/domains", params={"status": "blocked"}).json()
    assert [d["domain"] for d in blocked] == ["ads.example"]
    devs = c.get("/api/top/devices").json()
    assert {round(d["block_rate"]) for d in devs} == {50, 0}


def test_events_filter_and_validation(ctx):
    c, *_ = ctx
    assert len(c.get("/api/events", params={"q": "ads"}).json()) == 1
    assert c.get("/api/events", params={"limit": 5000}).status_code == 422
    assert c.get("/api/timeline").json()["bucket"] >= 60


def test_device_rename_and_merge(ctx):
    c, store, _ = ctx
    devs = c.get("/api/devices").json()
    assert len(devs) == 2
    a, b = devs
    assert c.put(f"/api/devices/{a['id']}", json={"name": "Wohnzimmer-TV"}, headers=H).status_code == 200
    assert c.put(f"/api/devices/{a['id']}", json={"name": "x"}).status_code == 403  # ohne Bestätigungs-Header
    assert c.put("/api/devices/9999", json={"name": "x"}, headers=H).status_code == 404
    assert c.post(f"/api/devices/{b['id']}/merge", json={"target_id": a["id"]}, headers=H).status_code == 200
    assert c.post(f"/api/devices/{a['id']}/merge", json={"target_id": a["id"]}, headers=H).status_code == 400
    names = [d["device_name"] for d in c.get("/api/events").json()]
    assert set(names) == {"Wohnzimmer-TV"}


def test_status_never_contains_password(ctx):
    c, *_ = ctx
    body = c.get("/api/status").text
    assert PASSWORD not in body and "password\"" not in body


def test_ingress_only_middleware(tmp_path):
    store = Store(str(tmp_path / "x.db"))
    app = create_app(store, LiveHub(), allow_all=False)
    with TestClient(app, client=("10.0.0.9", 1234)) as c:
        assert c.get("/api/health").status_code == 403
    with TestClient(app, client=("172.30.32.2", 1234)) as c:
        assert c.get("/api/health").status_code == 200


def test_live_publish_via_writer(ctx):
    """Writer -> Hub -> asyncio-Queue (SSE-Quelle)."""
    import asyncio

    _, store, hub = ctx

    async def run():
        q = hub.subscribe()
        w = Writer(store, hub, 14, 100_000)
        w.start()
        w.submit([ev(time.time(), "live.example", "blocked")])
        row = await asyncio.wait_for(q.get(), 5)
        w.stop()
        hub.unsubscribe(q)
        return row

    row = asyncio.run(run())
    assert row["qname"] == "live.example" and row["id"] > 0 and row["device_name"] is None


def test_assets_cache_busting(ctx):
    from fritzhole import __version__
    c, *_ = ctx
    html = c.get("/").text
    assert f'static/app.js?v={__version__}"' in html and f'static/style.css?v={__version__}"' in html
    r = c.get(f"/static/app.js?v={__version__}")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-cache"
