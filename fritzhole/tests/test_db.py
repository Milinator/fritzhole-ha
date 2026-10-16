import time

import pytest

from fritzhole.db import Store
from fritzhole.fritzbox import HostEntry
from fritzhole.processor import DnsEvent

MAC = "aa:bb:cc:00:00:01"


def ev(ts, ip="192.168.178.20", mac=MAC, qname="a.example", status="allowed", qtype="A"):
    return DnsEvent(ts, ip, mac, "192.168.178.1", "udp", qname, qtype, status,
                    0 if status != "no_answer" else None, "", 1.0)


@pytest.fixture
def store(tmp_path):
    s = Store(str(tmp_path / "t.db"))
    yield s
    s.close()


def test_insert_and_summary(store):
    now = time.time()
    store.insert_events([ev(now, status="blocked", qname="ads.example"), ev(now, qname="ok.example"),
                         ev(now, status="nxdomain"), ev(now, status="no_answer")])
    s = store.summary({"from_ts": now - 60})
    assert s["total"] == 4 and s["blocked"] == 1 and s["allowed"] == 1 and s["errors"] == 1
    assert s["block_rate"] == pytest.approx(100 / 3)
    assert s["devices"] == 1


def test_ipv4_and_ipv6_same_mac_one_device(store):
    now = time.time()
    store.insert_events([ev(now, ip="192.168.178.20"), ev(now, ip="fd00::20"), ev(now, ip="2001:db8::20")])
    devs = store.devices()
    assert len(devs) == 1
    assert {i["ip"] for i in devs[0]["ips"]} == {"192.168.178.20", "fd00::20", "2001:db8::20"}


def test_no_mac_means_no_merge(store):
    now = time.time()
    store.insert_events([ev(now, ip="192.168.178.20", mac=None), ev(now, ip="fd00::20", mac=None)])
    assert len(store.devices()) == 2


def test_shared_mac_splits_by_ip(store):
    now = time.time()
    store.insert_events([ev(now + i, ip=f"192.168.178.{i + 10}", mac="02:00:00:00:00:99") for i in range(6)])
    devs = store.devices()
    # erste Adressen hingen noch an der MAC; ab Erkennung getrennt nach IP
    assert len(devs) >= 3
    assert any(d["shared"] for d in devs)


def test_manual_merge_rename_unmerge(store):
    now = time.time()
    store.insert_events([ev(now, ip="10.0.0.5", mac=None), ev(now, ip="fd00::5", mac=None)])
    a, b = sorted(store.devices(), key=lambda d: d["id"])
    assert store.merge_devices(b["id"], a["id"])
    store.insert_events([ev(now + 1, ip="fd00::5", mac=None)])  # neues Ereignis landet beim Ziel
    tops = store.top_devices({})
    assert len(tops) == 1 and tops[0]["count"] == 3
    assert store.rename_device(a["id"], "Laptop")
    assert store.events({}, limit=1)[0]["device_name"] == "Laptop"
    assert not store.merge_devices(a["id"], a["id"])
    assert store.unmerge_device(b["id"])


def test_host_list_names(store):
    now = time.time()
    store.insert_events([ev(now), ev(now, ip="192.168.178.50", mac=None)])
    store.apply_host_list([HostEntry("192.168.178.20", MAC, "iPhone", True),
                           HostEntry("192.168.178.50", "", "Drucker", True)])
    names = {d["display_name"] for d in store.devices()}
    assert names == {"iPhone", "Drucker"}


def test_filters_and_search(store):
    now = time.time()
    store.insert_events([ev(now, qname="ads.doubleclick.net", status="blocked"), ev(now, qname="example.org"),
                         ev(now - 7200, qname="old.example")])
    assert [e["qname"] for e in store.events({"q": "double"})] == ["ads.doubleclick.net"]
    assert len(store.events({"status": "blocked,allowed", "from_ts": now - 60})) == 2
    assert store.events({"q": "%"}) == []  # LIKE-Wildcards escaped
    assert store.events({"status": "x' OR 1=1 --"}) != []  # ungültiger Status wird ignoriert, keine Injection
    top = store.top_domains({"status": "blocked"})
    assert top[0]["domain"] == "ads.doubleclick.net" and top[0]["blocked"] == 1


def test_paging(store):
    now = time.time()
    store.insert_events([ev(now + i, qname=f"d{i}.example") for i in range(10)])
    page1 = store.events({}, limit=4)
    page2 = store.events({}, limit=4, before_id=page1[-1]["id"])
    assert [e["id"] for e in page1 + page2] == sorted({e["id"] for e in page1 + page2}, reverse=True)
    newer = store.events({}, limit=100, after_id=page1[1]["id"])
    assert [e["id"] for e in newer] == [page1[0]["id"]]


def test_timeline_buckets(store):
    now = time.time()
    store.insert_events([ev(now - 30, status="blocked"), ev(now - 20), ev(now - 10, status="error")])
    tl = store.timeline({"from_ts": now - 3600, "to_ts": now})
    assert tl["bucket"] == 60
    assert sum(tl["series"]["blocked"]) == 1 and sum(tl["series"]["allowed"]) == 1 and sum(tl["series"]["errors"]) == 1
    assert len(tl["points"]) == len(tl["series"]["allowed"])


def test_retention_and_cap(store):
    now = time.time()
    store.insert_events([ev(now - 20 * 86400), ev(now - 19 * 86400)] + [ev(now - i) for i in range(30)])
    removed = store.cleanup(retention_days=14, max_events=10_000)
    assert removed == 2
    removed = store.cleanup(retention_days=14, max_events=10)
    assert removed == 20 and store.db_info()["events"] == 10
