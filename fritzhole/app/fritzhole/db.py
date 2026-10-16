"""SQLite persistence (/data/fritzhole.db): events, devices, aggregations."""
from __future__ import annotations

import ipaddress
import logging
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Iterable

from .processor import DnsEvent

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1
STATUSES = ("allowed", "blocked", "nxdomain", "error", "no_answer")

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS devices(
    id INTEGER PRIMARY KEY,
    ident TEXT NOT NULL UNIQUE,          -- 'mac:<mac>' oder 'ip:<ip>'
    mac TEXT,
    name TEXT,                           -- manuell
    auto_name TEXT,                      -- FRITZ!Box (TR-064)
    merged_into INTEGER REFERENCES devices(id),
    shared INTEGER NOT NULL DEFAULT 0,   -- MAC von mehreren IPv4 genutzt (Router/Repeater)
    first_seen REAL, last_seen REAL
);
CREATE TABLE IF NOT EXISTS device_ips(
    device_id INTEGER NOT NULL, ip TEXT NOT NULL, last_seen REAL,
    PRIMARY KEY(device_id, ip)
);
CREATE INDEX IF NOT EXISTS idx_device_ips_ip ON device_ips(ip);
CREATE TABLE IF NOT EXISTS events(
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    device_id INTEGER,
    client_ip TEXT NOT NULL,
    client_mac TEXT,
    server_ip TEXT,
    transport TEXT,
    qname TEXT NOT NULL,
    qtype TEXT,
    status TEXT NOT NULL,
    rcode INTEGER,
    answers TEXT,
    latency_ms REAL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_status_ts ON events(status, ts);
CREATE INDEX IF NOT EXISTS idx_events_device_ts ON events(device_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_qname_ts ON events(qname, ts);
"""

EVENT_COLUMNS = """e.id, e.ts, e.device_id, e.client_ip, e.client_mac, e.server_ip, e.transport,
    e.qname, e.qtype, e.status, e.rcode, e.answers, e.latency_ms,
    COALESCE(d.name, d.auto_name) AS device_name"""

SHARED_MAC_IPV4 = 3       # > n IPv4 je MAC im Fenster -> MAC gilt als geteilt
SHARED_WINDOW = 1800.0
BUCKETS = (60, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400)


def _is_ipv4(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).version == 4
    except ValueError:
        return False


def _usable_mac(mac: str | None) -> bool:
    if not mac or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return False
    return not (int(mac[:2], 16) & 1)  # Multicast-Bit


class Store:
    def __init__(self, path: str):
        self.path = path
        self._w: sqlite3.Connection | None = None
        self._dev_cache: dict[str, int] = {}
        self._ip_seen: dict[tuple[int, str], float] = {}
        self._mac_v4: dict[str, dict[str, float]] = {}
        self._shared: set[str] = set()
        self._invalidate = threading.Event()
        self._init()

    # ----------------------------------------------------------- connections
    def _connect(self, readonly: bool = False) -> sqlite3.Connection:
        con = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA busy_timeout=10000")
        if readonly:
            con.execute("PRAGMA query_only=ON")
        return con

    @contextmanager
    def read(self):
        con = self._connect(readonly=True)
        try:
            yield con
        finally:
            con.close()

    @contextmanager
    def write(self):
        con = self._connect()
        try:
            with con:
                yield con
        finally:
            con.close()

    def _init(self) -> None:
        con = self._connect()
        try:
            new = con.execute("SELECT count(*) FROM sqlite_master").fetchone()[0] == 0
            if new:
                con.execute("PRAGMA auto_vacuum=INCREMENTAL")
            con.execute("PRAGMA journal_mode=WAL")
            con.executescript(SCHEMA)
            con.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version',?)", (str(SCHEMA_VERSION),))
            con.commit()
            self._shared = {r[0] for r in con.execute("SELECT mac FROM devices WHERE shared=1 AND mac IS NOT NULL")}
        finally:
            con.close()

    def writer_conn(self) -> sqlite3.Connection:
        """Dedicated connection for the single writer thread."""
        if self._w is None:
            self._w = self._connect()
            self._w.execute("PRAGMA synchronous=NORMAL")
        return self._w

    def close(self) -> None:
        if self._w is not None:
            try:
                self._w.execute("PRAGMA optimize")
            except sqlite3.Error:
                pass
            self._w.close()
            self._w = None

    def invalidate_devices(self) -> None:
        self._invalidate.set()

    # ------------------------------------------------------------------ meta
    def get_meta(self, key: str) -> str | None:
        with self.read() as con:
            row = con.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def set_meta(self, key: str, value: str | None) -> None:
        with self.write() as con:
            if value is None:
                con.execute("DELETE FROM meta WHERE key=?", (key,))
            else:
                con.execute("INSERT INTO meta(key, value) VALUES(?,?) "
                            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    # --------------------------------------------------------------- devices
    def _resolve_device(self, con: sqlite3.Connection, ip: str, mac: str | None, ts: float) -> int:
        if self._invalidate.is_set():
            self._invalidate.clear()
            self._dev_cache.clear()
            self._shared = {r[0] for r in con.execute("SELECT mac FROM devices WHERE shared=1 AND mac IS NOT NULL")}
        mac = mac.lower() if mac else None
        if _usable_mac(mac) and _is_ipv4(ip):
            seen = self._mac_v4.setdefault(mac, {})
            seen[ip] = ts
            for k in [k for k, t in seen.items() if ts - t > SHARED_WINDOW]:
                del seen[k]
            if len(seen) > SHARED_MAC_IPV4 and mac not in self._shared:
                self._shared.add(mac)
                con.execute("UPDATE devices SET shared=1 WHERE mac=?", (mac,))
                log.warning("MAC %s wird von %d IPv4-Adressen genutzt (Router/Repeater?) – "
                            "Geräte werden für diese MAC künftig nach IP getrennt", mac, len(seen))
        ident = f"mac:{mac}" if _usable_mac(mac) and mac not in self._shared else f"ip:{ip}"
        dev_id = self._dev_cache.get(ident)
        if dev_id is None:
            row = con.execute("SELECT id, merged_into FROM devices WHERE ident=?", (ident,)).fetchone()
            if row is None:
                cur = con.execute(
                    "INSERT INTO devices(ident, mac, first_seen, last_seen) VALUES(?,?,?,?)",
                    (ident, mac if ident.startswith("mac:") else None, ts, ts))
                dev_id = cur.lastrowid
            else:
                dev_id = row["id"]
                for _ in range(10):  # Zusammenführungen folgen
                    if row["merged_into"] is None:
                        break
                    dev_id = row["merged_into"]
                    row = con.execute("SELECT id, merged_into FROM devices WHERE id=?", (dev_id,)).fetchone()
                    if row is None:
                        break
            self._dev_cache[ident] = dev_id
        key = (dev_id, ip)
        if ts - self._ip_seen.get(key, 0) > 60:
            self._ip_seen[key] = ts
            con.execute("INSERT INTO device_ips(device_id, ip, last_seen) VALUES(?,?,?) "
                        "ON CONFLICT(device_id, ip) DO UPDATE SET last_seen=excluded.last_seen", (dev_id, ip, ts))
            con.execute("UPDATE devices SET last_seen=MAX(COALESCE(last_seen,0),?) WHERE id=?", (ts, dev_id))
            if len(self._ip_seen) > 20000:
                self._ip_seen.clear()
        return dev_id

    # ---------------------------------------------------------------- writes
    def insert_events(self, events: Iterable[DnsEvent]) -> list[int]:
        con = self.writer_conn()
        ids = []
        with con:
            for ev in events:
                dev = self._resolve_device(con, ev.client_ip, ev.client_mac, ev.ts)
                cur = con.execute(
                    "INSERT INTO events(ts, device_id, client_ip, client_mac, server_ip, transport, qname, qtype,"
                    " status, rcode, answers, latency_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (ev.ts, dev, ev.client_ip, ev.client_mac, ev.server_ip, ev.transport, ev.qname, ev.qtype,
                     ev.status, ev.rcode, ev.answers, ev.latency_ms))
                ids.append(cur.lastrowid)
        return ids

    def apply_host_list(self, hosts) -> int:
        """Update auto_name from FRITZ!Box host list. Returns updated rows."""
        con = self.writer_conn()
        n = 0
        with con:
            for h in hosts:
                if not h.name:
                    continue
                if h.mac:
                    n += con.execute("UPDATE devices SET auto_name=? WHERE mac=? AND ident LIKE 'mac:%' "
                                     "AND COALESCE(auto_name,'')<>?", (h.name, h.mac, h.name)).rowcount
                if h.ip:
                    # IP-basierte Geräte nur, wenn die IP aktuell genau diesem Host gehört
                    n += con.execute("UPDATE devices SET auto_name=? WHERE ident=? AND COALESCE(auto_name,'')<>?",
                                     (h.name, f"ip:{h.ip}", h.name)).rowcount
        return n

    def cleanup(self, retention_days: int, max_events: int) -> int:
        con = self.writer_conn()
        cutoff = time.time() - retention_days * 86400
        removed = 0
        while True:
            with con:
                n = con.execute("DELETE FROM events WHERE id IN (SELECT id FROM events WHERE ts < ? LIMIT 20000)",
                                (cutoff,)).rowcount
            removed += n
            if n < 20000:
                break
        row = con.execute("SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET ?", (max_events,)).fetchone()
        if row:
            with con:
                removed += con.execute("DELETE FROM events WHERE id <= ?", (row[0],)).rowcount
        with con:
            con.execute("DELETE FROM device_ips WHERE last_seen < ?", (cutoff,))
            con.execute("DELETE FROM devices WHERE name IS NULL AND last_seen < ? AND merged_into IS NULL "
                        "AND id NOT IN (SELECT DISTINCT device_id FROM events WHERE device_id IS NOT NULL) "
                        "AND id NOT IN (SELECT merged_into FROM devices WHERE merged_into IS NOT NULL)", (cutoff,))
        if removed:
            con.execute("PRAGMA incremental_vacuum")
            self._dev_cache.clear()
        return removed

    def rename_device(self, device_id: int, name: str | None) -> bool:
        with self.write() as con:
            ok = con.execute("UPDATE devices SET name=? WHERE id=?", (name or None, device_id)).rowcount == 1
        self.invalidate_devices()
        return ok

    def merge_devices(self, source_id: int, target_id: int) -> bool:
        """Manually assign all IPs/events of source to target."""
        if source_id == target_id:
            return False
        with self.write() as con:
            ids = {r[0] for r in con.execute("SELECT id FROM devices WHERE id IN (?,?) AND merged_into IS NULL",
                                             (source_id, target_id))}
            if ids != {source_id, target_id}:
                return False
            con.execute("UPDATE events SET device_id=? WHERE device_id=?", (target_id, source_id))
            con.execute("INSERT OR IGNORE INTO device_ips(device_id, ip, last_seen) "
                        "SELECT ?, ip, last_seen FROM device_ips WHERE device_id=?", (target_id, source_id))
            con.execute("DELETE FROM device_ips WHERE device_id=?", (source_id,))
            con.execute("UPDATE devices SET merged_into=? WHERE id=? OR merged_into=?",
                        (target_id, source_id, source_id))
        self.invalidate_devices()
        return True

    def unmerge_device(self, device_id: int) -> bool:
        """Zusammenführung aufheben: künftige Ereignisse wieder getrennt (Historie bleibt beim Ziel)."""
        with self.write() as con:
            ok = con.execute("UPDATE devices SET merged_into=NULL WHERE id=? AND merged_into IS NOT NULL",
                             (device_id,)).rowcount == 1
        self.invalidate_devices()
        return ok

    # ----------------------------------------------------------------- reads
    @staticmethod
    def build_filter(f: dict) -> tuple[str, list]:
        cond, args = [], []
        if f.get("from_ts") is not None:
            cond.append("e.ts >= ?"); args.append(float(f["from_ts"]))
        if f.get("to_ts") is not None:
            cond.append("e.ts < ?"); args.append(float(f["to_ts"]))
        statuses = [s for s in (f.get("status") or "").split(",") if s in STATUSES]
        if statuses:
            cond.append("e.status IN (%s)" % ",".join("?" * len(statuses))); args += statuses
        if f.get("device_id") is not None:
            cond.append("e.device_id = ?"); args.append(int(f["device_id"]))
        if f.get("client_ip"):
            cond.append("e.client_ip = ?"); args.append(str(f["client_ip"]))
        if f.get("domain"):
            cond.append("e.qname = ?"); args.append(str(f["domain"]).lower().rstrip("."))
        if f.get("q"):
            q = str(f["q"]).lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            cond.append("(e.qname LIKE ? ESCAPE '\\' OR e.client_ip LIKE ? ESCAPE '\\')")
            args += [f"%{q}%", f"%{q}%"]
        return (" WHERE " + " AND ".join(cond)) if cond else "", args

    def summary(self, f: dict) -> dict:
        where, args = self.build_filter(f)
        with self.read() as con:
            rows = con.execute(f"SELECT e.status, COUNT(*) c FROM events e{where} GROUP BY e.status", args).fetchall()
            clients = con.execute(f"SELECT COUNT(DISTINCT e.device_id) FROM events e{where}", args).fetchone()[0]
            domains = con.execute(f"SELECT COUNT(DISTINCT e.qname) FROM events e{where}", args).fetchone()[0]
        by = {s: 0 for s in STATUSES}
        for r in rows:
            by[r["status"]] = r["c"]
        total = sum(by.values())
        answered = total - by["no_answer"]
        return {
            "total": total, "blocked": by["blocked"], "allowed": by["allowed"],
            "errors": by["nxdomain"] + by["error"], "no_answer": by["no_answer"], "by_status": by,
            "block_rate": (by["blocked"] / answered * 100.0) if answered else 0.0,
            "devices": clients, "domains": domains,
        }

    @staticmethod
    def pick_bucket(span: float) -> int:
        for b in BUCKETS:
            if span / b <= 120:
                return b
        return BUCKETS[-1]

    def timeline(self, f: dict, bucket: int | None = None) -> dict:
        now = time.time()
        frm = float(f.get("from_ts") or now - 86400)
        to = float(f.get("to_ts") or now)
        bucket = bucket or self.pick_bucket(max(60.0, to - frm))
        where, args = self.build_filter({**f, "from_ts": frm, "to_ts": to})
        with self.read() as con:
            rows = con.execute(
                f"SELECT CAST(e.ts / {bucket} AS INTEGER) * {bucket} AS b, e.status, COUNT(*) c "
                f"FROM events e{where} GROUP BY b, e.status ORDER BY b", args).fetchall()
        start = int(frm // bucket) * bucket
        n = int((to - start) // bucket) + 1
        series = {s: [0] * n for s in ("allowed", "blocked", "errors", "no_answer")}
        for r in rows:
            i = int((r["b"] - start) // bucket)
            if 0 <= i < n:
                key = "errors" if r["status"] in ("nxdomain", "error") else r["status"]
                series[key][i] += r["c"]
        return {"bucket": bucket, "start": start, "points": [start + i * bucket for i in range(n)], "series": series}

    def events(self, f: dict, limit: int = 100, before_id: int | None = None, after_id: int | None = None) -> list[dict]:
        where, args = self.build_filter(f)
        extra = []
        if before_id is not None:
            extra.append("e.id < ?"); args.append(int(before_id))
        if after_id is not None:
            extra.append("e.id > ?"); args.append(int(after_id))
        if extra:
            where = (where + " AND " if where else " WHERE ") + " AND ".join(extra)
        order = "ASC" if after_id is not None and before_id is None else "DESC"
        with self.read() as con:
            rows = con.execute(
                f"SELECT {EVENT_COLUMNS} FROM events e LEFT JOIN devices d ON d.id = e.device_id"
                f"{where} ORDER BY e.id {order} LIMIT ?", args + [max(1, min(int(limit), 1000))]).fetchall()
        return [dict(r) for r in rows]

    def events_by_id(self, ids: list[int]) -> list[dict]:
        if not ids:
            return []
        with self.read() as con:
            rows = con.execute(
                f"SELECT {EVENT_COLUMNS} FROM events e LEFT JOIN devices d ON d.id = e.device_id "
                f"WHERE e.id IN ({','.join('?' * len(ids))}) ORDER BY e.id", ids).fetchall()
        return [dict(r) for r in rows]

    def top_domains(self, f: dict, limit: int = 20) -> list[dict]:
        where, args = self.build_filter(f)
        with self.read() as con:
            rows = con.execute(
                f"SELECT e.qname AS domain, COUNT(*) AS count, SUM(e.status='blocked') AS blocked, "
                f"COUNT(DISTINCT e.device_id) AS devices, MAX(e.ts) AS last_seen "
                f"FROM events e{where} GROUP BY e.qname ORDER BY count DESC LIMIT ?",
                args + [max(1, min(int(limit), 200))]).fetchall()
        return [dict(r) for r in rows]

    def top_devices(self, f: dict, limit: int = 20) -> list[dict]:
        where, args = self.build_filter(f)
        with self.read() as con:
            rows = con.execute(
                f"SELECT e.device_id, COALESCE(d.name, d.auto_name) AS device_name, d.mac, "
                f"COUNT(*) AS count, SUM(e.status='blocked') AS blocked, "
                f"SUM(e.status<>'no_answer') AS answered, GROUP_CONCAT(DISTINCT e.client_ip) AS ips "
                f"FROM events e LEFT JOIN devices d ON d.id = e.device_id{where} "
                f"GROUP BY e.device_id ORDER BY count DESC LIMIT ?",
                args + [max(1, min(int(limit), 200))]).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["block_rate"] = (d["blocked"] / d["answered"] * 100.0) if d["answered"] else 0.0
            d["ips"] = sorted(set((d["ips"] or "").split(",")) - {""})[:10]
            out.append(d)
        return out

    def devices(self) -> list[dict]:
        with self.read() as con:
            devs = [dict(r) for r in con.execute(
                "SELECT id, ident, mac, name, auto_name, merged_into, shared, first_seen, last_seen "
                "FROM devices ORDER BY last_seen DESC")]
            ips: dict[int, list] = {}
            for r in con.execute("SELECT device_id, ip, last_seen FROM device_ips ORDER BY last_seen DESC"):
                ips.setdefault(r["device_id"], []).append({"ip": r["ip"], "last_seen": r["last_seen"]})
        for d in devs:
            d["ips"] = ips.get(d["id"], [])
            d["display_name"] = d["name"] or d["auto_name"] or d["mac"] or d["ident"].split(":", 1)[1]
        return devs

    def db_info(self) -> dict:
        with self.read() as con:
            n = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            oldest = con.execute("SELECT MIN(ts) FROM events").fetchone()[0]
            pages = con.execute("PRAGMA page_count").fetchone()[0]
            psize = con.execute("PRAGMA page_size").fetchone()[0]
        return {"events": n, "oldest": oldest, "size_bytes": pages * psize}
