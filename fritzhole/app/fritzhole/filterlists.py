"""FRITZ!Box-DNS-Filterlisten (inoffizielle Beta-API) – Ergänzung zu dnsfilter.py.

API-Aufrufe aus fritzhole_filterlists_admin.py (gegen FRITZ!OS 8.40-136793 (Labor) getestet):
  POST   /api/v0/beta/dnsfilter/filterlists          {enabled, name, url}
  PUT    /api/v0/beta/dnsfilter/filterlists/<UID>    {enabled, name, url}
  DELETE /api/v0/beta/dnsfilter/filterlists/<UID>
  PUT    /api/v0/beta/dnsfilter                      {manualUpdate: {trigger: true}}
  PUT    /api/v0/beta/dnsfilter                      {enabled: <unverändert>, automaticUpdate: {interval, enabled}}
"""
from __future__ import annotations

import logging
import urllib.parse
from datetime import datetime
from typing import Any

log = logging.getLogger(__name__)

API = "/api/v0/beta/dnsfilter"
# Stufen wie in der FRITZ!Box-Oberfläche (Werte an FRITZ!OS 8.40-136793 (Labor) ausgelesen, 16.10.2026)
AUTO_PRESETS = {
    "8h": (28800, True),
    "daily": (86400, True),
    "weekly": (604800, True),
    "monthly": (2592000, True),
    "never": (0, False),        # Box speichert „Nie“ als enabled=false, interval=0
}


def auto_preset(au) -> str | None:
    """Stufe zum aktuellen automaticUpdate oder None, wenn der Wert keiner Stufe entspricht."""
    if not isinstance(au, dict):
        return None
    for key, (interval, enabled) in AUTO_PRESETS.items():
        if au.get("interval") == interval and au.get("enabled") is enabled:
            return key
    return None
UPDATE_TIMEOUT = 600.0  # ohne Rückmeldung der Box nach 10 min -> "keine Rückmeldung"

# Beobachtet: "error". Weitere Werte sind nicht dokumentiert -> unbekannte Werte werden roh angezeigt.
ERROR_STATES = {"error", "failed", "failure"}
RUNNING_STATES = {"running", "inprogress", "in_progress", "pending", "updating", "started", "downloading", "busy"}
OK_STATES = {"success", "succeeded", "ok", "done", "finished", "completed", "complete"}


def _filter_error(msg: str, status: int = 400):
    from .dnsfilter import FilterError  # zyklischen Import vermeiden
    return FilterError(msg, status)


# ------------------------------------------------------------------ helpers
def to_epoch(v) -> float | None:
    """FRITZ!OS-Zeitstempel (Sekunden, Millisekunden oder ISO-String) -> Unix-Sekunden."""
    if isinstance(v, bool) or v is None or v == "":
        return None
    if isinstance(v, (int, float)):
        x = float(v)
    elif isinstance(v, str):
        try:
            x = float(v)
        except ValueError:
            try:
                return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
            except ValueError:
                return None
    else:
        return None
    if x <= 0:
        return None
    return x / 1000.0 if x > 1e12 else x


def _norm_status(v) -> str:
    return str(v or "").strip().lower().replace(" ", "")


def list_health(fl: dict) -> dict:
    """Aussagekräftiger Zustand einer Filterliste aus status + latestUpdate."""
    st = fl.get("status") if isinstance(fl.get("status"), dict) else {}
    lu = fl.get("latestUpdate") if isinstance(fl.get("latestUpdate"), dict) else {}
    err = lu.get("error") if isinstance(lu.get("error"), dict) else {}
    raw = _norm_status(lu.get("status"))
    if fl.get("enabled") is False:
        state = "disabled"
    elif raw in RUNNING_STATES:
        state = "updating"
    elif raw in ERROR_STATES or (err and (err.get("code") or err.get("message"))):
        state = "error"
    elif st.get("isReady") is True:
        state = "ready"
    elif st.get("isReady") is False:
        state = "not_ready"
    else:
        state = "unknown"
    return {
        "state": state,
        "is_ready": st.get("isReady"),
        "entry_count": st.get("entryCount"),
        "last_success": to_epoch(st.get("lastSuccessfulUpdateTimestamp")),
        "latest_status": lu.get("status"),
        "latest_ts": to_epoch(lu.get("timestamp")),
        "error_code": err.get("code"),
        "error_message": err.get("message"),
        "cause": lu.get("cause"),
    }


def normalize_lists(cfg: dict) -> list[dict]:
    out = []
    for fl in cfg.get("filterlists", []):
        if not isinstance(fl, dict):
            continue
        out.append({"uid": fl.get("UID"), "name": fl.get("name"), "url": fl.get("url"),
                    "enabled": fl.get("enabled"), "health": list_health(fl), "raw": fl})
    return out


def validate_url(url) -> str:
    u = str(url or "").strip()
    parts = urllib.parse.urlsplit(u)
    if len(u) > 1024 or parts.scheme != "https" or not parts.netloc or parts.username or parts.password \
            or any(c.isspace() for c in u):
        raise _filter_error("Bitte eine gültige HTTPS-URL ohne Zugangsdaten angeben")
    return u


def validate_name(name) -> str:
    n = str(name or "").strip()
    if not n:
        raise _filter_error("Name darf nicht leer sein")
    if len(n) > 100:
        raise _filter_error("Name zu lang (max. 100 Zeichen)")
    return n


def _same_url(a, b) -> bool:
    return str(a or "").strip().rstrip("/").lower() == str(b or "").strip().rstrip("/").lower()


def _conflict(cfg: dict, name: str, url: str, except_uid=None) -> str | None:
    for e in cfg.get("filterlists", []):
        if e.get("UID") == except_uid:
            continue
        if str(e.get("name", "")).strip().lower() == name.lower():
            return f"Eine Filterliste mit dem Namen „{name}“ existiert bereits"
        if _same_url(e.get("url"), url):
            return f"Diese URL wird bereits von „{e.get('name')}“ verwendet"
    return None


def _baseline(cfg: dict) -> dict:
    out = {}
    for fl in cfg.get("filterlists", []):
        lu = fl.get("latestUpdate") if isinstance(fl.get("latestUpdate"), dict) else {}
        out[fl.get("UID")] = [lu.get("timestamp"), lu.get("status")]
    return out


def update_progress(tracking: dict | None, cfg: dict | None, now: float) -> dict | None:
    """Fortschritt einer manuellen Aktualisierung – nur aus echten API-Daten abgeleitet.

    requested  angefordert, Box hat noch keine Änderung gemeldet
    running    mindestens eine Liste meldet laufenden Download bzw. erst ein Teil ist fertig
    success    alle aktiven Listen haben ein neues, fehlerfreies Update gemeldet
    error      alle aktiven Listen fertig, mindestens eine mit Fehler
    timeout    nach UPDATE_TIMEOUT keine (vollständige) Rückmeldung
    """
    if not tracking or not cfg:
        return None
    base = tracking.get("baseline", {})
    lists = [fl for fl in cfg.get("filterlists", []) if fl.get("enabled") is not False]
    per = []
    for fl in lists:
        lu = fl.get("latestUpdate") if isinstance(fl.get("latestUpdate"), dict) else {}
        now_sig = [lu.get("timestamp"), lu.get("status")]
        changed = now_sig != base.get(fl.get("UID"), [None, None]) and lu.get("timestamp") is not None
        raw = _norm_status(lu.get("status"))
        if raw in RUNNING_STATES:
            s = "running"
        elif not changed:
            s = "pending"
        elif raw in ERROR_STATES or (isinstance(lu.get("error"), dict) and lu["error"].get("code")):
            s = "error"
        elif raw in OK_STATES or not raw:
            s = "done"
        else:
            s = "unknown"
        per.append({"uid": fl.get("UID"), "name": fl.get("name"), "state": s, "status": lu.get("status")})
    states = {p["state"] for p in per}
    if "running" in states:
        phase = "running"
    elif per and states <= {"done", "error", "unknown"}:
        phase = "error" if "error" in states else "success" if states == {"done"} else "unknown"
    elif states & {"done", "error", "unknown"}:
        phase = "running"   # teilweise fertig
    else:
        phase = "requested"
    if phase in ("requested", "running") and now - tracking["requested_at"] > UPDATE_TIMEOUT:
        phase = "timeout"
    return {"phase": phase, "requested_at": tracking["requested_at"], "lists": per,
            "finished": phase in ("success", "error", "unknown", "timeout")}


# ------------------------------------------------------------------ service mixin
class FilterListsMixin:
    """Wird von DnsFilterService eingebunden (nutzt dessen Session, Lock, Verifikation)."""

    manual_update: dict | None = None

    def _find_list(self, cfg: dict, uid: str) -> dict:
        m = [e for e in cfg.get("filterlists", []) if e.get("UID") == uid]
        if len(m) != 1:
            raise _filter_error("Filterliste nicht (mehr) vorhanden – Liste wurde neu geladen", 404)
        return m[0]

    def add_list(self, name, url, enabled=True) -> dict:
        self._require_write()
        name, url = validate_name(name), validate_url(url)
        if not isinstance(enabled, bool):
            raise _filter_error("'enabled' muss true/false sein")
        with self._write_lock:
            cfg = self._get()
            conflict = _conflict(cfg, name, url)
            if conflict:
                raise _filter_error(conflict, 409)
            payload = {"enabled": enabled, "name": name, "url": url}
            self.rest.request("POST", API + "/filterlists", payload)
            cfg = self._verify(lambda c: any(
                e.get("name") == name and e.get("url") == url and e.get("enabled") is enabled
                for e in c.get("filterlists", [])), f"Hinzufügen der Filterliste {name}")
        log.info("DNS-Filter: Filterliste „%s“ hinzugefügt (%s)", name, "aktiv" if enabled else "inaktiv")
        return cfg

    def edit_list(self, uid: str, name=None, url=None, enabled=None) -> dict:
        self._require_write()
        with self._write_lock:
            cfg = self._get()
            entry = self._find_list(cfg, uid)
            # Unveränderte Eigenschaften aus dem aktuellen Stand übernehmen (wie Referenzskript)
            payload = {
                "enabled": entry.get("enabled") if enabled is None else enabled,
                "name": entry.get("name") if name is None else validate_name(name),
                "url": entry.get("url") if url is None else validate_url(url),
            }
            if not isinstance(payload["enabled"], bool):
                raise _filter_error("'enabled' muss true/false sein")
            conflict = _conflict(cfg, str(payload["name"]), str(payload["url"]), except_uid=uid)
            if conflict:
                raise _filter_error(conflict, 409)
            self.rest.request("PUT", API + "/filterlists/" + urllib.parse.quote(uid, safe=""), payload)
            cfg = self._verify(lambda c: any(
                e.get("UID") == uid and all(e.get(k) == v for k, v in payload.items())
                for e in c.get("filterlists", [])), f"Ändern der Filterliste {payload['name']}")
        log.info("DNS-Filter: Filterliste %s geändert (%s, %s)", uid, payload["name"],
                 "aktiv" if payload["enabled"] else "inaktiv")
        return cfg

    def delete_list(self, uid: str) -> dict:
        self._require_write()
        with self._write_lock:
            cfg = self._get()
            entry = self._find_list(cfg, uid)
            self.rest.request("DELETE", API + "/filterlists/" + urllib.parse.quote(uid, safe=""))
            cfg = self._verify(lambda c: all(e.get("UID") != uid for e in c.get("filterlists", [])),
                               f"Löschen der Filterliste {entry.get('name')}")
        log.warning("DNS-Filter: Filterliste „%s“ gelöscht", entry.get("name"))
        return cfg

    def trigger_update(self) -> dict:
        self._require_write()
        with self._write_lock:
            cfg = self._get()  # Ausgangszustand für die Fortschrittsanzeige
            self.rest.request("PUT", API, {"manualUpdate": {"trigger": True}})
            self.manual_update = {"requested_at": self.clock(), "baseline": _baseline(cfg)}
            cfg = self._get()  # Box hat die Anforderung angenommen; Abschluss wird NICHT behauptet
        log.info("DNS-Filter: manuelle Aktualisierung aller Filterlisten angefordert")
        return cfg

    def set_auto_update(self, preset: str) -> dict:
        """Automatische Aktualisierung auf eine der FRITZ!Box-Stufen setzen."""
        self._require_write()
        if preset not in AUTO_PRESETS:
            raise _filter_error("Unbekannte Stufe – erlaubt: " + ", ".join(AUTO_PRESETS))
        interval, new_enabled = AUTO_PRESETS[preset]
        with self._write_lock:
            cfg = self._get()
            cur = cfg.get("automaticUpdate")
            if not isinstance(cur, dict) or not isinstance(cur.get("interval"), int) \
                    or not isinstance(cur.get("enabled"), bool):
                raise _filter_error("Automatische Update-Konfiguration unvollständig – kein Schreibzugriff", 502)
            main = cfg.get("enabled")
            if not isinstance(main, bool):
                raise _filter_error("DNS-Hauptschalter nicht lesbar – kein Schreibzugriff", 502)
            # Hauptschalter unverändert mitschicken (auch während einer Pause)
            payload = {"enabled": main, "automaticUpdate": {"interval": interval, "enabled": new_enabled}}
            self.rest.request("PUT", API, payload)
            cfg = self._verify(lambda c: c.get("enabled") == main
                               and (c.get("automaticUpdate") or {}).get("interval") == interval
                               and (c.get("automaticUpdate") or {}).get("enabled") is new_enabled,
                               "Ändern der automatischen Aktualisierung")
        log.info("DNS-Filter: automatische Aktualisierung auf „%s“ gesetzt", preset)
        return cfg

    def progress(self, cfg: dict | None) -> dict | None:
        p = update_progress(self.manual_update, cfg, self.clock())
        return p

    def extra_state(self, cfg: dict | None) -> dict[str, Any]:
        out: dict[str, Any] = {"manual_update": self.progress(cfg)}
        if cfg is not None:
            out["filterlists_detail"] = normalize_lists(cfg)
            out["auto_preset"] = auto_preset(cfg.get("automaticUpdate"))
            mu = cfg.get("manualUpdate") if isinstance(cfg.get("manualUpdate"), dict) else {}
            out["manual_last"] = to_epoch(mu.get("lastTimestamp"))
        return out
