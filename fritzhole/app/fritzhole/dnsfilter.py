"""FRITZ!Box-DNS-Filter verwalten (inoffizielle Beta-API /api/v0/beta/dnsfilter).

API-Aufrufe 1:1 aus fritzhole_dnsfilter_admin.py übernommen (gegen FRITZ!OS 8.40-136793 (Labor) getestet):
  GET    /api/v0/beta/dnsfilter                 Konfiguration
  POST   /api/v0/beta/dnsfilter/domains         {enabled, domain, comment, action}
  PUT    /api/v0/beta/dnsfilter/domains/<UID>   {domain, comment, action}
  DELETE /api/v0/beta/dnsfilter/domains/<UID>
  PUT    /api/v0/beta/dnsfilter                 {enabled, automaticUpdate:{interval, enabled}}
Jede Schreiboperation wird durch erneutes Auslesen verifiziert.
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
import urllib.parse
from typing import Any, Callable

from .filterlists import FilterListsMixin
from .fritzbox import ApiError, AuthError, FritzError, RestSession

log = logging.getLogger(__name__)

API = "/api/v0/beta/dnsfilter"
ACTIONS = ("allow", "deny")
CACHE_TTL = 20.0
PAUSE_KEY = "dnsfilter_pause"
PAUSE_MIN, PAUSE_MAX = 1, 24 * 60          # Minuten
RETRY_MIN, RETRY_MAX = 30.0, 300.0         # Wiederholung bei fehlgeschlagener Reaktivierung
_LABEL = re.compile(r"^(\*|[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)$")


class FilterError(Exception):
    """Fachlicher Fehler (Validierung, Verifikation, Zustand) – Text ist für die Oberfläche gedacht."""

    def __init__(self, msg: str, status: int = 400):
        super().__init__(msg)
        self.status = status


# ------------------------------------------------------------------ helpers
def normalize_domain(raw: str) -> str:
    d = str(raw or "").strip().lower().rstrip(".")
    if not d or len(d) > 253 or "/" in d or any(c.isspace() for c in d):
        raise FilterError("Ungültiger Domain-Name")
    try:
        d = d.encode("idna").decode("ascii") if not d.isascii() else d
    except UnicodeError:
        raise FilterError("Ungültiger Domain-Name (IDN)") from None
    labels = d.split(".")
    if any(not _LABEL.match(lbl) for lbl in labels) or "*" in labels[1:]:
        raise FilterError("Ungültiger Domain-Name")
    return d


def _comment(raw) -> str:
    c = "" if raw is None else str(raw)
    if len(c) > 200:
        raise FilterError("Kommentar zu lang (max. 200 Zeichen)")
    return c.strip()


def _action(raw) -> str:
    if raw not in ACTIONS:
        raise FilterError("Aktion muss 'allow' oder 'deny' sein")
    return raw


def normalize_config(cfg: dict) -> dict:
    domains = [{
        "uid": e.get("UID"), "domain": e.get("domain", ""), "action": e.get("action"),
        "enabled": e.get("enabled"), "comment": e.get("comment", ""),
    } for e in cfg.get("domains", []) if isinstance(e, dict)]
    lists = [fl for fl in cfg.get("filterlists", []) if isinstance(fl, dict)]
    stats = cfg.get("statistics") if isinstance(cfg.get("statistics"), dict) else {}
    return {
        "enabled": cfg.get("enabled"),
        "automaticUpdate": cfg.get("automaticUpdate"),
        "domains": domains,
        "filterlists": lists,
        "filterlist_entries": sum(int((fl.get("status") or {}).get("entryCount") or 0)
                                  for fl in lists if isinstance(fl.get("status"), dict)),
        "statistics": stats,
    }


class DnsFilterService(FilterListsMixin):
    def __init__(self, rest: RestSession | None, store, writable: bool = True,
                 clock: Callable[[], float] = time.time):
        self.rest = rest
        self.store = store
        self.writable = writable and rest is not None
        self.clock = clock
        self._cache: dict | None = None
        self._cache_ts = 0.0
        self._error: str | None = None
        self._write_lock = threading.Lock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self.pause = self._load_pause()

    # ------------------------------------------------------------ low level
    def _get(self) -> dict:
        cfg = self.rest.request("GET", API)
        if not isinstance(cfg, dict) or not isinstance(cfg.get("domains"), list):
            raise ApiError("Unerwartete Antwort von der DNS-Filter-API")
        self._cache, self._cache_ts, self._error = cfg, self.clock(), None
        return cfg

    def config(self, max_age: float = CACHE_TTL) -> dict:
        """Read (cached). Raises on error when no cache is available."""
        if self.rest is None:
            raise FilterError("FRITZ!Box nicht konfiguriert", 503)
        if self._cache is not None and self.clock() - self._cache_ts < max_age:
            return self._cache
        try:
            return self._get()
        except (FritzError, AuthError) as exc:
            self._error = str(exc)
            raise

    def state(self, max_age: float = CACHE_TTL) -> dict:
        """Snapshot for the UI (never raises for API errors)."""
        out: dict[str, Any] = {"available": False, "writable": self.writable, "error": None,
                               "fetched_at": None, "config": None, "pause": self.pause_info(),
                               "server_time": self.clock()}
        try:
            cfg = self.config(max_age)
            out.update(available=True, config=normalize_config(cfg), fetched_at=self._cache_ts)
            out.update(self.extra_state(cfg))
        except FilterError as exc:
            out["error"] = str(exc)
        except FritzError as exc:
            out["error"] = str(exc)
            if self._cache is not None:  # letzter bekannter Stand, als veraltet markiert
                out.update(config=normalize_config(self._cache), fetched_at=self._cache_ts, stale=True)
                out.update(self.extra_state(self._cache))
        return out

    def _verify(self, check: Callable[[dict], bool], what: str) -> dict:
        cfg = self._get()
        if not check(cfg):
            log.error("DNS-Filter: %s konnte beim erneuten Auslesen NICHT bestätigt werden", what)
            raise FilterError(f"{what}: Änderung beim erneuten Auslesen nicht bestätigt", 502)
        return cfg

    def _require_write(self):
        if not self.writable:
            raise FilterError("Schreibzugriff ist in der App-Konfiguration deaktiviert", 403)

    @staticmethod
    def _find(cfg: dict, uid: str) -> dict:
        m = [e for e in cfg["domains"] if e.get("UID") == uid]
        if len(m) != 1:
            raise FilterError("Eintrag nicht (mehr) vorhanden – Liste wurde neu geladen", 404)
        return m[0]

    # ------------------------------------------------------------ domains
    def add_domain(self, domain, action, comment="") -> dict:
        self._require_write()
        domain, action, comment = normalize_domain(domain), _action(action), _comment(comment)
        with self._write_lock:
            cfg = self._get()
            for e in cfg["domains"]:
                if e.get("domain", "").lower() == domain:
                    kind = "Whitelist" if e.get("action") == "allow" else "Blacklist"
                    raise FilterError(f"{domain} steht bereits auf der {kind}", 409)
            payload = {"enabled": True, "domain": domain, "comment": comment, "action": action}
            self.rest.request("POST", API + "/domains", payload)
            cfg = self._verify(lambda c: any(
                e.get("domain", "").lower() == domain and e.get("action") == action
                and e.get("comment", "") == comment for e in c["domains"]), f"Hinzufügen von {domain}")
        log.info("DNS-Filter: %s zur %s hinzugefügt", domain, "Whitelist" if action == "allow" else "Blacklist")
        return cfg

    def edit_domain(self, uid: str, domain=None, action=None, comment=None) -> dict:
        self._require_write()
        with self._write_lock:
            cfg = self._get()
            entry = self._find(cfg, uid)
            domain = normalize_domain(domain if domain is not None else entry.get("domain"))
            action = _action(action if action is not None else entry.get("action"))
            comment = _comment(comment if comment is not None else entry.get("comment", ""))
            if any(e.get("UID") != uid and e.get("domain", "").lower() == domain for e in cfg["domains"]):
                raise FilterError(f"{domain} ist bereits als anderer Eintrag vorhanden", 409)
            payload = {"domain": domain, "comment": comment, "action": action}
            self.rest.request("PUT", API + "/domains/" + urllib.parse.quote(uid, safe=""), payload)
            cfg = self._verify(lambda c: any(
                e.get("UID") == uid and e.get("domain") == domain and e.get("action") == action
                and e.get("comment", "") == comment for e in c["domains"]), f"Bearbeiten von {domain}")
        log.info("DNS-Filter: Eintrag %s geändert (%s, %s)", uid, domain, action)
        return cfg

    def delete_domain(self, uid: str) -> dict:
        self._require_write()
        with self._write_lock:
            cfg = self._get()
            entry = self._find(cfg, uid)
            self.rest.request("DELETE", API + "/domains/" + urllib.parse.quote(uid, safe=""))
            cfg = self._verify(lambda c: all(e.get("UID") != uid for e in c["domains"]),
                               f"Löschen von {entry.get('domain')}")
        log.info("DNS-Filter: Eintrag %s (%s) gelöscht", uid, entry.get("domain"))
        return cfg

    # ------------------------------------------------------------ main switch
    def _set_enabled(self, enabled: bool) -> dict:
        cfg = self._get()
        auto = cfg.get("automaticUpdate")
        if not isinstance(auto, dict) or "enabled" not in auto or "interval" not in auto:
            raise FilterError("automaticUpdate ist unvollständig – kein Schreibzugriff", 502)
        payload = {"enabled": enabled, "automaticUpdate": {"interval": auto["interval"], "enabled": auto["enabled"]}}
        self.rest.request("PUT", API, payload)
        return self._verify(lambda c: c.get("enabled") is enabled
                            and (c.get("automaticUpdate") or {}).get("interval") == auto["interval"]
                            and (c.get("automaticUpdate") or {}).get("enabled") == auto["enabled"],
                            "DNS-Filter " + ("einschalten" if enabled else "ausschalten"))

    def set_enabled(self, enabled: bool) -> dict:
        """Hauptschalter. Einschalten beendet eine Pause; Ausschalten macht sie dauerhaft."""
        self._require_write()
        with self._write_lock:
            cfg = self._set_enabled(bool(enabled))
            if self.pause:
                self._save_pause(None)
        log.warning("DNS-Filter manuell %s", "EINGESCHALTET" if enabled else "AUSGESCHALTET")
        return cfg

    # ------------------------------------------------------------ pause
    def _load_pause(self) -> dict | None:
        raw = self.store.get_meta(PAUSE_KEY) if self.store else None
        if not raw:
            return None
        try:
            p = json.loads(raw)
            return p if isinstance(p, dict) and isinstance(p.get("resume_at"), (int, float)) else None
        except ValueError:
            return None

    def _save_pause(self, p: dict | None) -> None:
        self.store.set_meta(PAUSE_KEY, json.dumps(p) if p else None)
        self.pause = p
        self._wake.set()

    def pause_info(self) -> dict | None:
        p = self.pause
        if not p:
            return None
        return {**p, "remaining": max(0.0, p["resume_at"] - self.clock())}

    def pause_for(self, minutes: float) -> dict:
        self._require_write()
        try:
            minutes = float(minutes)
        except (TypeError, ValueError):
            raise FilterError("Dauer ungültig") from None
        if not PAUSE_MIN <= minutes <= PAUSE_MAX:
            raise FilterError(f"Dauer muss zwischen {PAUSE_MIN} und {PAUSE_MAX} Minuten liegen")
        with self._write_lock:
            now = self.clock()
            if self.pause:  # laufende Pause neu setzen
                self._save_pause({**self.pause, "resume_at": now + minutes * 60, "minutes": minutes,
                                  "attempts": 0, "last_error": None, "next_retry": None})
                log.warning("DNS-Filter-Pause geändert: Reaktivierung in %.0f min", minutes)
                cfg = self._get()
                if cfg.get("enabled") is True:  # zwischenzeitlich extern eingeschaltet -> wieder aus
                    cfg = self._set_enabled(False)
                return cfg
            cfg = self._get()
            if cfg.get("enabled") is not True:
                raise FilterError("DNS-Filter ist bereits ausgeschaltet – Pause nicht möglich", 409)
            # Zuerst persistieren: stürzt die App nach dem Ausschalten ab, wird trotzdem reaktiviert.
            self._save_pause({"paused_at": now, "resume_at": now + minutes * 60, "minutes": minutes,
                              "attempts": 0, "last_error": None})
            try:
                cfg = self._set_enabled(False)
            except Exception:
                self._recover_after_failed_pause()
                raise
        log.warning("DNS-Filter für %.0f min pausiert (Reaktivierung %s)", minutes,
                    time.strftime("%H:%M:%S", time.localtime(self.pause["resume_at"])))
        return cfg

    def _recover_after_failed_pause(self):
        """Ausschalten fehlgeschlagen: Pause nur verwerfen, wenn der Filter nachweislich noch aktiv ist."""
        try:
            if self._get().get("enabled") is True:
                self._save_pause(None)
        except Exception:  # noqa: BLE001 – Pause bleibt bestehen -> Scheduler stellt sicher, dass er wieder angeht
            pass

    def resume_now(self) -> dict:
        self._require_write()
        with self._write_lock:
            cfg = self._set_enabled(True)
            self._save_pause(None)
        log.warning("DNS-Filter manuell vorzeitig wieder eingeschaltet")
        return cfg

    def tick(self) -> float:
        """Fällige Reaktivierung ausführen. Liefert Sekunden bis zur nächsten Prüfung."""
        p = self.pause
        if not p:
            return 3600.0
        now = self.clock()
        if now < p["resume_at"]:
            return min(p["resume_at"] - now, 30.0)
        with self._write_lock:
            p = self.pause
            if not p:
                return 3600.0
            try:
                self._set_enabled(True)
            except Exception as exc:  # noqa: BLE001
                attempts = int(p.get("attempts", 0)) + 1
                msg = str(exc) or type(exc).__name__
                delay = min(RETRY_MAX, RETRY_MIN * 2 ** (attempts - 1))
                self._save_pause({**p, "attempts": attempts, "last_error": msg, "last_attempt": now,
                                  "next_retry": now + delay})
                log.error("DNS-Filter-Reaktivierung fehlgeschlagen (Versuch %d): %s – neuer Versuch in %.0f s",
                          attempts, msg, delay)
                return delay
            overdue = now - p["resume_at"]
            self._save_pause(None)
        log.warning("DNS-Filter nach Pause automatisch wieder eingeschaltet%s",
                    f" (verspätet um {overdue:.0f} s)" if overdue > 60 else "")
        return 3600.0

    def _due_wait(self) -> float:
        p = self.pause
        if p and p.get("next_retry") and p.get("next_retry") > self.clock():
            return p["next_retry"] - self.clock()
        return self.tick()

    def start(self) -> None:
        if self.rest is None or (self._thread and self._thread.is_alive()):
            return
        if self.pause:
            overdue = self.clock() - self.pause["resume_at"]
            if overdue >= 0:
                log.warning("Ausstehende DNS-Filter-Reaktivierung ist seit %.0f s überfällig – wird ausgeführt", overdue)
            else:
                log.info("DNS-Filter ist pausiert – Reaktivierung in %.0f s", -overdue)
        self._thread = threading.Thread(target=self._run, name="dnsfilter-resume", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                wait = self._due_wait()
            except Exception:  # noqa: BLE001
                log.exception("Fehler im DNS-Filter-Scheduler")
                wait = RETRY_MIN
            self._wake.clear()
            self._wake.wait(max(1.0, wait))
