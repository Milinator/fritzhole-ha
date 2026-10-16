"""FRITZ!Box access: login (login_sid.lua), packet capture, TR-064 host list.

Die Login- und Capture-Logik ist aus fritzhole_live.py (PoC) übernommen.
KRITISCH: Die Capture-Parameter müssen mit quote_via=urllib.parse.quote kodiert
werden (Leerzeichen -> %20). Mit '+' liefert FRITZ!OS keinen PCAP-Stream.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import logging
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass

log = logging.getLogger(__name__)

ZERO_SID = "0000000000000000"
CAPTURE_FILTER = "udp port 53 or tcp port 53"
TR064_PORT = 49000

# Wie im PoC: Header aus dem funktionierenden Firefox-Mitschnitt
BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "de,en-US;q=0.9,en;q=0.8",
    "Upgrade-Insecure-Requests": "1",
}


class FritzError(Exception):
    pass


class AuthError(FritzError):
    def __init__(self, msg: str, block_time: int = 0):
        super().__init__(msg)
        self.block_time = block_time


def split_host(host: str) -> tuple[str, int]:
    """'192.168.178.1', 'fritz.box:80', '[fd00::1]' -> (host, port)."""
    host = host.strip()
    for prefix in ("http://", "https://"):
        if host.lower().startswith(prefix):
            host = host[len(prefix):]
    host = host.rstrip("/")
    if host.startswith("["):
        h, _, rest = host[1:].partition("]")
        return h, int(rest[1:]) if rest.startswith(":") else 80
    if host.count(":") == 1:
        h, p = host.split(":")
        return h, int(p)
    return host, 80


def url_host(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def capture_query(sid: str, iface: str, start: bool = True) -> str:
    """Query string for /cgi-bin/capture_notimeout (unverändert aus dem PoC)."""
    params = {"sid": sid, "capture": "Start" if start else "Stop"}
    if start:
        params.update({"snaplen": "1600", "filter": CAPTURE_FILTER})
    params["ifaceorminor"] = iface
    return urllib.parse.urlencode(params, quote_via=urllib.parse.quote)


def compute_response(challenge: str, password: str) -> str:
    if challenge.startswith("2$"):
        fields = challenge.split("$")
        if len(fields) != 5:
            raise FritzError("Unbekanntes PBKDF2-Challenge-Format")
        _, it1, salt1, it2, salt2 = fields
        h1 = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt1), int(it1))
        h2 = hashlib.pbkdf2_hmac("sha256", h1, bytes.fromhex(salt2), int(it2))
        # AVM Technical Note "Session ID": <response> = <salt2>$<hash2>
        # (Der PoC sendete challenge+'$'+hash2 – fiel nie auf, da ohne version=2 MD5 kam.)
        return salt2 + "$" + h2.hex()
    data = (challenge + "-" + password).encode("utf-16le")
    try:
        digest = hashlib.md5(data, usedforsecurity=False).hexdigest()
    except TypeError:  # pragma: no cover
        digest = hashlib.md5(data).hexdigest()
    return challenge + "-" + digest


@dataclass
class HostEntry:
    ip: str
    mac: str
    name: str
    active: bool


class FritzBox:
    def __init__(self, host: str, username: str, password: str, timeout: float = 10.0):
        self.host, self.port = split_host(host)
        self.username = username
        self._password = password
        self.timeout = timeout
        self.base = f"http://{url_host(self.host)}" + (f":{self.port}" if self.port != 80 else "")
        self._conn: http.client.HTTPConnection | None = None
        self._lock = threading.Lock()

    def __repr__(self) -> str:  # Passwort nie ausgeben
        return f"FritzBox({self.base!r}, user={self.username!r})"

    # ------------------------------------------------------------- session
    def _get(self, path: str, timeout: float | None = None) -> bytes:
        with urllib.request.urlopen(self.base + path, timeout=timeout or self.timeout) as r:
            return r.read()

    def login(self) -> str:
        try:
            info = ET.fromstring(self._get("/login_sid.lua?version=2"))
        except ET.ParseError as exc:
            raise FritzError("login_sid.lua liefert kein gültiges XML") from exc
        challenge = info.findtext("Challenge", "")
        block = int(info.findtext("BlockTime", "0") or 0)
        if block > 0:
            raise AuthError(f"FRITZ!Box sperrt Anmeldungen noch {block} s (frühere Fehlversuche)", block)
        if not challenge:
            raise FritzError("FRITZ!Box liefert keine Challenge")
        query = urllib.parse.urlencode({"username": self.username,
                                        "response": compute_response(challenge, self._password)})
        result = ET.fromstring(self._get("/login_sid.lua?version=2&" + query))
        sid = result.findtext("SID", ZERO_SID)
        if sid == ZERO_SID:
            block = int(result.findtext("BlockTime", "0") or 0)
            raise AuthError("Anmeldung fehlgeschlagen (Benutzer, Passwort oder Berechtigung "
                            "'FRITZ!Box Einstellungen' prüfen)", block)
        return sid

    def logout(self, sid: str) -> None:
        try:
            self._get("/login_sid.lua?" + urllib.parse.urlencode({"logout": "1", "sid": sid}), timeout=3)
        except Exception as exc:  # noqa: BLE001
            log.debug("Logout fehlgeschlagen: %s", type(exc).__name__)

    # ------------------------------------------------------------- capture
    def open_capture(self, sid: str, iface: str, idle_timeout: float):
        """Start capture; returns a file-like HTTP response streaming PCAP data."""
        path = "/cgi-bin/capture_notimeout?" + capture_query(sid, iface, True)
        conn = http.client.HTTPConnection(self.host, self.port, timeout=30)
        headers = dict(BROWSER_HEADERS, Referer=self.base + "/")
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        if resp.status != 200:
            conn.close()
            raise FritzError(f"Mitschnitt-Anfrage: HTTP {resp.status}")
        if conn.sock is not None:
            conn.sock.settimeout(idle_timeout)
        with self._lock:
            self._conn = conn
        return resp

    def abort_capture(self) -> None:
        """Unblock a reading thread by shutting down the capture socket."""
        with self._lock:
            conn, self._conn = self._conn, None
        if conn is None:
            return
        try:
            if conn.sock is not None:
                conn.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        conn.close()

    def stop_capture(self, sid: str, iface: str) -> None:
        """Explizites Stop wie in der FRITZ!Box-Oberfläche [Parameter nicht offiziell dokumentiert]."""
        try:
            with urllib.request.urlopen(
                urllib.request.Request(
                    self.base + "/cgi-bin/capture_notimeout?" + capture_query(sid, iface, False),
                    headers=dict(BROWSER_HEADERS, Referer=self.base + "/"),
                ),
                timeout=3,
            ) as r:
                r.read(1024)
        except Exception as exc:  # noqa: BLE001
            log.debug("Stop-Anfrage fehlgeschlagen: %s", type(exc).__name__)

    # ------------------------------------------------------------- TR-064
    def host_list(self) -> list[HostEntry]:
        """Geräteliste via TR-064 (Hosts:1, X_AVM-DE_GetHostListPath)."""
        tr_base = f"http://{url_host(self.host)}:{TR064_PORT}"
        mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        mgr.add_password(None, tr_base, self.username, self._password)
        opener = urllib.request.build_opener(urllib.request.HTTPDigestAuthHandler(mgr))
        svc = "urn:dslforum-org:service:Hosts:1"
        action = "X_AVM-DE_GetHostListPath"
        body = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            f'<s:Body><u:{action} xmlns:u="{svc}"/></s:Body></s:Envelope>'
        ).encode()
        req = urllib.request.Request(
            tr_base + "/upnp/control/hosts", data=body, method="POST",
            headers={"Content-Type": 'text/xml; charset="utf-8"', "SOAPACTION": f"{svc}#{action}"},
        )
        with opener.open(req, timeout=self.timeout) as r:
            root = ET.fromstring(r.read())
        path = None
        for el in root.iter():
            if el.tag.endswith("NewX_AVM-DE_HostListPath"):
                path = (el.text or "").strip()
        if not path:
            raise FritzError("TR-064: kein HostListPath erhalten")
        with opener.open(tr_base + path, timeout=self.timeout) as r:
            return parse_host_list(r.read())


def parse_host_list(xml: bytes) -> list[HostEntry]:
    root = ET.fromstring(xml)
    out = []
    for item in root.iter("Item"):
        ip = (item.findtext("IPAddress") or "").strip()
        mac = (item.findtext("MACAddress") or "").strip().lower()
        name = (item.findtext("HostName") or "").strip()
        active = (item.findtext("Active") or "0").strip() == "1"
        if mac or ip:
            out.append(HostEntry(ip, mac, name, active))
    return out


# ---------------------------------------------------------------- REST (beta)
class ApiError(FritzError):
    """Fehler der (inoffiziellen) FRITZ!OS-REST-API."""

    def __init__(self, msg: str, status: int | None = None, transient: bool = False):
        super().__init__(msg)
        self.status = status
        self.transient = transient


class RestSession:
    """Eigene, wiederverwendete Session für /api/v0/... (getrennt von der Capture-Session).

    Login wie im Capture-Dienst (FritzBox.login). Bei 401/403 wird einmal neu angemeldet.
    Header wie in fritzhole_dnsfilter_admin.py (getestet gegen FRITZ!OS 8.40-136793 (Labor)).
    """

    def __init__(self, fritz: FritzBox, timeout: float = 20.0):
        self.fritz = fritz
        self.timeout = timeout
        self._sid: str | None = None
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return f"RestSession({self.fritz.base!r})"

    def _sid_value(self, renew: bool = False) -> str:
        if renew or not self._sid:
            self._sid = self.fritz.login()
        return self._sid

    def close(self) -> None:
        if not self._lock.acquire(timeout=2):  # laufende Anfrage blockiert das Beenden nicht
            return
        try:
            if self._sid:
                self.fritz.logout(self._sid)
                self._sid = None
        finally:
            self._lock.release()

    def request(self, method: str, path: str, payload=None):
        with self._lock:
            for attempt in (0, 1):
                try:
                    sid = self._sid_value(renew=attempt == 1)
                    return self._do(method, path, sid, payload)
                except urllib.error.HTTPError as exc:
                    body = _read_body(exc)
                    if _session_invalid(exc.code, body) and attempt == 0:
                        # FRITZ!OS 8.40-136793 (Labor) meldet eine abgelaufene SID als HTTP 400 "permission denied" (code 3001)
                        log.info("REST: Session ungültig (HTTP %s) – neu anmelden", exc.code)
                        continue
                    raise _api_error(exc.code, body) from None
                except (urllib.error.URLError, OSError) as exc:
                    reason = getattr(exc, "reason", exc)
                    raise ApiError(f"FRITZ!Box nicht erreichbar: {reason}", transient=True) from None
                except ET.ParseError:
                    raise ApiError("FRITZ!Box-Login liefert ungültige Antwort", transient=True) from None
        raise ApiError("Keine gültige Session")  # pragma: no cover

    def _do(self, method: str, path: str, sid: str, payload):
        base = self.fritz.base
        headers = {"Accept": "application/json", "Client-Name": "WebGUI", "Referer": base + "/",
                   "Authorization": "AVM-SID " + sid}
        body = None
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
            headers["Origin"] = base
        req = urllib.request.Request(base + path, data=body, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            raw = r.read()
        if not raw.strip():
            return None
        try:
            return json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            return raw.decode("utf-8", errors="replace")


def _read_body(exc: "urllib.error.HTTPError") -> str:
    try:
        return exc.read(4000).decode("utf-8", errors="replace").strip()
    except Exception:  # noqa: BLE001
        return ""


def _error_items(body: str) -> list[dict]:
    """FRITZ!OS liefert Fehler als Liste [{"message":..., "code":...}] oder als Objekt."""
    try:
        data = json.loads(body)
    except ValueError:
        return []
    if isinstance(data, dict):
        inner = data.get("errors")
        data = inner if isinstance(inner, list) else [data]
    return [d for d in data if isinstance(d, dict)] if isinstance(data, list) else []


def _session_invalid(status: int, body: str) -> bool:
    if status in (401, 403):
        return True
    if status == 400:
        return any(str(e.get("code")) == "3001" or "permission denied" in str(e.get("message", "")).lower()
                   for e in _error_items(body))
    return False


def _api_error(status: int, body: str) -> ApiError:
    items = _error_items(body)
    if items:
        detail = "; ".join(f"{e.get('message', '?')}" + (f" (Code {e['code']})" if "code" in e else "")
                           for e in items)[:200]
    else:
        detail = body[:200] if body and "<" not in body else ""
    if _session_invalid(status, body):
        msg = "Keine Berechtigung für die DNS-Filter-API, auch nach erneuter Anmeldung " \
              "(Recht 'FRITZ!Box Einstellungen' prüfen)"
    elif status == 404:
        msg = "DNS-Filter-API nicht gefunden (FRITZ!OS-Version ohne Beta-API?)"
    else:
        msg = f"FRITZ!Box-API: HTTP {status}"
    if detail:
        msg += f" – {detail}"
    return ApiError(msg, status=status, transient=status >= 500 or status == 429)
