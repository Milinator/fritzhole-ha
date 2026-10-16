"""Simulierte FRITZ!Box: login_sid.lua (PBKDF2, version=2) + /api/v0/beta/dnsfilter."""
import copy
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from fritzhole.fritzbox import compute_response

PASSWORD = "geheim-Passw0rt"
CHALLENGE = "2$10$" + "aa" * 16 + "$10$" + "bb" * 16
API = "/api/v0/beta/dnsfilter"

INITIAL = {
    "enabled": True,
    "automaticUpdate": {"enabled": True, "interval": 86400},
    "manualUpdate": {"lastTimestamp": 1760000000},
    "domains": [{"UID": "domain1", "domain": "example.org", "action": "allow", "enabled": True, "comment": "Test"}],
    "filterlists": [
        {"UID": "filterlist1", "name": "HaGeZi Multi PRO", "url": "https://example.net/hagezi.txt", "enabled": True,
         "status": {"isReady": True, "entryCount": 123456, "lastSuccessfulUpdateTimestamp": 1760000000},
         "latestUpdate": {"status": "success", "timestamp": 1760000000, "cause": "automatic"}},
        {"UID": "filterlist2", "name": "Testliste", "url": "https://example.net/broken.txt", "enabled": True,
         "status": {"isReady": False, "entryCount": 0, "lastSuccessfulUpdateTimestamp": 0},
         "latestUpdate": {"status": "error", "timestamp": 1760000100, "cause": "manual",
                          "error": {"code": 3643, "message": "download failed"}}},
    ],
    "statistics": {"dnsQueryCount": {"total": 1000, "blocked": 120}},
}


class FakeFritzApi:
    def __init__(self):
        self.cfg = copy.deepcopy(INITIAL)
        self.sids: set[str] = set()
        self.n = 0
        self.logins = 0
        self.requests: list[tuple[str, str, dict | None, dict]] = []
        self.expire_next = False      # nächster REST-Aufruf -> Session abgelaufen
        self.revoked = False          # Login ok, aber keine Rechte auf die API
        self.expired_status = 401     # FRITZ!OS 8.40-136793 (Labor) antwortet real mit 400 + code 3001
        self.fail_put_enabled = 0     # n-mal HTTP 500 auf PUT /dnsfilter
        self.ignore_writes = False    # Box antwortet OK, ändert aber nichts
        self.manual_triggers = 0
        self.lock = threading.Lock()
        box = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body=None, ctype="application/json"):
                data = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _xml(self, s):
                self._send(200, s.encode(), "text/xml")

            def _rest(self, method):
                path = urllib.parse.urlparse(self.path).path
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n)) if n else None
                auth = self.headers.get("Authorization", "")
                with box.lock:
                    box.requests.append((method, path, body, dict(self.headers)))
                    if box.expire_next:
                        box.expire_next = False
                        box.sids.clear()
                    if box.revoked or not auth.startswith("AVM-SID ") or auth[8:] not in box.sids:
                        if box.expired_status == 400:  # wie echte Box (Screenshot 16.10.)
                            return self._send(400, [{"message": "permission denied: " + path, "code": 3001}])
                        return self._send(401, {"message": "unauthorized"})
                    if self.headers.get("Client-Name") != "WebGUI":
                        return self._send(400)
                    cfg = box.cfg
                    if method == "GET" and path == API:
                        return self._send(200, cfg)
                    if box.ignore_writes and method != "GET":
                        return self._send(200, None)
                    if method == "PUT" and path == API:
                        if box.fail_put_enabled > 0:
                            box.fail_put_enabled -= 1
                            return self._send(500, {"message": "intern"})
                        if body == {"manualUpdate": {"trigger": True}}:
                            box.manual_triggers += 1
                            cfg["manualUpdate"]["lastTimestamp"] += 1
                            return self._send(204)
                        if set(body) != {"enabled", "automaticUpdate"}:
                            return self._send(400)
                        cfg["enabled"] = body["enabled"]
                        cfg["automaticUpdate"] = body["automaticUpdate"]
                        return self._send(204)
                    if path == API + "/filterlists" and method == "POST":
                        box.n += 1
                        cfg["filterlists"].append({"UID": f"fl{box.n}", **body, "status": {"isReady": False, "entryCount": 0}})
                        return self._send(201, {"UID": f"fl{box.n}"})
                    if path.startswith(API + "/filterlists/"):
                        uid = urllib.parse.unquote(path.rsplit("/", 1)[1])
                        hit = [e for e in cfg["filterlists"] if e["UID"] == uid]
                        if not hit:
                            return self._send(404, [{"message": "not found", "code": 404}])
                        if method == "PUT":
                            if set(body) != {"enabled", "name", "url"}:
                                return self._send(400)
                            hit[0].update(body)
                        elif method == "DELETE":
                            cfg["filterlists"].remove(hit[0])
                        return self._send(204)
                    if method == "POST" and path == API + "/domains":
                        box.n += 1
                        cfg["domains"].append({"UID": f"new{box.n}", **body})
                        return self._send(201, {"UID": f"new{box.n}"})
                    if path.startswith(API + "/domains/"):
                        uid = urllib.parse.unquote(path.rsplit("/", 1)[1])
                        hit = [e for e in cfg["domains"] if e["UID"] == uid]
                        if not hit:
                            return self._send(404, {"message": "not found"})
                        if method == "PUT":
                            hit[0].update(body)
                        elif method == "DELETE":
                            cfg["domains"].remove(hit[0])
                        return self._send(204)
                    return self._send(404)

            def do_GET(self):
                path, _, raw = self.path.partition("?")
                if path == "/login_sid.lua":
                    q = urllib.parse.parse_qs(raw)
                    if "logout" in q:
                        box.sids.discard(q.get("sid", [""])[0])
                        return self._xml("<SessionInfo><SID>0000000000000000</SID></SessionInfo>")
                    if "response" in q:
                        if q["response"][0] == compute_response(CHALLENGE, PASSWORD):
                            box.logins += 1
                            sid = f"{box.logins:016x}"
                            box.sids.add(sid)
                            return self._xml(f"<SessionInfo><SID>{sid}</SID></SessionInfo>")
                        return self._xml("<SessionInfo><SID>0000000000000000</SID><BlockTime>0</BlockTime></SessionInfo>")
                    return self._xml(f"<SessionInfo><SID>0000000000000000</SID><Challenge>{CHALLENGE}</Challenge>"
                                     "<BlockTime>0</BlockTime></SessionInfo>")
                return self._rest("GET")

            def do_POST(self):
                return self._rest("POST")

            def do_PUT(self):
                return self._rest("PUT")

            def do_DELETE(self):
                return self._rest("DELETE")

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def set_update(self, uid, status, ts, error=None):
        """Simuliert Fortschritt/Ergebnis eines Downloads auf der Box."""
        fl = next(e for e in self.cfg["filterlists"] if e["UID"] == uid)
        fl["latestUpdate"] = {"status": status, "timestamp": ts, "cause": "manual"}
        if error:
            fl["latestUpdate"]["error"] = error
        elif status == "success":
            fl["status"] = {"isReady": True, "entryCount": 1000, "lastSuccessfulUpdateTimestamp": ts}

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()
