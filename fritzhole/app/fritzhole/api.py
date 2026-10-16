"""HTTP backend (Starlette/ASGI) + static dashboard, served via Home Assistant Ingress.

Bewusst Starlette statt FastAPI: nur reine Python-Abhängigkeiten, damit der
Image-Build unter Alpine/musl auf jeder Architektur ohne Compiler funktioniert.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Callable

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, StreamingResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Receive, Scope, Send

from . import __version__
from .db import Store
from .dnsfilter import DnsFilterService, FilterError
from .fritzbox import FritzError
from .pipeline import LiveHub

STATIC = Path(__file__).parent / "static"
INGRESS_PROXY = {"172.30.32.2"}  # Supervisor-Ingress-Proxy
LOCAL = {"127.0.0.1", "::1", "testclient"}
CONFIRM_HEADER = "x-fritzhole-confirm"  # Pflicht für schreibende Aufrufe (CSRF-/Fehlklick-Schutz)


# ---------------------------------------------------------------- validation
def _param(req: Request, name: str, kind=str, lo=None, hi=None, default=None, max_len=255):
    raw = req.query_params.get(name)
    if raw is None or raw == "":
        return default
    if len(raw) > max_len:
        raise HTTPException(422, f"Parameter '{name}' zu lang")
    try:
        val = kind(raw)
    except ValueError:
        raise HTTPException(422, f"Parameter '{name}' ungültig") from None
    if (lo is not None and val < lo) or (hi is not None and val > hi):
        raise HTTPException(422, f"Parameter '{name}' außerhalb des Bereichs")
    return val


def _filters(req: Request) -> dict:
    return {
        "from_ts": _param(req, "from_ts", float, 0), "to_ts": _param(req, "to_ts", float, 0),
        "status": _param(req, "status", max_len=100), "device_id": _param(req, "device_id", int, 0),
        "q": (_param(req, "q", max_len=100) or "").strip() or None,
        "domain": _param(req, "domain"), "client_ip": _param(req, "client_ip", max_len=64),
    }


async def _json_body(req: Request) -> dict:
    try:
        body = await req.json()
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(422, "Ungültiges JSON") from None
    if not isinstance(body, dict):
        raise HTTPException(422, "JSON-Objekt erwartet")
    return body


class IngressOnly:
    """Nur der Ingress-Proxy des Supervisors darf zugreifen (keine Portfreigabe nötig)."""

    def __init__(self, app: ASGIApp, allow_all: bool):
        self.app, self.allow_all = app, allow_all

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if not self.allow_all:
            host = (scope.get("client") or ("", 0))[0]
            if host not in INGRESS_PROXY | LOCAL:
                resp = JSONResponse({"detail": "Zugriff nur über Home Assistant Ingress"}, status_code=403)
                return await resp(scope, receive, send)
        if scope["method"] in ("POST", "PUT", "DELETE", "PATCH"):
            headers = dict(scope.get("headers") or [])
            if headers.get(CONFIRM_HEADER.encode()) != b"1":
                resp = JSONResponse({"detail": "Schreibender Aufruf ohne Bestätigungs-Header abgelehnt"},
                                    status_code=403)
                return await resp(scope, receive, send)

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers += [(b"x-content-type-options", b"nosniff"), (b"referrer-policy", b"no-referrer")]
                if scope["path"].startswith("/static/"):  # immer revalidieren (ETag), nie veraltet ausliefern
                    headers = [h for h in headers if h[0].lower() != b"cache-control"] + [(b"cache-control", b"no-cache")]
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrapper)


# ---------------------------------------------------------------- app factory
def create_app(store: Store, hub: LiveHub, status_provider: Callable[[], dict] | None = None,
               lifespan_hooks: tuple[Callable, Callable] | None = None,
               allow_all: bool | None = None, dnsfilter: DnsFilterService | None = None) -> Starlette:
    if allow_all is None:
        allow_all = os.environ.get("FRITZHOLE_ALLOW_ALL") == "1"

    @asynccontextmanager
    async def lifespan(app):
        if lifespan_hooks:
            await run_in_threadpool(lifespan_hooks[0])
        try:
            yield
        finally:
            if lifespan_hooks:
                await run_in_threadpool(lifespan_hooks[1])

    async def index(req: Request):
        # Cache-Busting: JS/CSS-URLs tragen die Version, sonst mischt der Browser
        # (v. a. die HA-Companion-App) neues HTML mit altem app.js.
        html = (STATIC / "index.html").read_text(encoding="utf-8")
        for asset in ("static/app.js", "static/style.css"):
            html = html.replace(f'"{asset}"', f'"{asset}?v={__version__}"')
        return HTMLResponse(html, headers={"Cache-Control": "no-cache"})

    async def health(req: Request):
        return JSONResponse({"ok": True, "version": __version__})

    async def status(req: Request):
        info: dict[str, Any] = {"version": __version__, "time": time.time(), "live_clients": hub.count}
        if status_provider:
            info.update(status_provider())
        info["database"] = await run_in_threadpool(store.db_info)
        return JSONResponse(info)

    async def summary(req: Request):
        return JSONResponse(await run_in_threadpool(store.summary, _filters(req)))

    async def timeline(req: Request):
        bucket = _param(req, "bucket", int, 60, 86400)
        return JSONResponse(await run_in_threadpool(store.timeline, _filters(req), bucket))

    async def events(req: Request):
        limit = _param(req, "limit", int, 1, 1000, 100)
        before = _param(req, "before_id", int, 0)
        after = _param(req, "after_id", int, 0)
        return JSONResponse(await run_in_threadpool(store.events, _filters(req), limit, before, after))

    async def top_domains(req: Request):
        limit = _param(req, "limit", int, 1, 200, 20)
        return JSONResponse(await run_in_threadpool(store.top_domains, _filters(req), limit))

    async def top_devices(req: Request):
        limit = _param(req, "limit", int, 1, 200, 20)
        return JSONResponse(await run_in_threadpool(store.top_devices, _filters(req), limit))

    async def devices(req: Request):
        return JSONResponse(await run_in_threadpool(store.devices))

    async def rename(req: Request):
        body = await _json_body(req)
        name = body.get("name")
        if name is not None and (not isinstance(name, str) or len(name) > 64):
            raise HTTPException(422, "Name ungültig (max. 64 Zeichen)")
        name = (name or "").strip() or None
        if not await run_in_threadpool(store.rename_device, req.path_params["device_id"], name):
            raise HTTPException(404, "Gerät nicht gefunden")
        return JSONResponse({"ok": True})

    async def merge(req: Request):
        body = await _json_body(req)
        target = body.get("target_id")
        if not isinstance(target, int) or isinstance(target, bool):
            raise HTTPException(422, "target_id fehlt")
        if not await run_in_threadpool(store.merge_devices, req.path_params["device_id"], target):
            raise HTTPException(400, "Zusammenführung nicht möglich")
        return JSONResponse({"ok": True})

    async def unmerge(req: Request):
        if not await run_in_threadpool(store.unmerge_device, req.path_params["device_id"]):
            raise HTTPException(400, "Gerät ist nicht zusammengeführt")
        return JSONResponse({"ok": True})

    async def stream(req: Request):
        q = hub.subscribe()

        async def gen():
            try:
                yield "retry: 5000\n\n"
                while True:
                    if await req.is_disconnected():
                        break
                    try:
                        row = await asyncio.wait_for(q.get(), timeout=15)
                        yield f"id: {row['id']}\nevent: dns\ndata: {json.dumps(row, separators=(',', ':'))}\n\n"
                    except asyncio.TimeoutError:
                        yield "event: ping\ndata: {}\n\n"  # sichtbar für JS-Watchdog
            finally:
                hub.unsubscribe(q)

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    # ------------------------------------------------------------ DNS-Filter
    def _svc() -> DnsFilterService:
        if dnsfilter is None:
            raise HTTPException(503, "DNS-Filterverwaltung nicht verfügbar")
        return dnsfilter

    async def _run(fn, *args):
        svc = _svc()
        try:
            await run_in_threadpool(fn, *args)
        except FilterError as exc:
            raise HTTPException(exc.status, str(exc)) from None
        except FritzError as exc:
            raise HTTPException(502, str(exc)) from None
        return JSONResponse(await run_in_threadpool(svc.state, 60))  # Cache ist durch Verifikation frisch

    async def df_state(req: Request):
        svc = _svc()
        max_age = 0.0 if req.query_params.get("fresh") == "1" else 20.0
        return JSONResponse(await run_in_threadpool(svc.state, max_age))

    async def df_add(req: Request):
        b = await _json_body(req)
        return await _run(_svc().add_domain, b.get("domain"), b.get("action"), b.get("comment", ""))

    async def df_edit(req: Request):
        b = await _json_body(req)
        return await _run(_svc().edit_domain, req.path_params["uid"], b.get("domain"), b.get("action"),
                          b.get("comment"))

    async def df_delete(req: Request):
        return await _run(_svc().delete_domain, req.path_params["uid"])

    async def df_enabled(req: Request):
        b = await _json_body(req)
        if not isinstance(b.get("enabled"), bool):
            raise HTTPException(422, "'enabled' (true/false) fehlt")
        return await _run(_svc().set_enabled, b["enabled"])

    async def df_pause(req: Request):
        b = await _json_body(req)
        return await _run(_svc().pause_for, b.get("minutes"))

    async def df_resume(req: Request):
        return await _run(_svc().resume_now)

    # ------------------------------------------------------------ Filterlisten
    def _bool_or_none(b: dict, key: str):
        v = b.get(key)
        if v is not None and not isinstance(v, bool):
            raise HTTPException(422, f"'{key}' muss true/false sein")
        return v

    async def fl_add(req: Request):
        b = await _json_body(req)
        enabled = _bool_or_none(b, "enabled")
        return await _run(_svc().add_list, b.get("name"), b.get("url"), True if enabled is None else enabled)

    async def fl_edit(req: Request):
        b = await _json_body(req)
        return await _run(_svc().edit_list, req.path_params["uid"], b.get("name"), b.get("url"),
                          _bool_or_none(b, "enabled"))

    async def fl_delete(req: Request):
        return await _run(_svc().delete_list, req.path_params["uid"])

    async def fl_update(req: Request):
        return await _run(_svc().trigger_update)

    async def fl_auto(req: Request):
        b = await _json_body(req)
        preset = b.get("preset")
        if not isinstance(preset, str):
            raise HTTPException(422, "'preset' fehlt (8h, daily, weekly, monthly, never)")
        return await _run(_svc().set_auto_update, preset)

    async def http_error(req: Request, exc: HTTPException):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    routes = [
        Route("/", index), Route("/index.html", index),
        Mount("/static", StaticFiles(directory=STATIC), name="static"),
        Route("/api/health", health), Route("/api/status", status),
        Route("/api/summary", summary), Route("/api/timeline", timeline), Route("/api/events", events),
        Route("/api/top/domains", top_domains), Route("/api/top/devices", top_devices),
        Route("/api/devices", devices),
        Route("/api/devices/{device_id:int}", rename, methods=["PUT"]),
        Route("/api/devices/{device_id:int}/merge", merge, methods=["POST"]),
        Route("/api/devices/{device_id:int}/unmerge", unmerge, methods=["POST"]),
        Route("/api/stream", stream),
        Route("/api/dnsfilter", df_state),
        Route("/api/dnsfilter/domains", df_add, methods=["POST"]),
        Route("/api/dnsfilter/domains/{uid}", df_edit, methods=["PUT"]),
        Route("/api/dnsfilter/domains/{uid}", df_delete, methods=["DELETE"]),
        Route("/api/dnsfilter/enabled", df_enabled, methods=["PUT"]),
        Route("/api/dnsfilter/pause", df_pause, methods=["POST"]),
        Route("/api/dnsfilter/resume", df_resume, methods=["POST"]),
        Route("/api/dnsfilter/filterlists", fl_add, methods=["POST"]),
        Route("/api/dnsfilter/filterlists/{uid}", fl_edit, methods=["PUT"]),
        Route("/api/dnsfilter/filterlists/{uid}", fl_delete, methods=["DELETE"]),
        Route("/api/dnsfilter/update", fl_update, methods=["POST"]),
        Route("/api/dnsfilter/auto-update", fl_auto, methods=["PUT"]),
    ]
    return Starlette(routes=routes, lifespan=lifespan, exception_handlers={HTTPException: http_error},
                     middleware=[Middleware(IngressOnly, allow_all=allow_all)])
