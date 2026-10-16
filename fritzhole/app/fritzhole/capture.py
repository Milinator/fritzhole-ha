"""Long-running capture service (one capture session at a time)."""
from __future__ import annotations

import http.client
import logging
import threading
import time
import xml.etree.ElementTree as ET
from typing import Callable

from .fritzbox import AuthError, FritzBox, FritzError
from .pcap import PcapError, PcapReader
from .processor import DnsEvent, Processor

log = logging.getLogger(__name__)

IDLE_TIMEOUT = 900.0      # ohne Daten -> Reconnect (nachts kann DNS still sein)
BACKOFF_MIN = 5.0
BACKOFF_MAX = 300.0
AUTH_BACKOFF = 300.0
HEALTHY_AFTER = 60.0
EXPIRE_EVERY = 1.0

KNOWN_LINKTYPES = {1, 12, 14, 101, 113, 228, 229, 276, 2048}

_active_lock = threading.Lock()  # prozessweit: nie zwei Capture-Sessions


class CaptureService:
    def __init__(self, fritz: FritzBox, iface: str, sink: Callable[[list[DnsEvent]], None],
                 tcp_enabled: bool = True, debug: bool = False):
        self.fritz = fritz
        self.iface = iface
        self.sink = sink
        self.tcp_enabled = tcp_enabled
        self.debug = debug
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.state = "stopped"
        self.last_error: str | None = None
        self.linktype: int | None = None
        self.variant: str | None = None
        self.connected_since: float | None = None
        self.next_retry: float | None = None
        self.sessions = 0
        self.totals: dict[str, int] = {}
        self._proc: Processor | None = None

    # ---------------------------------------------------------------- control
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="capture", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        self.fritz.abort_capture()
        if self._thread:
            self._thread.join(timeout)
        self.state = "stopped"

    def status(self) -> dict:
        stats = dict(self.totals)
        if self._proc:
            for k, v in self._proc.stats.items():
                stats[k] = stats.get(k, 0) + v
            stats.update({f"tcp_{k}": v for k, v in self._proc.tcp.stats.items()})
        return {
            "state": self.state, "last_error": self.last_error, "linktype": self.linktype,
            "pcap_variant": self.variant, "connected_since": self.connected_since,
            "next_retry": self.next_retry, "sessions": self.sessions, "interface": self.iface,
            "tcp_dns": self.tcp_enabled, "stats": stats,
        }

    # ------------------------------------------------------------------- loop
    def _run(self) -> None:
        if not _active_lock.acquire(blocking=False):
            log.error("Es läuft bereits eine Capture-Session – zweite Session wird nicht gestartet")
            self.state = "error"
            return
        try:
            failures = 0
            while not self._stop.is_set():
                started = time.monotonic()
                delay = None
                try:
                    self._session()
                except AuthError as exc:
                    delay = max(AUTH_BACKOFF, float(exc.block_time))
                    self._fail("auth_error", str(exc))
                except (OSError, EOFError, PcapError, FritzError, http.client.HTTPException, ET.ParseError) as exc:
                    self._fail("backoff", _describe(exc))
                except Exception as exc:  # noqa: BLE001 – Dienst soll weiterlaufen
                    log.exception("Unerwarteter Fehler im Capture-Service")
                    self._fail("backoff", f"Interner Fehler: {type(exc).__name__}")
                if self._stop.is_set():
                    break
                failures = 0 if time.monotonic() - started > HEALTHY_AFTER else failures + 1
                if delay is None:
                    delay = min(BACKOFF_MAX, BACKOFF_MIN * (2 ** max(0, failures - 1))) if failures else BACKOFF_MIN
                self.next_retry = time.time() + delay
                log.info("Neuer Verbindungsversuch in %.0f s", delay)
                self._stop.wait(delay)
                self.next_retry = None
        finally:
            _active_lock.release()
            self.state = "stopped"

    def _fail(self, state: str, msg: str) -> None:
        self.state = state
        self.last_error = msg
        self.connected_since = None
        if not self._stop.is_set():
            log.warning("Capture: %s", msg)

    def _session(self) -> None:
        self.state = "connecting"
        log.info("Anmeldung an %s ...", self.fritz.base)
        sid = self.fritz.login()
        try:
            resp = self.fritz.open_capture(sid, self.iface, IDLE_TIMEOUT)
            try:
                reader = PcapReader(resp)
            except EOFError:
                raise FritzError("FRITZ!Box liefert HTTP 200, aber keine Mitschnittdaten – läuft parallel "
                                 "ein anderer Mitschnitt (z. B. im Browser)?") from None
            self.linktype, self.variant = reader.linktype, reader.variant
            if reader.linktype not in KNOWN_LINKTYPES:
                log.warning("Unbekannter Linktype %s – Frames werden heuristisch dekodiert", reader.linktype)
            self._absorb_stats()
            self._proc = proc = Processor(reader.linktype, self.tcp_enabled)
            self.sessions += 1
            self.state = "running"
            self.last_error = None
            self.connected_since = time.time()
            log.info("Mitschnitt aktiv (Interface %s, Linktype %s, Format %s)",
                     self.iface, reader.linktype, reader.variant)
            next_expire = time.monotonic() + EXPIRE_EVERY
            dumped = 0
            for rec in reader:
                if self.debug and dumped < 3:
                    log.debug("Frame %d: %d/%d Byte, ifindex=%s, Kopf=%s", dumped, len(rec.data),
                              rec.orig_len, rec.ifindex, rec.data[:48].hex())
                    dumped += 1
                events = proc.feed(rec)
                if time.monotonic() >= next_expire:
                    events += proc.expire()
                    next_expire = time.monotonic() + EXPIRE_EVERY
                if events:
                    self.sink(events)
                if self._stop.is_set():
                    break
            if not self._stop.is_set():
                raise EOFError("FRITZ!Box hat den Mitschnitt-Stream beendet")
        finally:
            self.fritz.abort_capture()
            self.fritz.stop_capture(sid, self.iface)
            self.fritz.logout(sid)
            if self._proc:
                self._proc.flush()

    def _absorb_stats(self) -> None:
        if self._proc:
            for k, v in self._proc.stats.items():
                self.totals[k] = self.totals.get(k, 0) + v
            self._proc = None


def _describe(exc: Exception) -> str:
    if isinstance(exc, TimeoutError) or "timed out" in str(exc):
        return "Zeitüberschreitung (keine Daten von der FRITZ!Box)"
    if isinstance(exc, ConnectionRefusedError):
        return "Verbindung abgelehnt – Host/IP prüfen"
    if isinstance(exc, EOFError):
        return str(exc)
    return f"{type(exc).__name__}: {exc}"
