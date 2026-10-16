"""Glue: event queue -> SQLite writer, live fan-out, host-name refresh, retention."""
from __future__ import annotations

import asyncio
import logging
import queue
import threading
import time

from .db import Store
from .processor import DnsEvent

log = logging.getLogger(__name__)

QUEUE_MAX = 20_000
BATCH_MAX = 500
FLUSH_INTERVAL = 0.5
CLEANUP_INTERVAL = 3600.0
HOSTS_INTERVAL = 600.0
HOSTS_RETRY = 1800.0


class LiveHub:
    """Thread-safe fan-out of new events to asyncio subscribers (SSE)."""

    def __init__(self):
        self._subs: set[tuple[asyncio.AbstractEventLoop, asyncio.Queue]] = set()
        self._lock = threading.Lock()

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        with self._lock:
            self._subs.add((asyncio.get_running_loop(), q))
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        with self._lock:
            self._subs = {s for s in self._subs if s[1] is not q}

    @property
    def count(self) -> int:
        return len(self._subs)

    def publish(self, rows: list[dict]) -> None:
        with self._lock:
            subs = list(self._subs)
        for loop, q in subs:
            for row in rows:
                try:
                    loop.call_soon_threadsafe(_put, q, row)
                except RuntimeError:  # Loop beendet
                    self.unsubscribe(q)
                    break


def _put(q: asyncio.Queue, row: dict) -> None:
    try:
        q.put_nowait(row)
    except asyncio.QueueFull:
        pass  # langsamer Client: Live-Ansicht lädt per Polling nach


class Writer:
    """Single SQLite writer thread. Also runs retention cleanup and host-name updates."""

    def __init__(self, store: Store, hub: LiveHub, retention_days: int, max_events: int):
        self.store = store
        self.hub = hub
        self.retention_days = retention_days
        self.max_events = max_events
        self.q: queue.Queue = queue.Queue(maxsize=QUEUE_MAX)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="db-writer", daemon=True)
        self._hosts = None
        self._hosts_lock = threading.Lock()
        self.dropped = 0
        self.written = 0
        self.last_cleanup: float | None = None

    def start(self) -> None:
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        self._thread.join(timeout)

    def submit(self, events: list[DnsEvent]) -> None:
        for ev in events:
            try:
                self.q.put_nowait(ev)
            except queue.Full:
                self.dropped += 1
                if self.dropped % 1000 == 1:
                    log.warning("Schreib-Warteschlange voll – %d Ereignisse verworfen", self.dropped)

    def submit_hosts(self, hosts) -> None:
        with self._hosts_lock:
            self._hosts = hosts

    def _run(self) -> None:
        next_cleanup = time.monotonic() + 30
        while True:
            batch: list[DnsEvent] = []
            deadline = time.monotonic() + FLUSH_INTERVAL
            while len(batch) < BATCH_MAX:
                timeout = deadline - time.monotonic()
                if timeout <= 0:
                    break
                try:
                    batch.append(self.q.get(timeout=timeout))
                except queue.Empty:
                    break
            try:
                if batch:
                    ids = self.store.insert_events(batch)
                    self.written += len(ids)
                    if self.hub.count:
                        self.hub.publish(self.store.events_by_id(ids))
                with self._hosts_lock:
                    hosts, self._hosts = self._hosts, None
                if hosts is not None:
                    n = self.store.apply_host_list(hosts)
                    log.debug("Gerätenamen aktualisiert: %d", n)
                if time.monotonic() >= next_cleanup:
                    removed = self.store.cleanup(self.retention_days, self.max_events)
                    self.last_cleanup = time.time()
                    if removed:
                        log.info("Bereinigung: %d alte Ereignisse gelöscht", removed)
                    next_cleanup = time.monotonic() + CLEANUP_INTERVAL
            except Exception:  # noqa: BLE001
                log.exception("Datenbankfehler im Writer")
                time.sleep(1)
            if self._stop.is_set() and self.q.empty():
                break
        self.store.close()


class HostRefresher:
    """Periodically fetch device names from the FRITZ!Box (TR-064)."""

    def __init__(self, fritz, writer: Writer):
        self.fritz = fritz
        self.writer = writer
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="hosts", daemon=True)
        self.state = "idle"
        self.last_error: str | None = None
        self.last_ok: float | None = None
        self.count = 0

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        warned = False
        while not self._stop.is_set():
            try:
                hosts = self.fritz.host_list()
                self.count = len(hosts)
                self.writer.submit_hosts(hosts)
                self.state, self.last_error, self.last_ok = "ok", None, time.time()
                warned = False
                delay = HOSTS_INTERVAL
            except Exception as exc:  # noqa: BLE001
                self.state = "error"
                self.last_error = f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}"
                if not warned:
                    log.warning("Gerätenamen (TR-064) nicht abrufbar: %s – 'Zugriff für Anwendungen' "
                                "in der FRITZ!Box aktiv? Neuer Versuch in %d min",
                                self.last_error, HOSTS_RETRY // 60)
                    warned = True
                delay = HOSTS_RETRY
            self._stop.wait(delay)
