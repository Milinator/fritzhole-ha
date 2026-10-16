"""Entry point: python -m fritzhole"""
from __future__ import annotations

import logging
import os
import sys

import uvicorn

from . import __version__, config
from .api import create_app
from .capture import CaptureService
from .db import Store
from .dnsfilter import DnsFilterService
from .fritzbox import FritzBox, RestSession
from .pipeline import HostRefresher, LiveHub, Writer

log = logging.getLogger("fritzhole")


def build():
    cfg = config.load()
    config.setup_logging(cfg)
    log.info("FritzHole %s startet (Host %s, Interface %s, Aufbewahrung %d Tage)",
             __version__, cfg.fritzbox_host, cfg.capture_interface, cfg.retention_days)
    os.makedirs(os.path.dirname(cfg.db_path), exist_ok=True)
    store = Store(cfg.db_path)
    hub = LiveHub()
    writer = Writer(store, hub, cfg.retention_days, cfg.max_events)
    fritz = FritzBox(cfg.fritzbox_host, cfg.fritzbox_username, cfg.fritzbox_password)
    capture = CaptureService(fritz, cfg.capture_interface, writer.submit, cfg.tcp_dns, cfg.debug)
    hosts = HostRefresher(fritz, writer) if cfg.resolve_hostnames else None
    # Eigene REST-Session (gleiche Zugangsdaten/Login-Logik wie der Mitschnitt)
    rest = RestSession(fritz) if cfg.configured else None
    dnsfilter = DnsFilterService(rest, store, writable=cfg.dnsfilter_management)

    def startup():
        writer.start()
        if not cfg.configured:
            log.error("FRITZ!Box-Zugangsdaten fehlen – bitte in der App-Konfiguration eintragen. "
                      "Dashboard läuft, Mitschnitt ist inaktiv.")
            capture.state = "unconfigured"
            return
        capture.start()
        dnsfilter.start()  # prüft auch überfällige Reaktivierung nach Neustart
        if hosts:
            hosts.start()

    def shutdown():
        log.info("Beende FritzHole ...")
        if hosts:
            hosts.stop()
        dnsfilter.stop()
        capture.stop()
        if rest:
            rest.close()
        writer.stop()
        log.info("Beendet.")

    def status():
        st = {"capture": capture.status(), "config": cfg.public(),
              "writer": {"written": writer.written, "dropped": writer.dropped, "queue": writer.q.qsize(),
                         "last_cleanup": writer.last_cleanup}}
        if hosts:
            st["hostnames"] = {"state": hosts.state, "last_error": hosts.last_error,
                               "last_ok": hosts.last_ok, "count": hosts.count}
        return st

    return create_app(store, hub, status, (startup, shutdown), dnsfilter=dnsfilter), cfg


def main() -> int:
    try:
        app, _cfg = build()
    except (ValueError, OSError) as exc:
        logging.basicConfig()
        log.error("Start fehlgeschlagen: %s", exc)
        return 1
    port = int(os.environ.get("FRITZHOLE_PORT", "8099"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_config=None, access_log=False,
                proxy_headers=False, timeout_graceful_shutdown=5)
    return 0


if __name__ == "__main__":
    sys.exit(main())
