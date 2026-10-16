"""App options (/data/options.json, written by the Supervisor) and logging setup."""
from __future__ import annotations

import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field

OPTIONS_PATH = os.environ.get("FRITZHOLE_OPTIONS", "/data/options.json")
DATA_DIR = os.environ.get("FRITZHOLE_DATA", "/data")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")


@dataclass
class Config:
    fritzbox_host: str = "192.168.178.1"
    fritzbox_username: str = ""
    fritzbox_password: str = field(default="", repr=False)
    capture_interface: str = "1-lan"
    retention_days: int = 14
    max_events: int = 2_000_000
    resolve_hostnames: bool = True
    tcp_dns: bool = True
    dnsfilter_management: bool = True
    debug: bool = False

    @property
    def configured(self) -> bool:
        return bool(self.fritzbox_host and self.fritzbox_password)

    @property
    def db_path(self) -> str:
        return os.path.join(DATA_DIR, "fritzhole.db")

    def public(self) -> dict:
        """Safe view for the API – never contains the password."""
        return {
            "fritzbox_host": self.fritzbox_host, "fritzbox_username": self.fritzbox_username,
            "capture_interface": self.capture_interface, "retention_days": self.retention_days,
            "max_events": self.max_events, "resolve_hostnames": self.resolve_hostnames,
            "tcp_dns": self.tcp_dns, "dnsfilter_management": self.dnsfilter_management, "debug": self.debug, "password_set": bool(self.fritzbox_password),
        }


def load(path: str = OPTIONS_PATH) -> Config:
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        logging.getLogger(__name__).warning("%s nicht gefunden – Standardwerte aktiv", path)
        raw = {}
    cfg = Config()
    for key in cfg.__dataclass_fields__:
        if key in raw and raw[key] is not None:
            setattr(cfg, key, raw[key])
    cfg.fritzbox_host = str(cfg.fritzbox_host).strip()
    cfg.fritzbox_username = str(cfg.fritzbox_username or "").strip()
    cfg.retention_days = max(1, min(int(cfg.retention_days), 365))
    cfg.max_events = max(10_000, int(cfg.max_events))
    if not IFACE_RE.match(str(cfg.capture_interface)):
        raise ValueError("capture_interface enthält ungültige Zeichen")
    return cfg


class RedactFilter(logging.Filter):
    """Removes SIDs and password-like values from log output."""

    PATTERNS = [
        (re.compile(r"(sid=)[0-9a-fA-F]{16}"), r"\1***"),
        (re.compile(r"(response=)[^&\s]+"), r"\1***"),
        (re.compile(r"(<SID>)[0-9a-fA-F]{16}"), r"\1***"),
        (re.compile(r"(AVM-SID )[0-9a-fA-F]{16}"), r"\1***"),
    ]

    def __init__(self, secrets: list[str] | None = None):
        super().__init__()
        self.secrets = [s for s in (secrets or []) if s and len(s) >= 3]

    def _clean(self, text: str) -> str:
        for pat, repl in self.PATTERNS:
            text = pat.sub(repl, text)
        for s in self.secrets:
            text = text.replace(s, "***")
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        clean = self._clean(msg)
        if clean != msg:
            record.msg, record.args = clean, None
        if record.exc_info and record.exc_info[1] is not None:
            record.exc_text = self._clean(logging.Formatter().formatException(record.exc_info))
        return True


def setup_logging(cfg: Config) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s [%(name)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
    handler.addFilter(RedactFilter([cfg.fritzbox_password]))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.DEBUG if cfg.debug else logging.INFO)
    for noisy in ("uvicorn.access", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
