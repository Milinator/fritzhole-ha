# Architektur

[← zurück zur README](../README.md)

FritzHole ist eine Home-Assistant-App (ehemals Add-on) mit einem Python-Backend (Starlette/uvicorn) und einer
Web-Oberfläche ohne externe Abhängigkeiten. Sie läuft als ein Prozess in einem Container und wird über
Home-Assistant-Ingress bereitgestellt.

## Repository-Aufbau

```
repository.yaml              Repository-Metadaten für Home Assistant
README.md / README.en.md     Projektvorstellung (Deutsch / Englisch)
docs/                        Technische Dokumentation
fritzhole/
  config.yaml                App-Metadaten, Optionen, Ingress
  Dockerfile                 Alpine-Basis (ghcr.io/home-assistant/base:3.23), Python-venv
  requirements.txt           starlette, uvicorn (reine Python-Pakete)
  DOCS.md / CHANGELOG.md     Doku und Änderungen (in Home Assistant sichtbar)
  icon.png / logo.png        Icon und Logo für den App-Store
  translations/              Beschriftung der Optionen (de/en)
  app/fritzhole/
    fritzbox.py              Login (PBKDF2/MD5), Capture-Start/-Stop, TR-064-Hostliste, REST-Session
    pcap.py                  Stream-PCAP-Reader inkl. AVM/Kuznetsov-Format (24-Byte-Record-Header)
    netparse.py              Ethernet/VLAN/IPv4/IPv6/UDP/TCP
    dnsparse.py              DNS-Parser + Klassifizierung
    tcpreasm.py              DNS-over-TCP-Reassemblierung
    processor.py             Korrelation Anfrage/Antwort, Duplikate, Timeouts
    capture.py               Capture-Dienst (eine Session, Reconnect mit Backoff)
    dnsfilter.py             DNS-Filter-Verwaltung (Beta-API), Verifikation, Pause/Reaktivierung
    filterlists.py           Filterlisten, manuelle/automatische Aktualisierung, Statusauswertung
    db.py                    SQLite: Ereignisse, Geräte, Aggregationen, Bereinigung
    pipeline.py              Schreib-Thread, Live-Verteilung (SSE), Gerätenamen
    api.py                   HTTP-API + Dashboard (Starlette)
    config.py                Optionen aus /data/options.json, Logging mit Schwärzung
    static/                  Web-Oberfläche (HTML/CSS/JS)
  tests/                     pytest (inkl. simulierter FRITZ!Box)
```

## Datenfluss

```
FRITZ!Box ── /cgi-bin/capture_notimeout (PCAP-Stream) ──► capture.py
                                                            │ pcap.py → netparse.py → dnsparse.py / tcpreasm.py
                                                            ▼
                                                       processor.py  (Anfrage ↔ Antwort, Status, Duplikate)
                                                            │ DnsEvent
                                                            ▼
                                                       pipeline.Writer ──► db.py (SQLite /data/fritzhole.db)
                                                            │                      ▲
                                                            ▼                      │ Abfragen
                                                       LiveHub (SSE) ──► api.py ◄──┘ ◄── Browser (Ingress)

FRITZ!Box ── TR-064 Hosts:1 ──► pipeline.HostRefresher ──► Gerätenamen
FRITZ!Box ── /api/v0/beta/dnsfilter ◄──► dnsfilter.py / filterlists.py ◄──► api.py
```

## Komponenten

- **Capture-Dienst** (`capture.py`): Eigener Thread, genau eine Mitschnitt-Session. Meldet sich an, öffnet den
  PCAP-Stream, verarbeitet Pakete und baut die Verbindung bei Abbruch mit Backoff (5 s … 5 min) neu auf. Nach 15 min
  ohne Daten wird neu verbunden. Beim Beenden: Socket schließen, `capture=Stop`, Logout.
- **Processor** (`processor.py`): Ordnet Anfragen und Antworten über Client-IP/-Port, Server, Transaktions-ID,
  Domain, Typ und Transport zu. Unbeantwortete Anfragen werden nach 10 s als „Keine Antwort“ gewertet, doppelte
  Antworten innerhalb von 2 s verworfen.
- **Writer** (`pipeline.py`): Einziger Schreiber auf die Datenbank. Schreibt gebündelt (alle 0,5 s bzw. 500
  Ereignisse), verteilt neue Ereignisse an Live-Clients und führt stündlich die Bereinigung (`retention_days`,
  `max_events`) aus.
- **Datenbank** (`db.py`): SQLite im WAL-Modus mit Tabellen `events`, `devices`, `device_ips` und `meta`.
  Geräte werden über die MAC-Adresse gebildet, sonst über die IP. Der Zustand einer DNS-Filter-Pause liegt in `meta`.
- **DNS-Filter-Dienst** (`dnsfilter.py` + `filterlists.py`): Eigene REST-Session zur FRITZ!Box, Cache von 20 s,
  Schreiboperationen unter einer Sperre mit anschließender Verifikation. Ein Hintergrund-Thread übernimmt die
  zeitgesteuerte Wiedereinschaltung nach einer Pause.
- **HTTP-API** (`api.py`): Starlette-App, die nur Anfragen des Ingress-Proxys (`172.30.32.2`) annimmt. Schreibende
  Aufrufe erfordern den Header `X-FritzHole-Confirm: 1`. Details in [api.md](api.md).
- **Oberfläche** (`static/`): Ein HTML-Dokument mit relativen Pfaden (Ingress-tauglich). Live-Updates per
  Server-Sent Events, mit automatischem Wechsel auf Polling, falls ein Proxy den Stream puffert. JS/CSS werden mit
  Versionsparameter geladen, damit nach Updates keine veralteten Dateien aus dem Cache kommen.

## Bewusste Entscheidungen

- **Starlette statt FastAPI:** nur reine Python-Abhängigkeiten, damit der Image-Build unter Alpine/musl auf amd64 und
  aarch64 ohne Compiler funktioniert.
- **Kein s6-overlay:** `ENTRYPOINT []` und Docker-Init (`init: true`), damit SIGTERM direkt beim Python-Prozess
  ankommt und sauber heruntergefahren wird.
- **Keine Portfreigabe:** Zugriff ausschließlich über Ingress, Dashboard standardmäßig nur für Administratoren
  (`panel_admin`).
