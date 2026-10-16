# FritzHole – Home-Assistant-App

Pi-hole-ähnliches Dashboard und Verwaltung für die integrierte DNS-Filterung der FRITZ!Box.
Läuft als App (ehemals Add-on) unter Home Assistant OS, öffnet sich über die Seitenleiste (Ingress)
und speichert alles lokal.

- Live-DNS-Protokoll über den Paketmitschnitt der FRITZ!Box (blockierte Anfragen erkennbar an `0.0.0.0` / `::`)
- Auswertungen nach Domain, Gerät und Zeitraum
- Whitelist/Blacklist direkt aus dem Live-Protokoll pflegen, Filter ein/aus, befristete Pause
- Filterlisten verwalten, manuell oder automatisch aktualisieren

**Voraussetzung für die DNS-Filter-Funktionen:** FRITZ!OS mit integriertem DNS-Filter – eingeführt mit
FRITZ!OS 8.50 bzw. den zugehörigen Laborversionen. Entwickelt und getestet mit FRITZ!Box 7530 AX und der
Laborversion **FRITZ!OS 8.40-136793 BETA**. Ob sich die Release-Version 8.50 identisch verhält, ist nicht geprüft.
Die Verwaltung nutzt eine **inoffizielle Beta-API** (`/api/v0/beta/dnsfilter`), die AVM jederzeit ändern kann.
Ohne DNS-Filter in der FRITZ!Box zeigt der Tab „DNS-Filter“ eine Fehlermeldung; Live-Protokoll und Auswertungen
(Paketmitschnitt) funktionieren unabhängig davon.

> [!IMPORTANT]
> **Inoffizielles Privatprojekt – nicht von AVM.**
> FritzHole wird von einer Privatperson in der Freizeit entwickelt. Es besteht **keine Verbindung** zur
> AVM GmbH bzw. FRITZ! GmbH: kein offizielles Produkt, keine Kooperation, keine Unterstützung oder Freigabe durch AVM.
> Bitte wende dich bei Fragen oder Problemen mit FritzHole **nicht an den AVM-Support**, sondern nutze die
> [Issues](https://github.com/Milinator/fritzhole-ha/issues) dieses Repositories.
>
> *Unofficial hobby project. Not affiliated with, endorsed by or supported by AVM / FRITZ! GmbH.*

## Installation

1. Home Assistant → **Einstellungen → Apps → App-Store** → Menü (⋮) → **Repositories** →
   `https://github.com/Milinator/fritzhole-ha` hinzufügen.
2. **FritzHole** auswählen → **Installieren**. Das Image wird lokal auf dem Home-Assistant-System gebaut
   (kein vorgebautes Image, daher dauert der erste Build einige Minuten).
3. Tab **Konfiguration**: FRITZ!Box-Adresse, Benutzer, Passwort eintragen → speichern.
4. **Starten**, „Beim Start ausführen“ und „In Seitenleiste anzeigen“ aktivieren.

Voraussetzungen an der FRITZ!Box, Optionen, Grenzen und Datenschutz: [`fritzhole/DOCS.md`](fritzhole/DOCS.md).

## Aufbau

```
repository.yaml              Repository-Metadaten
fritzhole/
  config.yaml                App-Metadaten, Optionen, Ingress
  Dockerfile                 Alpine-Basis (ghcr.io/home-assistant/base:3.23), Python-venv
  requirements.txt           starlette, uvicorn (reine Python-Pakete)
  DOCS.md / CHANGELOG.md     Doku im App-Store
  icon.png / logo.png
  translations/              Beschriftung der Optionen (de/en)
  app/fritzhole/
    fritzbox.py              Login (PBKDF2/MD5), Capture-Start/-Stop, TR-064-Hostliste, REST-Session
    pcap.py                  Stream-PCAP-Reader inkl. AVM/Kuznetsov-Format (24-Byte-Record-Header)
    netparse.py              Ethernet/VLAN/IPv4/IPv6/UDP/TCP
    dnsparse.py              DNS-Parser + Klassifizierung
    tcpreasm.py              DNS-over-TCP-Reassemblierung
    dnsfilter.py             DNS-Filter-Verwaltung (Beta-API), Verifikation, Pause/Reaktivierung
    filterlists.py           Filterlisten, manuelle/automatische Aktualisierung, Statusauswertung
    processor.py             Korrelation Anfrage/Antwort, Duplikate, Timeouts
    capture.py               Capture-Dienst (eine Session, Reconnect mit Backoff)
    db.py                    SQLite: Ereignisse, Geräte, Aggregationen, Bereinigung
    pipeline.py              Schreib-Thread, Live-Verteilung (SSE), Gerätenamen
    api.py                   HTTP-API + Dashboard (Starlette)
    static/                  Web-Oberfläche (ohne externe Abhängigkeiten)
  tests/                     pytest
```

## Tests lokal ausführen

```bash
cd fritzhole
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest httpx
.venv/bin/python -m pytest -q
```

Lokaler Start ohne Home Assistant (nur für Entwicklung, Zugriff von überall erlaubt):

```bash
cd fritzhole/app
echo '{"fritzbox_host":"192.168.178.1","fritzbox_username":"fritzhole","fritzbox_password":"..."}' > /tmp/fh/options.json
FRITZHOLE_OPTIONS=/tmp/fh/options.json FRITZHOLE_DATA=/tmp/fh FRITZHOLE_ALLOW_ALL=1 ../.venv/bin/python -m fritzhole
# -> http://localhost:8099
```

## Kritisches Detail aus dem PoC

Die Capture-URL muss mit `urllib.parse.urlencode(params, quote_via=urllib.parse.quote)` kodiert werden
(`filter=udp%20port%2053%20or%20tcp%20port%2053`). Mit `+` statt `%20` liefert FRITZ!OS keinen PCAP-Stream.
Abgesichert durch `tests/test_fritzbox_capture.py::test_capture_query_uses_percent20_not_plus`.

## Bekannte Einschränkungen

- Getestet nur mit FRITZ!Box 7530 AX / FRITZ!OS 8.40-136793 BETA (Labor). Andere Modelle/Versionen können abweichen
  (PCAP-Format, Beta-API).
- `capture=Stop` ist nicht offiziell dokumentiert; zusätzlich wird die HTTP-Verbindung geschlossen.
- SSE über Ingress: Fällt automatisch auf Polling (3 s) zurück, falls ein Proxy den Stream puffert.

## Haftungsausschluss und Marken

- FRITZ!, FRITZ!Box und FRITZ!OS sind Marken der AVM GmbH bzw. FRITZ! GmbH. Sie werden hier nur verwendet, um
  zu beschreiben, mit welchen Geräten FritzHole zusammenarbeitet. Name und Logo von FritzHole sind keine
  Produkte oder Logos von AVM.
- FritzHole nutzt **inoffizielle, undokumentierte Schnittstellen** von FRITZ!OS (u. a. eine Beta-API). Diese können
  sich mit jedem FRITZ!OS-Update ändern oder wegfallen.
- Die DNS-Filter-Verwaltung **ändert Einstellungen deiner FRITZ!Box** (Filter ein/aus, Ausnahmen, Filterlisten).
  Nutzung auf eigenes Risiko. Die Software wird ohne jede Gewährleistung bereitgestellt (siehe Lizenz).

## Lizenz

MIT – siehe [`LICENSE`](LICENSE).
