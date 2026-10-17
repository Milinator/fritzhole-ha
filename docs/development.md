# Entwicklung

[← zurück zur README](../README.md)

Aufbau und Datenfluss der App: [architecture.md](architecture.md).

## Tests ausführen

Die Tests nutzen eine **simulierte FRITZ!Box** (HTTP-Server mit Login, Mitschnitt-Stream im AVM-PCAP-Format und
DNS-Filter-API), eine echte Box ist nicht nötig.

```bash
cd fritzhole
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest httpx
.venv/bin/python -m pytest -q
```

Abgedeckt sind u. a. DNS- und PCAP-Parser (IPv4/IPv6, VLAN, fehlerhafte und abgeschnittene Pakete), TCP-Reassemblierung,
Anfrage/Antwort-Korrelation, Datenbank, HTTP-API, Login (inkl. AVM-Referenzvektor), Capture mit Reconnect sowie
DNS-Filter-, Pausen- und Filterlisten-Funktionen.

## Lokal starten (ohne Home Assistant)

Nur für die Entwicklung – mit `FRITZHOLE_ALLOW_ALL=1` ist das Dashboard für jeden erreichbar, der den Port erreicht.

```bash
cd fritzhole/app
mkdir -p /tmp/fh
echo '{"fritzbox_host":"192.168.178.1","fritzbox_username":"fritzhole","fritzbox_password":"..."}' > /tmp/fh/options.json
FRITZHOLE_OPTIONS=/tmp/fh/options.json FRITZHOLE_DATA=/tmp/fh FRITZHOLE_ALLOW_ALL=1 ../.venv/bin/python -m fritzhole
# -> http://localhost:8099
```

| Umgebungsvariable | Bedeutung | Standard |
|---|---|---|
| `FRITZHOLE_OPTIONS` | Pfad zur Options-Datei | `/data/options.json` |
| `FRITZHOLE_DATA` | Verzeichnis für die Datenbank | `/data` |
| `FRITZHOLE_PORT` | HTTP-Port | `8099` |
| `FRITZHOLE_ALLOW_ALL` | `1` = Zugriff nicht auf den Ingress-Proxy beschränken | – |

## Lokale Installation in Home Assistant (ohne GitHub)

Den Ordner `fritzhole/` per Samba/SSH nach `/addons/fritzhole` kopieren und im App-Store „Nach Updates suchen“
wählen – die App erscheint unter „Lokale Apps“. Nach Änderungen die Versionsnummer in `config.yaml` erhöhen und
aktualisieren (ohne neue Version: „Neu erstellen“).

## Neue Version veröffentlichen

1. `version` in `fritzhole/config.yaml` und `__version__` in `fritzhole/app/fritzhole/__init__.py` erhöhen.
2. Eintrag in `fritzhole/CHANGELOG.md` ergänzen.
3. Committen und pushen. Home Assistant liest die Version aus `config.yaml` im Branch `main` – GitHub-Releases sind
   dafür nicht nötig.
4. Optional: Tag (`git tag -a vX.Y.Z -m "FritzHole X.Y.Z"`, `git push origin vX.Y.Z`) und GitHub-Release mit dem
   Changelog-Abschnitt anlegen.

Der Image-Build läuft auf dem Home-Assistant-System selbst (kein vorgebautes Image). Basis ist
`ghcr.io/home-assistant/base:3.23`; seit Supervisor 2026.04 wird `BUILD_FROM` nicht mehr automatisch gesetzt,
deshalb steht das Basisimage fest im `Dockerfile`.

## Beitragen

- Fehler und Kompatibilitätsberichte bitte als [Issue](https://github.com/Milinator/fritzhole-ha/issues).
- Pull Requests sind willkommen; bitte mit Tests und ohne neue native Abhängigkeiten (Build unter Alpine/musl auf
  amd64 und aarch64).
- Keine echten Zugangsdaten, Session-IDs oder DNS-Protokolle in Issues, Tests oder Commits.
