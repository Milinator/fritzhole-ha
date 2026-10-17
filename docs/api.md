# HTTP-API des Dashboards

[← zurück zur README](../README.md)

Die API dient der Web-Oberfläche. Sie ist **nur über Home-Assistant-Ingress** erreichbar (Anfragen werden nur vom
Ingress-Proxy `172.30.32.2` angenommen) und nicht als stabile öffentliche Schnittstelle gedacht – sie kann sich
zwischen Versionen ändern.

## Allgemein

- Antworten sind JSON. Fehler: `{"detail": "<Meldung>"}` mit passendem HTTP-Status (400, 403, 404, 409, 422, 502, 503).
- **Schreibende Aufrufe** (`POST`, `PUT`, `DELETE`) erfordern den Header `X-FritzHole-Confirm: 1`, sonst HTTP 403
  (Schutz gegen CSRF und versehentliche Aufrufe).
- Zeitangaben sind Unix-Sekunden.

### Gemeinsame Filterparameter

Gelten für `summary`, `timeline`, `events`, `top/domains`, `top/devices`:

| Parameter | Bedeutung |
|---|---|
| `from_ts`, `to_ts` | Zeitraum |
| `status` | kommagetrennt: `allowed`, `blocked`, `nxdomain`, `error`, `no_answer` |
| `device_id` | Gerät |
| `client_ip` | Client-IP |
| `domain` | exakte Domain |
| `q` | Suche in Domain und Client-IP (max. 100 Zeichen) |

## Monitoring

| Methode | Pfad | Beschreibung |
|---|---|---|
| GET | `/api/health` | Lebenszeichen, Version |
| GET | `/api/status` | Zustand von Mitschnitt, Datenbank, Writer, Gerätenamen, Konfiguration (ohne Passwort) |
| GET | `/api/summary` | Summen nach Status, Blockierungsrate, Anzahl Geräte/Domains |
| GET | `/api/timeline` | Verlauf; optional `bucket` (60–86400 s) |
| GET | `/api/events` | Ereignisse; `limit` (1–1000), `before_id`, `after_id` |
| GET | `/api/top/domains` | Top-Domains; `limit` (1–200) |
| GET | `/api/top/devices` | Top-Geräte mit Blockierungsrate; `limit` (1–200) |
| GET | `/api/stream` | Server-Sent Events: `dns` (neues Ereignis), `ping` (alle 15 s) |

## Geräte

| Methode | Pfad | Body |
|---|---|---|
| GET | `/api/devices` | – |
| PUT | `/api/devices/{id}` | `{"name": "…"}` (max. 64 Zeichen, leer = zurücksetzen) |
| POST | `/api/devices/{id}/merge` | `{"target_id": <id>}` |
| POST | `/api/devices/{id}/unmerge` | – |

## DNS-Filter

Alle schreibenden Aufrufe liefern den aktualisierten Zustand (wie `GET /api/dnsfilter`) zurück.

| Methode | Pfad | Body |
|---|---|---|
| GET | `/api/dnsfilter` | – (Cache 20 s, `?fresh=1` erzwingt Neuladen) |
| POST | `/api/dnsfilter/domains` | `{"domain", "action": "allow"\|"deny", "comment"}` |
| PUT | `/api/dnsfilter/domains/{uid}` | `{"domain"?, "action"?, "comment"?}` |
| DELETE | `/api/dnsfilter/domains/{uid}` | – |
| PUT | `/api/dnsfilter/enabled` | `{"enabled": true\|false}` |
| POST | `/api/dnsfilter/pause` | `{"minutes": 1–1440}` |
| POST | `/api/dnsfilter/resume` | – |
| POST | `/api/dnsfilter/filterlists` | `{"name", "url" (https), "enabled"?}` |
| PUT | `/api/dnsfilter/filterlists/{uid}` | `{"name"?, "url"?, "enabled"?}` |
| DELETE | `/api/dnsfilter/filterlists/{uid}` | – |
| POST | `/api/dnsfilter/update` | – (manuelle Aktualisierung aller Listen anfordern) |
| PUT | `/api/dnsfilter/auto-update` | `{"preset": "8h"\|"daily"\|"weekly"\|"monthly"\|"never"}` |

Zusätzliche Felder in `GET /api/dnsfilter`: `available`, `writable`, `error`, `stale`, `pause` (inkl. `remaining`,
`attempts`, `last_error`), `filterlists_detail` (je Liste ausgewerteter Zustand), `manual_update` (Fortschritt:
`requested`, `running`, `success`, `error`, `unknown`, `timeout`), `auto_preset`, `server_time`.

Ist `dnsfilter_management: false` gesetzt, antworten alle schreibenden DNS-Filter-Aufrufe mit HTTP 403.
