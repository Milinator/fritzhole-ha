# Kommunikation mit der FRITZ!Box

[← zurück zur README](../README.md)

FritzHole nutzt drei Schnittstellen der FRITZ!Box. **Keine davon ist für diesen Zweck offiziell dokumentiert**;
alle Angaben stammen aus Beobachtung und Tests mit FRITZ!Box 7530 AX und FRITZ!OS 8.40-136793 BETA (Labor).

## Anmeldung (`login_sid.lua`)

- `GET /login_sid.lua?version=2` liefert eine Challenge. Bei `2$<iter1>$<salt1>$<iter2>$<salt2>` wird PBKDF2
  verwendet, sonst MD5.
- **PBKDF2-Antwort:** `<salt2>$<hash2>` mit
  `hash1 = PBKDF2-HMAC-SHA256(passwort, salt1, iter1)` und `hash2 = PBKDF2-HMAC-SHA256(hash1, salt2, iter2)`
  (AVM Technical Note „Session ID“; abgesichert durch den Referenzvektor in den Tests).
  Achtung: `challenge + "$" + hash2` – wie in frühen Prototypen – wird abgelehnt.
- **MD5-Antwort:** `<challenge>-<md5(utf16le(challenge + "-" + passwort))>`.
- Eine `BlockTime > 0` (nach Fehlversuchen) wird respektiert: kein erneuter Versuch vor Ablauf.
- Mitschnitt, REST-API und Logout nutzen jeweils eigene Session-IDs.

## Paketmitschnitt (`/cgi-bin/capture_notimeout`)

- Start: `GET /cgi-bin/capture_notimeout?sid=…&capture=Start&snaplen=1600&filter=…&ifaceorminor=1-lan`
- Stopp: `…?sid=…&capture=Stop&ifaceorminor=1-lan` (nicht offiziell dokumentiert; zusätzlich wird die
  HTTP-Verbindung geschlossen).
- **Kritisch – URL-Kodierung:** Die Parameter müssen mit `urllib.parse.urlencode(params, quote_via=urllib.parse.quote)`
  kodiert werden (`filter=udp%20port%2053%20or%20tcp%20port%2053`). Mit `+` statt `%20` liefert FRITZ!OS keinen
  PCAP-Stream. Abgesichert durch `tests/test_fritzbox_capture.py::test_capture_query_uses_percent20_not_plus`.
- Liefert die Box HTTP 200 ohne Daten, läuft vermutlich bereits ein anderer Mitschnitt (z. B. im Browser).

### PCAP-Format

- Die FRITZ!Box liefert „modified pcap“ (Kuznetsov-Patch), Magic `0xa1b2cd34`. Jeder Record-Header ist **24 statt
  16 Byte** lang: `ts_sec, ts_usec, caplen, len, ifindex(4), protocol(2), pkt_type(1), pad(1)`.
  `pcap.py` entfernt die 8 Zusatzbytes sauber aus dem Header.
- Unterstützt werden außerdem Standard-PCAP (µs/ns, Little/Big Endian).
- Linktypes: Ethernet (1, inklusive Fallback für Frames mit 8-Byte-AVM-Präfix), Raw IP (12/14/101/228/229),
  Linux SLL/SLL2 (113/276) sowie AVM-Linktype 2048 (2-Byte-Präfix + Ethernet); unbekannte Linktypes werden
  heuristisch dekodiert.
- Ethernet-Padding wird anhand der IP-Länge abgeschnitten, VLAN-Tags (auch QinQ) werden übersprungen, IP-Fragmente
  ignoriert. IPv6-Extension-Header (Hop-by-Hop, Routing, Destination Options) werden ausgewertet.
- Mit `debug: true` protokolliert FritzHole die ersten drei Frames als Hex-Kopf – hilfreich, falls eine andere
  FRITZ!OS-Version ein abweichendes Format liefert.

### Blockierte Anfragen

Die FRITZ!Box beantwortet gefilterte Domains mit `NOERROR` und der Adresse `0.0.0.0` (A) bzw. `::` (AAAA). Daran
erkennt FritzHole den Status „Blockiert“ – auch hinter CNAME-Ketten.

### DNS über TCP

DNS-over-TCP wird reassembliert (RFC 1035 4.2.2 / RFC 7766), aber konservativ: nur Flows mit gesehenem SYN; bei
Lücken, Überlauf oder abgeschnittenen Segmenten wird der Flow verworfen.

## Geräteliste (TR-064)

- `POST http://<box>:49000/upnp/control/hosts`, Service `urn:dslforum-org:service:Hosts:1`, Aktion
  `X_AVM-DE_GetHostListPath`, HTTP-Digest-Authentifizierung. Die zurückgegebene XML-Liste enthält IP, MAC und
  Hostname.
- Voraussetzung: „Zugriff für Anwendungen zulassen“ in der FRITZ!Box. Abruf alle 10 min, nach Fehlern alle 30 min.

## DNS-Filter-API (Beta)

Basis: `/api/v0/beta/dnsfilter`. Header wie in der FRITZ!Box-Oberfläche: `Authorization: AVM-SID <sid>`,
`Client-Name: WebGUI`, `Accept: application/json`, bei Schreibzugriffen zusätzlich `Content-Type: application/json`
und `Origin`.

| Aktion | Aufruf | Body |
|---|---|---|
| Konfiguration lesen | `GET /api/v0/beta/dnsfilter` | – |
| Ausnahme anlegen | `POST …/domains` | `{enabled, domain, comment, action}` (`action`: `allow`/`deny`) |
| Ausnahme ändern | `PUT …/domains/<UID>` | `{domain, comment, action}` |
| Ausnahme löschen | `DELETE …/domains/<UID>` | – |
| Filter ein/aus | `PUT /api/v0/beta/dnsfilter` | `{enabled, automaticUpdate: {interval, enabled}}` |
| Filterliste anlegen | `POST …/filterlists` | `{enabled, name, url}` |
| Filterliste ändern | `PUT …/filterlists/<UID>` | `{enabled, name, url}` |
| Filterliste löschen | `DELETE …/filterlists/<UID>` | – |
| Alle Listen aktualisieren | `PUT /api/v0/beta/dnsfilter` | `{manualUpdate: {trigger: true}}` |
| Automatische Aktualisierung | `PUT /api/v0/beta/dnsfilter` | `{enabled: <unverändert>, automaticUpdate: {interval, enabled}}` |

Beobachtete Besonderheiten:

- **Abgelaufene Session** meldet FRITZ!OS als **HTTP 400** mit `[{"message": "permission denied: …", "code": 3001}]`
  statt 401/403. FritzHole meldet sich dann genau einmal neu an.
- **Stufen der automatischen Aktualisierung** (wie in der FRITZ!Box-Oberfläche): alle 8 Stunden = `28800`,
  täglich = `86400`, wöchentlich = `604800`, monatlich = `2592000` Sekunden, „nie“ = `enabled: false, interval: 0`.
- Beim Umschalten des Filters muss `automaticUpdate` unverändert mitgeschickt werden, beim Ändern der automatischen
  Aktualisierung der aktuelle Hauptschalter (`enabled`).
- Pro Filterliste liefert die Box u. a. `status.isReady`, `status.entryCount`, `status.lastSuccessfulUpdateTimestamp`
  sowie `latestUpdate.status`, `.timestamp`, `.cause` und `.error.code/.message` (z. B. Fehlercode `3643` bei einer
  nicht ladbaren Liste). Als `latestUpdate.status` ist bisher nur `error` sicher beobachtet; weitere Werte wertet
  FritzHole tolerant aus und zeigt unbekannte Werte unverändert an.
- Die Statistik steht unter `statistics.dnsQueryCount.total` und `.blocked`.

Nach jeder Schreiboperation liest FritzHole die Konfiguration erneut aus und prüft, ob die Änderung angekommen ist.
