# FritzHole

> **Inoffizielles Open-Source-Projekt – nicht von AVM.** Keine Verbindung zur AVM GmbH bzw. FRITZ! GmbH, kein Support
> durch AVM. Fragen und Fehler bitte über die [GitHub-Issues](https://github.com/Milinator/fritzhole-ha/issues)
> melden. FRITZ!, FRITZ!Box und FRITZ!OS sind Marken der AVM GmbH bzw. FRITZ! GmbH.

FritzHole zeigt, was die integrierte DNS-Filterung deiner FRITZ!Box blockiert – als Dashboard ähnlich Pi-hole,
direkt in der Home-Assistant-Seitenleiste – und verwaltet diesen DNS-Filter.

**Was FritzHole ist – und was nicht:**

- FritzHole ist **kein DNS-Server**. Die FRITZ!Box bleibt DNS-Server und filtert selbst; an den Geräten im Netz
  wird nichts umgestellt.
- Für das Live-Protokoll startet FritzHole über die FRITZ!Box-Oberfläche einen **Paketmitschnitt**
  (`/cgi-bin/capture_notimeout`, Filter `udp port 53 or tcp port 53`), wertet die DNS-Antworten aus und speichert
  sie lokal in SQLite unter `/data`.
- Über den Tab „DNS-Filter“ **ändert FritzHole Einstellungen der FRITZ!Box**: Ausnahmen, Filter ein/aus/Pause,
  Filterlisten und deren Aktualisierung. Das lässt sich mit `dnsfilter_management: false` abschalten
  (nur lesen). Andere Einstellungen der FRITZ!Box verändert FritzHole nicht.

## Voraussetzungen an der FRITZ!Box

1. **Benutzer mit Recht „FRITZ!Box Einstellungen“** – Paketmitschnitt und DNS-Filter-API sind nur damit erlaubt.
   Empfehlung: eigenen Benutzer `fritzhole` anlegen (System → FRITZ!Box-Benutzer), Zugang nur aus dem Heimnetz.
2. **Optional – Gerätenamen:** Heimnetz → Netzwerk → Netzwerkeinstellungen → „Zugriff für Anwendungen zulassen“
   (TR-064). Ohne diese Freigabe funktioniert alles, es fehlen nur die Gerätenamen.
3. **DNS-Filter** (z. B. HaGeZi-Blockliste) in der FRITZ!Box aktiv. Blockierte Domains beantwortet die Box mit
   `0.0.0.0` bzw. `::` – daran erkennt FritzHole die Blockierung. Den DNS-Filter gibt es ab FRITZ!OS 8.50 bzw. den
   zugehörigen Laborversionen; getestet mit FRITZ!Box 7530 AX und FRITZ!OS 8.40-136793 BETA (Labor).

## Konfiguration

| Option | Bedeutung |
|---|---|
| `fritzbox_host` | IP oder Hostname der Box, Standard `192.168.178.1` |
| `fritzbox_username` / `fritzbox_password` | Zugang (Passwort wird nie protokolliert oder per API ausgegeben) |
| `capture_interface` | Mitschnitt-Schnittstelle, Standard `1-lan` |
| `retention_days` | Aufbewahrung in Tagen (Standard 14), danach automatische Löschung |
| `max_events` | Harte Obergrenze für gespeicherte Ereignisse (Standard 2.000.000) |
| `resolve_hostnames` | Gerätenamen per TR-064 abrufen (alle 10 min) |
| `tcp_dns` | DNS über TCP auswerten (experimentell) |
| `dnsfilter_management` | Änderungen am FRITZ!Box-DNS-Filter aus dem Dashboard erlauben (aus = nur lesen) |
| `debug` | ausführliche Logs (ohne Zugangsdaten/SIDs) |

Nach dem Speichern die App neu starten. Fehlende Zugangsdaten werden im Dashboard als Hinweis angezeigt.

### Speicherbedarf

Jede DNS-Anfrage wird als einzelnes Ereignis gespeichert – in einer realen Installation gemessen rund 340 Byte pro
Ereignis (inklusive Indizes). Wie viel das ist, hängt stark vom Netz ab: Ein einzelnes Gerät, das ununterbrochen dieselben
Namen anfragt (z. B. ein Firmenrechner ohne Verbindung zu seinem Domänencontroller), kann Hunderttausende Anfragen
pro Tag erzeugen.

- Im Tab **Status** stehen Anzahl der Ereignisse und Größe der Datenbank, im Tab **Auswertungen** die aktivsten
  Geräte und Domains.
- Die Datei wird durch **beide** Grenzen gedeckelt – was zuerst greift: `retention_days` (Alter) und `max_events`
  (Anzahl). Beispiel: Bei rund 400.000 Anfragen pro Tag begrenzt `max_events: 500000` die Datenbank auf etwa
  1–1,5 Tage und rund 170 MB.
- Die Datenbank liegt unter `/data` und ist damit Teil jeder Home-Assistant-Sicherung.

## Funktionsweise und Grenzen

- **Status-Klassen:** `Blockiert` (0.0.0.0/::), `Erlaubt`, `NXDOMAIN`, `Fehler` (SERVFAIL, REFUSED …),
  `Keine Antwort` (Anfrage gesehen, nach 10 s keine Antwort).
- **Anfrage/Antwort-Korrelation** über Client-IP, Client-Port, Server, Transaktions-ID, Domain und Typ.
  Doppelt mitgeschnittene Antworten werden innerhalb von 2 s verworfen.
- **Nur was über die gewählte Schnittstelle läuft:** Geräte im Gastnetz oder Geräte, die DNS-over-HTTPS/TLS
  (z. B. Browser mit „sicherem DNS“) nutzen, tauchen nicht oder unvollständig auf.
- **Geräteerkennung:** Ist im Mitschnitt die Ziel-MAC vorhanden, werden IPv4- und IPv6-Adressen derselben MAC zu
  einem Gerät zusammengefasst. Nutzt eine MAC viele IPv4-Adressen (Router/Repeater mit MAC-NAT), wird sie als
  „geteilt“ markiert und ab dann pro IP getrennt. Ohne MAC wird **nie automatisch** zusammengeführt –
  das geht manuell im Tab „Geräte“.
- **TCP-DNS** wird nur ausgewertet, wenn der Verbindungsaufbau (SYN) im Mitschnitt war. Lücken oder
  abgeschnittene Segmente verwerfen den Flow, statt halbe Nachrichten zu interpretieren.
- **Ein Mitschnitt gleichzeitig:** Während FritzHole läuft, ist ein paralleler Mitschnitt in der FRITZ!Box-Oberfläche
  (z. B. per Browser) möglicherweise gestört – und umgekehrt [nicht abschließend getestet].
- **Wiederverbindung:** Bei Abbrüchen neuer Versuch mit Backoff (5 s … 5 min), nach fehlgeschlagener Anmeldung
  frühestens nach 5 min bzw. nach der von der Box gemeldeten Sperrzeit.

## DNS-Filter verwalten

FritzHole nutzt dafür eine **inoffizielle Beta-API** von FRITZ!OS (`/api/v0/beta/dnsfilter`, getestet mit
FRITZ!OS 8.40-136793 BETA). AVM kann sie mit jedem Update ändern oder entfernen – dann zeigt der Tab „DNS-Filter“ eine
Fehlermeldung, der Mitschnitt läuft unabhängig davon weiter.

- **Tab „DNS-Filter“:** Status, Hauptschalter, Allowlist/Blocklist (hinzufügen, bearbeiten, löschen),
  Filterlisten und die Statistik der FRITZ!Box.
- **Live-Protokoll / Auswertungen:** Über „⋯“ (oder Rechtsklick auf die Zeile) eine Domain erlauben/sperren,
  bestehende Einträge bearbeiten, verschieben oder entfernen. Vorhandene Einträge werden als Badge angezeigt;
  „≈“ kennzeichnet einen Eintrag auf einer übergeordneten Domain (ob die FRITZ!Box diesen auch auf Subdomains
  anwendet, ist nicht verifiziert).
- **Ausschalten wirkt netzweit:** Der DNS-Filter gilt für alle Geräte, die die FRITZ!Box als DNS-Server nutzen.
  Ausschalten oder Pausieren hebt die Filterung für das ganze Netz auf.
- **Pause:** 5/15/30/60 min oder eigene Dauer (1–1440 min). Der Zeitpunkt der Reaktivierung wird in der Datenbank
  unter `/data` gespeichert; nach einem Neustart wird eine überfällige Reaktivierung sofort ausgeführt.
  Schlägt sie fehl, wird mit wachsendem Abstand (30 s … 5 min) erneut versucht und der Fehler im Dashboard
  sowie im Log angezeigt. „Dauerhaft ausschalten“ über den Hauptschalter beendet eine Pause ohne Reaktivierung.
- **Filterlisten:** im selben Tab unter „Filterlisten“. Name/URL (nur HTTPS, ohne Zugangsdaten) bearbeiten,
  Liste per Schalter aktivieren/deaktivieren, löschen (mit Bestätigung), alle Listen manuell aktualisieren und die
  automatische Aktualisierung in den FRITZ!Box-Stufen (alle 8 Stunden, täglich, wöchentlich, monatlich, nie)
  einstellen. Doppelte Namen oder URLs werden abgelehnt. Fehler der FRITZ!Box (z. B. Fehlercode 3643,
  `isReady = false`, 0 Einträge) erscheinen direkt an der Liste. Die Fortschrittsanzeige der manuellen
  Aktualisierung meldet „erfolgreich“ erst, wenn jede aktive Liste ein neues, fehlerfreies Update gemeldet hat;
  ohne Rückmeldung nach 10 min erscheint ein Hinweis.
- **Sicherheit:** Jede Änderung braucht eine Bestätigung im Dialog; die API akzeptiert schreibende Aufrufe nur mit
  einem speziellen Header (Schutz vor Fehlklicks/CSRF). Nach jedem Schreiben wird erneut ausgelesen und geprüft.
  Beim Umschalten bleibt `automaticUpdate` unverändert, beim Ändern der automatischen Aktualisierung der
  Hauptschalter. Session-IDs und Passwort erscheinen nie in Logs oder API-Antworten.

## Datenschutz

DNS-Protokolle zeigen, welche Dienste ein Gerät nutzt, und sind bei Zuordnung zu Personen **personenbezogene Daten**
(Art. 4 DSGVO). Informiere Mitbewohner/Familie, halte die Aufbewahrung kurz, protokolliere keine Geräte, deren Daten
dir nicht zustehen (z. B. Dienstrechner), und gib das Dashboard nur Administratoren frei (Standard: `panel_admin`).
FritzHole sendet keine Daten an externe Dienste; der Zugriff erfolgt ausschließlich über Home-Assistant-Ingress.
Hinweis: Die Kommunikation zur FRITZ!Box läuft im LAN per HTTP; das Passwort wird dabei nicht im Klartext übertragen
(Challenge-Response/PBKDF2 bzw. HTTP-Digest), die Session-ID jedoch schon. Keine Rechtsberatung.

## Fehlersuche

| Meldung | Ursache |
|---|---|
| „Anmeldung fehlgeschlagen“ | Benutzer/Passwort falsch oder Recht „FRITZ!Box Einstellungen“ fehlt |
| „FRITZ!Box sperrt Anmeldungen noch … s“ | Zu viele Fehlversuche – Box-Sperre abwarten |
| „FRITZ!Box hat den Mitschnitt-Stream beendet“ | Box hat den Mitschnitt beendet (z. B. Neustart, paralleler Mitschnitt) |
| „FRITZ!Box liefert HTTP 200, aber keine Mitschnittdaten“ | Vermutlich läuft parallel ein anderer Mitschnitt (z. B. im Browser) |
| „Zeitüberschreitung“ | 15 min keine DNS-Pakete – Verbindung wird neu aufgebaut |
| „DNS-Filter-API nicht gefunden“ / Fehler im Tab „DNS-Filter“ | FRITZ!OS ohne integrierten DNS-Filter oder geänderte Beta-API |
| „Keine Berechtigung für die DNS-Filter-API“ | Recht „FRITZ!Box Einstellungen“ fehlt |
| Gerätenamen fehlen | TR-064 „Zugriff für Anwendungen“ deaktiviert |
| Dashboard zeigt nach einem Update Fehler | Seite neu laden; in der Companion-App ggf. Frontend-Cache zurücksetzen |

Der Tab **Status** zeigt Linktype, PCAP-Format und Zähler für fehlerhafte, abgeschnittene oder doppelte Pakete.
Mit `debug: true` werden zusätzlich die ersten Frames als Hex-Kopf protokolliert (hilfreich bei neuen FRITZ!OS-Versionen).

Weitere technische Details: [docs/ im GitHub-Repository](https://github.com/Milinator/fritzhole-ha/tree/main/docs).
