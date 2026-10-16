# FritzHole

FritzHole zeigt, was die integrierte DNS-Filterung deiner FRITZ!Box blockiert – als Dashboard ähnlich Pi-hole,
direkt in der Home-Assistant-Seitenleiste.

FritzHole ist **kein DNS-Server** und ändert **nichts** an der FRITZ!Box-Konfiguration. Die App startet über die
FRITZ!Box-Oberfläche einen Paketmitschnitt (`/cgi-bin/capture_notimeout`, Filter `udp port 53 or tcp port 53`),
wertet die DNS-Antworten aus und speichert sie lokal in SQLite unter `/data`.

## Voraussetzungen an der FRITZ!Box

1. **Benutzer mit Recht „FRITZ!Box Einstellungen“** – der Paketmitschnitt ist nur damit erlaubt.
   Empfehlung: eigenen Benutzer `fritzhole` anlegen (System → FRITZ!Box-Benutzer), Zugang nur aus dem Heimnetz.
2. **Optional – Gerätenamen:** Heimnetz → Netzwerk → Netzwerkeinstellungen → „Zugriff für Anwendungen zulassen“
   (TR-064). Ohne diese Freigabe funktioniert alles, es fehlen nur die Gerätenamen.
3. DNS-Filter (z. B. HaGeZi-Blockliste) in der FRITZ!Box aktiv. Blockierte Domains beantwortet die Box mit
   `0.0.0.0` bzw. `::` – daran erkennt FritzHole die Blockierung.

## Konfiguration

| Option | Bedeutung |
|---|---|
| `fritzbox_host` | IP oder Hostname der Box, Standard `192.168.178.1` |
| `fritzbox_username` / `fritzbox_password` | Zugang (Passwort wird nie protokolliert oder per API ausgegeben) |
| `capture_interface` | Mitschnitt-Schnittstelle, Standard `1-lan` |
| `retention_days` | Aufbewahrung in Tagen (Standard 14), danach automatische Löschung |
| `max_events` | Harte Obergrenze für gespeicherte Ereignisse |
| `resolve_hostnames` | Gerätenamen per TR-064 abrufen (alle 10 min) |
| `tcp_dns` | DNS über TCP auswerten (experimentell) |
| `dnsfilter_management` | Änderungen am FRITZ!Box-DNS-Filter aus dem Dashboard erlauben (aus = nur lesen) |
| `debug` | ausführliche Logs (ohne Zugangsdaten/SIDs) |

Nach dem Speichern die App neu starten. Fehlende Zugangsdaten werden im Dashboard als Hinweis angezeigt.

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

## DNS-Filter verwalten (ab 0.2.0)

FritzHole nutzt die **inoffizielle Beta-API** von FRITZ!OS (`/api/v0/beta/dnsfilter`, getestet mit FRITZ!OS 8.40-136793 (Labor)).
AVM kann sie mit jedem Update ändern oder entfernen – dann zeigt der Tab „DNS-Filter“ eine Fehlermeldung,
der Mitschnitt läuft unabhängig davon weiter.

- **Tab „DNS-Filter“:** Status, Hauptschalter, Whitelist/Blacklist (hinzufügen, bearbeiten, löschen),
  Filterlisten mit Eintragszahl und die Statistik der FRITZ!Box.
- **Live-Protokoll / Auswertungen:** Über „⋯“ (oder Rechtsklick auf die Zeile) eine Domain erlauben/sperren,
  bestehende Einträge bearbeiten, verschieben oder entfernen. Vorhandene Einträge werden als Badge angezeigt;
  „≈“ kennzeichnet einen Eintrag auf einer übergeordneten Domain (ob die FRITZ!Box diesen auch auf Subdomains
  anwendet, ist nicht verifiziert).
- **Pause:** 5/15/30/60 min oder eigene Dauer (1–1440 min). Der Zeitpunkt der Reaktivierung wird in der Datenbank
  unter `/data` gespeichert; nach einem Neustart wird eine überfällige Reaktivierung sofort ausgeführt.
  Schlägt sie fehl, wird mit wachsendem Abstand (30 s … 5 min) erneut versucht und der Fehler im Dashboard
  sowie im Log angezeigt. „Dauerhaft ausschalten“ über den Hauptschalter beendet eine Pause ohne Reaktivierung.
- **Filterlisten (ab 0.3.0):** im selben Tab unter „Filterlisten“. Name/URL (nur HTTPS, ohne Zugangsdaten) bearbeiten,
  Liste per Schalter aktivieren/deaktivieren, löschen (mit Bestätigung), alle Listen manuell aktualisieren und die
  automatische Aktualisierung in den FRITZ!Box-Stufen (alle 8 Stunden, täglich, wöchentlich, monatlich, nie) einstellen. Doppelte Namen oder URLs werden abgelehnt.
  Fehler der FRITZ!Box (z. B. Fehlercode 3643, `isReady = false`, 0 Einträge) erscheinen direkt an der Liste.
  Die Fortschrittsanzeige der manuellen Aktualisierung meldet „erfolgreich“ erst, wenn jede aktive Liste ein
  neues, fehlerfreies Update gemeldet hat; ohne Rückmeldung nach 10 min erscheint ein Hinweis.
- **Sicherheit:** Jede Änderung braucht eine Bestätigung im Dialog; die API akzeptiert schreibende Aufrufe nur mit
  einem speziellen Header (Schutz vor Fehlklicks/CSRF). Nach jedem Schreiben wird erneut ausgelesen und geprüft.
  Beim Umschalten bleibt `automaticUpdate` unverändert. Session-IDs und Passwort erscheinen nie in Logs oder API-Antworten.

## Datenschutz

DNS-Protokolle zeigen, welche Dienste ein Gerät nutzt, und sind bei Zuordnung zu Personen **personenbezogene Daten**
(Art. 4 DSGVO). Informiere Mitbewohner/Familie, halte die Aufbewahrung kurz und gib das Dashboard nur Administratoren
frei (Standard: `panel_admin`). FritzHole sendet keine Daten an externe Dienste; der Zugriff erfolgt ausschließlich
über Home-Assistant-Ingress. Hinweis: Die Kommunikation zur FRITZ!Box läuft im LAN per HTTP; das Passwort wird dabei
nicht im Klartext übertragen (Challenge-Response/PBKDF2 bzw. HTTP-Digest), die Session-ID jedoch schon.
Keine Rechtsberatung.

## Fehlersuche

| Meldung | Ursache |
|---|---|
| „Anmeldung fehlgeschlagen“ | Benutzer/Passwort falsch oder Recht „FRITZ!Box Einstellungen“ fehlt |
| „FRITZ!Box sperrt Anmeldungen noch … s“ | Zu viele Fehlversuche – Box-Sperre abwarten |
| „FRITZ!Box hat den Mitschnitt-Stream beendet“ | Box hat den Mitschnitt beendet (z. B. Neustart, paralleler Mitschnitt) |
| „Zeitüberschreitung“ | 15 min keine DNS-Pakete – Verbindung wird neu aufgebaut |
| Gerätenamen fehlen | TR-064 „Zugriff für Anwendungen“ deaktiviert |

Der Tab **Status** zeigt Linktype, PCAP-Format und Zähler für fehlerhafte, abgeschnittene oder doppelte Pakete.
Mit `debug: true` werden zusätzlich die ersten Frames als Hex-Kopf protokolliert (hilfreich bei neuen FRITZ!OS-Versionen).
