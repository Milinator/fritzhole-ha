# Changelog

## 0.3.3

- Neues Icon/Logo (App-Store-Icon, Logo in der Beschreibung, Logo und Favicon im Dashboard).

## 0.3.2

- Automatische Aktualisierung nur noch in den Stufen der FRITZ!Box-Oberfläche: alle 8 Stunden (28800 s),
  täglich (86400 s), wöchentlich (604800 s), monatlich (2592000 s), nie (`enabled=false`, `interval=0`).
  Werte außerhalb dieser Stufen werden roh angezeigt und nicht ungefragt überschrieben.
- API: `PUT /api/dnsfilter/auto-update` erwartet jetzt `{"preset": "8h|daily|weekly|monthly|never"}`.

## 0.3.1

- Fix: Nach Updates konnte der Browser/die HA-App neues HTML mit veraltetem `app.js` kombinieren
  („Cannot set properties of null“). JS/CSS werden jetzt mit Versionsparameter geladen und immer revalidiert.
- Darstellungsfehler werden nicht mehr fälschlich als „DNS-Filter-Status nicht abrufbar“ gemeldet.

## 0.3.0

- Neu: Filterlisten-Verwaltung im Tab „DNS-Filter“ – Listen anzeigen (Name, URL, Einträge, Status),
  hinzufügen, bearbeiten, aktivieren/deaktivieren, löschen.
- Neu: Manuelle Aktualisierung aller Listen mit Fortschrittsanzeige (angefordert → läuft → erfolgreich/Fehler),
  ausschließlich aus Rückmeldungen der FRITZ!Box abgeleitet; begrenztes Nachfragen mit wachsendem Abstand.
- Neu: Automatische Aktualisierung ein/aus und Intervall; DNS-Hauptschalter (und Pause) bleibt unverändert.
- Fehleranzeige je Liste aus `latestUpdate` (Status, Fehlercode/-text, Auslöser) und `status` (isReady, Einträge).
- Intervall wird lesbar angezeigt („täglich“ statt 86400).

## 0.2.1

- Fix: Abgelaufene Session der DNS-Filter-API wurde nicht erneuert. FRITZ!OS 8.40-136793 (Labor) meldet sie als
  HTTP 400 „permission denied“ (Code 3001) statt 401/403 – jetzt automatische Neuanmeldung.
- Fehlermeldungen der FRITZ!Box-API lesbar statt als Python-Liste.

## 0.2.0

- Neu: Tab „DNS-Filter“ – Status, Hauptschalter, Whitelist/Blacklist hinzufügen/bearbeiten/löschen,
  Filterlisten und FRITZ!Box-Statistik (inoffizielle Beta-API `/api/v0/beta/dnsfilter`).
- Neu: Kontextmenü (⋯ bzw. Rechtsklick) im Live-Protokoll/Auswertungen: Domain erlauben/sperren,
  vorhandene Einträge erkennen, bearbeiten, verschieben, entfernen.
- Neu: Filter befristet pausieren (5/15/30/60 min oder eigene Dauer) mit persistenter, neustartfester
  Reaktivierung, Countdown und Wiederholungsversuchen bei Fehlern.
- Jede Schreiboperation wird durch erneutes Auslesen verifiziert; `automaticUpdate` bleibt beim Umschalten unverändert.
- Sicherheit: schreibende API-Aufrufe erfordern Bestätigungs-Header (CSRF-/Fehlklick-Schutz) und Bestätigungsdialog;
  neue Option `dnsfilter_management` (aus = nur lesen).

## 0.1.1

- Fix: PBKDF2-Login-Antwort im AVM-Format `<salt2>$<hash2>` (Anmeldung schlug mit `version=2` fehl).

## 0.1.0

- Erste Version.
