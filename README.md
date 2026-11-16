# Kleine Firewall (Windows)

Fragt nach, bevor ein Programm ins Netz darf. Nutzt nur die eingebaute
Windows-Firewall, kein eigener Treiber.

![Oberflaeche](vorschau.png)

## Herunterladen

Oben auf **Actions** klicken, den neuesten Lauf "EXE bauen" oeffnen und unten
unter **Artifacts** `KleineFirewall` herunterladen. Die ZIP-Datei enthaelt
`KleineFirewall.exe`.

Die EXE ist nicht signiert: Windows zeigt beim ersten Start eine Warnung
("Weitere Informationen" -> "Trotzdem ausfuehren").

## Bedienung

- **Fragen** (Standard): neue Programme erscheinen als Anfrage - Erlauben oder Sperren.
- **Nicht stoeren**: Neues bleibt still gesperrt und wartet als Anfrage.
- **Alles erlauben**: alles darf raus, nur die Sperrliste gilt.
- Symbol in der Taskleiste: oben Out, unten In. Klick oeffnet das Fenster.

Gut zu wissen:
- Der erste Verbindungsversuch eines neuen Programms scheitert; nach
  "Erlauben" klappt der naechste.
- Laeuft das Programm nicht, bleibt Neues gesperrt, aber niemand fragt -
  dafuer gibt es den Haken "Mit Windows starten".
- Alles rueckgaengig: Knopf "Alles zuruecksetzen" oder
  `KleineFirewall.exe --zuruecksetzen`.
- Nur ansehen, ohne etwas zu veraendern: `KleineFirewall.exe --demo`.
