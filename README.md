# Kleine Firewall (Windows)

Fragt nach, bevor ein Programm ins Netz darf. Nutzt nur die eingebaute
Windows-Firewall, kein eigener Treiber.

![Oberflaeche](vorschau.png)

## Herunterladen

Rechts auf **Releases** klicken und bei der neuesten Version die Datei
`KleineFirewall-<Nummer>.zip` herunterladen. ZIP entpacken, den Ordner an einen
festen Platz legen und darin `KleineFirewall-<Nummer>.exe` starten. Der Ordner
`_internal` daneben gehoert dazu und muss bleiben.

Die EXE ist nicht signiert: Windows zeigt beim ersten Start eine Warnung
("Weitere Informationen" -> "Trotzdem ausfuehren").

## Versionen

- **2.1** - als Ordner im ZIP statt als einzelne EXE (weniger Fehlalarme bei Virenscannern); jeder Build wird mit Windows Defender geprueft.
- **2.0** - eigenes Programmfenster statt Browser; Schliessen-Kreuz blendet es nur aus, das Programm laeuft in der Taskleiste weiter.
- **1.7** - eigenes kleines Fenster auch auf Rechnern, auf denen Edge anders installiert ist oder fehlt (dann ueber Chrome).
- **1.6** - Versionsnummer im Dateinamen (`KleineFirewall-1.6.exe`); Autostart folgt der neuen Datei.
- **1.5** - Rechtsklick auf das Taskleisten-Symbol zeigt ein Menue mit "Oeffnen" und "Beenden".
- **1.4** - es gibt nur noch ein Fenster; ein offenes wird nach vorn geholt statt neu geoeffnet.
- **1.3** - Fenster oeffnet sich in der richtigen Groesse (war winzig bzw. riesig).
- **1.2** - kleineres, ruhigeres Fenster; Groesse mit A-/A+ einstellbar;
  Fenster passt sich dem Inhalt an; Versionsnummer sichtbar.
- **1.1** - mehr Angaben zu jeder Anfrage (Hersteller, Ziel, Port, Datei).
- **1.0** - erste Version mit Fragen-Modus, Listen und Taskleisten-Anzeige.

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
  `KleineFirewall-<Nummer>.exe --zuruecksetzen`.
- Nur ansehen, ohne etwas zu veraendern: `KleineFirewall-<Nummer>.exe --demo`.
