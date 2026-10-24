# HomeConnectLocal – FHEM-Modul (Version 1.59-7)

**HomeConnectLocal** ermöglicht die direkte lokale Kommunikation zwischen FHEM und kompatiblen Home-Connect-Hausgeräten über deren LAN-/WLAN-Schnittstelle. Je nach Gerät erfolgt die Verbindung über **TLS-PSK oder AES mit WebSocket**. Eine Cloud-Verbindung ist für die lokale Steuerung nicht erforderlich.

> **Stand: 22.10.2026 · Version 1.59-7**  
> Diese Version ist die freigegebene Referenz für die bisher getesteten Geräte. Die Kühlschrankintegration ist **nicht** Bestandteil dieser Version.

## Unterstützte Geräte

- Geschirrspüler (`dishwasher`)
- Kochfelder (`hob`)
- Waschmaschinen (`washer`)
- Waschtrockner (`washerdryer`)
- Backöfen (`oven`)

Welche Funktionen verfügbar sind, hängt vom jeweiligen Gerätemodell, den XML-Mappings und den zur Laufzeit gemeldeten Berechtigungen ab.

## Funktionen

- Lokale Verbindung über IPv4, FQDN oder IPv6
- IPv6-Link-Local-Adressen (`fe80::`) auch ohne manuell angehängten Interface-Scope; automatische Ermittlung eines numerischen Scope-Index
- TLS-PSK- und AES-Verbindungen, WebSocket-Kommunikation und Heartbeat
- Dynamische Readings, Programme, Optionen und Einstellungen aus `DeviceDescription`- und `FeatureMapping`-XML-Dateien
- Berücksichtigung von zur Laufzeit gemeldeter Verfügbarkeit und Zugriffsrechten
- Dynamisch erzeugte Set-Befehle und FHEMWEB-Programmauswahl-Popup
- Backofen-Programmauswahl einschließlich Optionen und Schutzprüfungen, unter anderem für Pyrolyse
- Zustandsabhängige Ablehnung nicht verfügbarer Backofenbefehle, ohne die Verbindung zu trennen
- Optionale DE-/EN-Anzeigeübersetzungen
- Ausblendbare Rohdaten-Readings und private Speicherung von kryptografischem Sitzungszustand

## Dateien

Das Release-Archiv enthält:

```text
70_HomeConnectLocal.pm
HomeConnectLocal.js
README.txt
```

Zusätzlich werden **zum jeweiligen Gerät passende XML-Dateien** benötigt:

```text
*_DeviceDescription.xml
*_FeatureMapping.xml
```

Die XML-Mappings sind gerätespezifisch und gehören nicht pauschal zu jedem Release-Archiv.

## Installation

1. `70_HomeConnectLocal.pm` in das FHEM-Modulverzeichnis kopieren (typisch `/opt/fhem/FHEM/`).
2. `HomeConnectLocal.js` so bereitstellen, dass FHEMWEB die Datei über seine JavaScript-Einbindung laden kann (bei Standardinstallationen im FHEMWEB-JavaScript-Verzeichnis, typischerweise `/opt/fhem/www/pgm2/`).
3. Die beiden passenden Geräte-XML-Dateien in das Mapping-Verzeichnis legen. Standardmäßig verwendet das Modul `/opt/fhem/FHEM/FHEM_HomeConnectLocal`.
4. Benötigte Perl-Abhängigkeiten installieren, insbesondere `JSON::PP`, `IO::Socket::IP`, `Crypt::Mode::CBC` sowie die weiteren vom Modul verwendeten Standardbibliotheken.
5. FHEM neu starten beziehungsweise das Modul neu laden und das Gerät konfigurieren.

Vor einem Update bestehende Dateien und die FHEM-Konfiguration sichern.

## Beispielkonfiguration

```text
define Geschirrspueler_Lokal HomeConnectLocal 192.168.1.55
attr Geschirrspueler_Lokal deviceType dishwasher
attr Geschirrspueler_Lokal connectionType TLS
attr Geschirrspueler_Lokal encryptionKey <GERAETESCHLUESSEL>
attr Geschirrspueler_Lokal mappingDir /opt/fhem/FHEM/FHEM_HomeConnectLocal
attr Geschirrspueler_Lokal mappingPrefix <PASSENDER_MAPPING_PREFIX>
```

IP-Adresse, Verbindungstyp, Schlüssel und Mapping-Prefix müssen zum eigenen Gerät passen. Für AES-Geräte kann zusätzlich das Attribut `iv` erforderlich sein.

**IPv6-Link-Local-Beispiel:**

```text
define Kochfeld_Lokal HomeConnectLocal fe80:0:0:0:6aa4:eff:fea7:b1bf
attr Kochfeld_Lokal deviceType hob
attr Kochfeld_Lokal connectionType AES
```

Bei einer ungescopten `fe80::`-Adresse versucht Version 1.59-7 automatisch, den passenden numerischen Interface-Index zu ermitteln. Eine explizite Angabe wie `%eth0` oder `%2` bleibt ebenfalls möglich.

## Wichtige Attribute

| Attribut | Zweck |
|---|---|
| `deviceType` | `dishwasher`, `hob`, `washer`, `washerdryer`, `oven` |
| `connectionType` | `TLS` oder `AES` |
| `encryptionKey` | Gerätespezifischer Pairing-/Verschlüsselungsschlüssel |
| `iv` | Initialisierungsvektor, sofern benötigt |
| `mappingDir` | Verzeichnis mit den Geräte-XML-Dateien |
| `mappingPrefix` | Auswahl des passenden XML-Dateipaares |
| `programPopup` | `on` / `off` |
| `translation` | `off` / `DE` / `EN` |
| `showRawReadings` | `0` / `1`; Rohdaten nur für Diagnose einschalten |
| `excludeReadings` | Unerwünschte Readings ausblenden |
| `excludeSets` | Einträge aus der dynamischen Set-Liste ausblenden |
| `disable` | Kommunikation deaktivieren |

Die integrierte FHEM-Commandref beschreibt weitere Details und Befehle.

## Set und Get

Beispiele für vorhandene Befehle:

```text
set <name> connect
set <name> disconnect
set <name> reloadMapping
set <name> program <programm>
set <name> start
set <name> stop
get <name> status
get <name> deviceID
get <name> mapping
get <name> programConfig
```

Weitere Set-Befehle werden dynamisch erzeugt. Nicht jedes Gerät unterstützt jeden Befehl oder jede Einstellung.

## Änderungen in 1.59-7

- **Neu:** Automatische IPv6-Link-Local-Scope-Erkennung für Adressen ohne `%Interface`.
- Scope-Ermittlung durch kurze TCP-Verbindungsversuche auf dem Geräteport (TLS: 443, AES: 80); gefundener Scope wird für Reconnects zwischengespeichert.
- Explizite Scope-Angaben sowie IPv4-, FQDN- und IPv6-ULA-Verbindungen bleiben auf dem bisherigen Verbindungsweg.
- Die in den Vorversionen ergänzte Backofenunterstützung und die Prüfungen für nicht verfügbare Befehle sind enthalten.
- **Das Popup und `HomeConnectLocal.js` wurden gegenüber 1.59-6 nicht geändert.**

## Bekannte Einschränkungen

- Die automatische IPv6-Scope-Suche ist experimentell und erfolgt synchron. Bei nicht erreichbaren Geräten kann sie bis zu etwa **10 Sekunden** blockieren. Die Funktion wurde unter Linux mit TLS und AES erfolgreich getestet; Windows und macOS sind damit noch nicht bestätigt.
- Die Programmauswahl beim Backofen kann deutlich länger dauern als beim Geschirrspüler. In einem Praxistest betrug der Programmwechsel ungefähr **12–13 Sekunden**, unabhängig vom Einschaltzustand. Die Ursache ist noch nicht abschließend geklärt.
- Die Verarbeitung bestimmter `/ro/descriptionChange`-Benachrichtigungen kann dazu führen, dass Reading-Updates ausbleiben. Eine Korrektur ist **nicht** Bestandteil von 1.59-7 und wird separat getestet.
- Kühl-/Gefriergeräte sind in dieser Version noch nicht als eigener `deviceType` integriert.

## Sicherheit

Der `encryptionKey` ist vertraulich und darf nicht in öffentlichen Logs, Screenshots oder Support-Beiträgen veröffentlicht werden. Kryptografischer Sitzungszustand wird außerhalb der sichtbaren FHEM-Geräte-Internals gehalten. `showRawReadings=1` nur vorübergehend für die Fehlersuche aktivieren.

## Lizenz

GNU General Public License, Version 2 oder (nach Wahl) jede spätere Version. Siehe Lizenzhinweis in `70_HomeConnectLocal.pm`.
