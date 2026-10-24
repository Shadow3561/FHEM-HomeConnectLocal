# HomeConnectLocal für FHEM

**Stabile Version: 1.59-7 (22.10.2026)** · **Entwicklungszweig: 1.60-0 (Kühlschrank-Test, nicht freigegeben)**

HomeConnectLocal bindet kompatible Home-Connect-Hausgeräte **direkt über das lokale Netzwerk** in FHEM ein. Die Kommunikation erfolgt je nach Gerät per **TLS-PSK oder AES über WebSocket**. Für die laufende lokale Steuerung ist keine Home-Connect-Cloudverbindung erforderlich.

> **Wichtig:** Nicht jedes Home-Connect-Gerät ist automatisch kompatibel. Für jedes Gerätemodell werden passende XML-Beschreibungen sowie die für die lokale Verbindung erforderlichen Zugangsdaten benötigt.

## Unterstützte Geräte (1.59-7)

| Gerätetyp | `deviceType` |
| --- | --- |
| Geschirrspüler | `dishwasher` | getestet |
| Kochfeld | `hob` | getestet |
| Waschmaschine | `washer` | experimentell |
| Waschtrockner | `washerdryer` | getestet |
| Trockner | `washerdryer` | experimentell |
| Backofen | `oven` | getestet |

Welche Funktionen tatsächlich verfügbar sind, hängt von Modell, XML-Mapping und den zur Laufzeit vom Gerät gemeldeten Berechtigungen ab. **Kühl-/Gefriergeräte sind erst Gegenstand der noch ungetesteten Entwicklungsversion 1.60-0.**

## Funktionen

- Direkte lokale Verbindung über IPv4, Hostnamen oder IPv6; automatische Scope-Erkennung für IPv6-Link-Local-Adressen unter Linux (experimentell).
- TLS-PSK- bzw. AES-WebSocket-Kommunikation mit Heartbeat und Reconnect.
- Dynamische Readings, Programme, Optionen und Einstellungen aus gerätespezifischen XML-Dateien.
- Berücksichtigung aktueller Verfügbarkeit und Schreibberechtigungen des Geräts.
- Dynamische FHEM-`set`-Befehle und optionales FHEMWEB-Popup zur Programmauswahl.
- Optionale deutsche und englische Anzeigeübersetzungen.
- Schutzprüfungen bei Backofenfunktionen, unter anderem Pyrolyse.
- Optionales Ausblenden von Rohdaten-Readings und Aufbewahrung kryptografischen Sitzungszustands außerhalb der sichtbaren Geräte-Internals.

## Voraussetzungen

- Laufende FHEM-Installation mit Netzwerkzugriff auf das Hausgerät. Das Hausgerät aus in der Homeconnect-App eingerichtet sein.
- Perl-Module: `JSON::PP`, `IO::Socket::INET`, `IO::Socket::IP`, `MIME::Base64`, `Digest::SHA`, `Crypt::Mode::CBC` und `Encode`.
- Zum Gerät passende **Pairing-/Verschlüsselungsdaten** und das **XML-Dateipaar** `*_DeviceDescription.xml` / `*_FeatureMapping.xml`.
- Das zur Beschaffung dieser gerätespezifischen Dateien erforderliche **separate Download-/Extraktionsprogramm** (siehe nächsten Abschnitt). Die XML-Dateien werden nicht automatisch vom FHEM-Modul heruntergeladen.

### Geräteprofil mit dem Home Connect Profile Downloader beschaffen

Für jedes Gerät werden die **individuellen Verbindungsdaten und XML-Dateien** benötigt. Dazu muss zunächst der eigenständige **Home Connect Profile Downloader** von bruestel heruntergeladen werden. Er gehört **nicht** zu HomeConnectLocal.

- [Projektseite des Home Connect Profile Downloaders](https://github.com/bruestel/homeconnect-profile-downloader)
- [Aktuelle stabile Version herunterladen (Releases)](https://github.com/bruestel/homeconnect-profile-downloader/releases/latest)

**Schritt für Schritt:**

1. Das Hausgerät in der offiziellen Home-Connect-App einrichten und dem eigenen Home-Connect-/SingleKey-ID-Konto zuordnen.
2. Den Profile Downloader für das eigene Betriebssystem herunterladen und installieren bzw. entpacken. Es gibt Pakete für Windows, macOS und Linux; auf die passende Prozessorarchitektur achten.
3. Das Programm starten, die passende Region auswählen und den Abruf der Geräteprofile starten.
4. Im geöffneten Home-Connect-/SingleKey-ID-Anmeldefenster mit dem Konto anmelden, dem das Hausgerät zugeordnet ist.
5. Das Profil des gewünschten realen Geräts herunterladen und die enthaltenen Dateien sichern.

Ein heruntergeladenes Geräteprofil enthält insbesondere:

```text
<Seriennummer>.json
<Seriennummer>_DeviceDescription.xml
<Seriennummer>_FeatureMapping.xml
```

Die **JSON-Datei** enthält unter anderem `connectionType` und den individuellen Verschlüsselungsschlüssel; bei AES-Geräten außerdem den benötigten IV. Die **beiden XML-Dateien** beschreiben Funktionen, Programme, Einstellungen, UID-Zuordnungen und Werte des Geräts. Sie werden **nicht automatisch vom FHEM-Modul heruntergeladen**.

**XML-Dateien installieren:**

```bash
sudo mkdir -p /opt/fhem/FHEM/FHEM_HomeConnectLocal
sudo chown fhem:dialout /opt/fhem/FHEM/FHEM_HomeConnectLocal
```

Anschließend beide zusammengehörigen XML-Dateien nach `/opt/fhem/FHEM/FHEM_HomeConnectLocal/` kopieren. Ihre Dateinamen müssen denselben Präfix vor `_DeviceDescription.xml` bzw. `_FeatureMapping.xml` besitzen. Mehrere Geräteprofile dürfen in diesem Verzeichnis liegen; bei Bedarf lässt sich das richtige Paar mit `attr <name> mappingPrefix <DATEIPRAEFIX>` auswählen. Alternativ ist ein anderes Verzeichnis mit `mappingDir` möglich.

> **Sicherheit:** Die heruntergeladene JSON-Datei und insbesondere die darin enthaltenen Schlüssel sind vertraulich. **Keine vollständigen Geräteprofile, Schlüssel oder IVs auf GitHub oder im Forum veröffentlichen.**

## Installation

1. Vorhandene Moduldateien und die FHEM-Konfiguration sichern.
2. `70_HomeConnectLocal.pm` nach `/opt/fhem/FHEM/` kopieren.
3. `HomeConnectLocal.js` nach `/opt/fhem/www/pgm2/` kopieren und die JavaScript-Einbindung in FHEMWEB sicherstellen.
4. Unter Debian/Ubuntu die zusätzlichen Pakete installieren: `sudo apt update && sudo apt install libcryptx-perl openssl socat`. Danach die passenden XML-Dateien wie oben beschrieben ablegen.
5. Das FHEM-Gerät definieren und die benötigten Attribute setzen.
6. FHEM neu starten bzw. das Modul neu laden; Verbindung und Mapping kontrollieren.

Die Übersetzungsdatei gehört zur Modulversion und sollte zusammen mit dem Modul installiert werden.

## Beispielkonfiguration

```text
define Geschirrspueler_Lokal HomeConnectLocal 192.168.1.55
attr Geschirrspueler_Lokal deviceType dishwasher
attr Geschirrspueler_Lokal connectionType TLS
attr Geschirrspueler_Lokal encryptionKey <GERAETESCHLUESSEL>
attr Geschirrspueler_Lokal mappingDir /opt/fhem/FHEM/FHEM_HomeConnectLocal
attr Geschirrspueler_Lokal mappingPrefix <PASSENDER_DATEIPRAEFIX>
```

Die IP-Adresse, `connectionType`, `encryptionKey` und der Mapping-Präfix müssen zum **eigenen** Gerät passen. Bei AES-Geräten kann zusätzlich `attr <name> iv <WERT>` erforderlich sein.

**IPv6-Link-Local-Beispiel:**

```text
define Kochfeld_Lokal HomeConnectLocal fe80::6aa4:eff:fea7:b1bf
attr Kochfeld_Lokal deviceType hob
attr Kochfeld_Lokal connectionType AES
```

Ab 1.59-7 versucht das Modul unter Linux, bei einer Link-Local-Adresse ohne `%Interface` den numerischen Scope automatisch zu bestimmen. Eine explizite Scope-Angabe bleibt möglich. Die automatische Suche kann bei unerreichbaren Geräten FHEM für bis zu etwa 10 Sekunden blockieren.

## Wichtige Attribute

| Attribut | Bedeutung |
| --- | --- |
| `deviceType` | Geräteklasse gemäß Tabelle oben |
| `connectionType` | `TLS` oder `AES` |
| `encryptionKey` | Vertraulicher gerätespezifischer Schlüssel |
| `iv` | Initialisierungsvektor, falls benötigt |
| `mappingDir` | XML-Verzeichnis; Standard: `/opt/fhem/FHEM/FHEM_HomeConnectLocal` |
| `mappingPrefix` | Gemeinsamer Präfix des XML-Dateipaares |
| `programPopup` | `on` / `off` |
| `translation` | `off` / `DE` / `EN` |
| `showRawReadings` | `0` / `1` (Diagnose) |
| `excludeReadings` | Readings ausblenden |
| `excludeSets` | Dynamische Set-Befehle ausblenden |
| `disable` | Kommunikation deaktivieren |

## Set und Get

```text
set <name> connect
set <name> disconnect
set <name> reloadMapping
set <name> program <programm>
set <name> start
set <name> stop
set <name> pause
set <name> resume
set <name> power on
set <name> power off
get <name> status
get <name> deviceID
get <name> mapping
get <name> programConfig
```

**Nicht jeder Befehl wird von jedem Gerät angeboten oder akzeptiert.** Weitere Set-Befehle werden aus Mapping und aktuellen Laufzeitinformationen generiert. Details stehen in der integrierten FHEM-Commandref.

## Versionshinweise

### 1.59-7 – stabile Referenz

- Automatische IPv6-Link-Local-Scope-Ermittlung durch kurze TCP-Verbindungsversuche auf Port 443 (TLS) bzw. 80 (AES).
- Wiederverwendung des ermittelten Scope für Reconnects.
- Bestehende Backofenunterstützung inklusive zustandsabhängiger Schutzprüfungen.
- `HomeConnectLocal.js` und Programmauswahl-Popup gegenüber 1.59-6 unverändert.

### 1.60-0 – separate Kühlschrank-Testversion

- Neuer `deviceType fridgefreezer`.
- Test-Mapping für Siemens KG49NSBBF beigelegt.
- `/ro/descriptionChange` mit `uid` und `value` aktualisiert zusätzlich gezielt Readings.
- **Noch nicht an einem realen Kühlschrank getestet; nicht als stabiles Release verwenden.**
- Statische XML-Einträge mit `access=none` / `available=false` werden **nicht** künstlich freigeschaltet.

## Bekannte Einschränkungen (1.59-7)

- IPv6-Scope-Autodetektion ist experimentell; bisher unter Linux getestet.
- Die Backofen-Programmauswahl benötigte in einem Test etwa 12–13 Sekunden.
- Bestimmte `/ro/descriptionChange`-Benachrichtigungen können Reading-Aktualisierungen verhindern; ein gezielter Korrekturversuch ist in 1.60-0 enthalten.
- Kühlschränke sind in 1.59-7 noch nicht integriert.

## Sicherheit

**`encryptionKey` und `iv` sowie gegebenenfalls aus Pairing-Tools exportierte Schlüssel niemals veröffentlichen.** Keine vollständigen Gerätekonfigurationen mit Zugangsdaten in GitHub-Issues hochladen. `showRawReadings=1` nur vorübergehend zur Diagnose verwenden.

## Lizenz

GNU General Public License, Version 2 oder (nach Wahl) jede spätere Version; siehe Lizenzhinweis in `70_HomeConnectLocal.pm`.
