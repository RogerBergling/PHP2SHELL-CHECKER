PHP2Shell Checker 1.1.0
=======================

Defensiv kontroll av PHP och PHP2Shell (CVE-2026-109618, CVE-2026-109619)
samt CVE-2026-115560 (session.upload_progress).

Windows
-------
1. Extrahera ZIP-filen med "Extrahera alla..." och kor sedan
   PHP2Shell-Checker-Windows-x64.exe fran den extraherade mappen.
   Kor inte filen direkt inifran ZIP-filen.
2. Ett konsolfonster oppnas och webblasaren startar automatiskt.
3. Windows SmartScreen kan varna eftersom filen inte ar koddignerad.
   Valj "Mer information" -> "Kor anda" om du litar pa filen.

Om Windows sager att filen ar skadad
-------------------------------------
"Filen eller katalogen ar skadad och kan inte lasas" (0x80070570) och en
tom ZIP beror pa att filen pa datorn ar ofullstandig, blockerad eller
ligger pa ett skadat filsystem - inte pa programmet.

Kontrollera i denna ordning:
1. Kor i PowerShell i denna mapp:
     powershell -ExecutionPolicy Bypass -File .\verify-windows.ps1
   Skriptet kontrollerar storlek, filhuvud och SHA-256.
2. EXE-filen ska vara 7 850 496 byte (cirka 7,5 MiB) i version 1.1.0.
   Ar den 0 byte eller bara nagra kilobyte har nedladdningen misslyckats.
3. Avblockera filen: hogerklicka -> Egenskaper -> Avblockera, eller:
     Unblock-File .\PHP2Shell-Checker-Windows-x64.exe
4. Kor fran en lokal mapp, inte fran ZIP, OneDrive eller natverksenhet.
5. Kontrollera skyddshistoriken i Windows-sakerhet (antivirus).
6. Om bade ZIP och EXE blir skadade, kor som administratör:
     chkdsk C: /scan
7. Reservvag om nedladdningen fortsatter bli skadad:
     powershell -ExecutionPolicy Bypass -File .\restore-windows.ps1
   Skriptet aterstaller EXE-filen fran textfilen
   PHP2Shell-Checker-Windows-x64.exe.gz.b64 och verifierar SHA-256.
8. Testa: .\PHP2Shell-Checker-Windows-x64.exe --version

Kontrollera Smart App Control / S-lage i Windows-sakerhet om filen
blockeras utan att vara skadad.

Linux
-----
chmod +x PHP2Shell-Checker-Linux-x64
./PHP2Shell-Checker-Linux-x64

Webblasaren startar automatiskt. Om inte, oppna adressen som skrivs ut.
Anvand --no-browser for att bara starta den lokala servern.

Stang av
--------
Anvand knappen "Stang av" i granssnittet, stang konsolfonstret
eller tryck Ctrl+C i terminalen.

Kontrollsummor
--------------
SHA256SUMS.txt innehaller kontrollsummor for Linux-filen, Windows-filen,
Windows-ZIP-filen och reservfilen (.gz.b64).

Viktigt
-------
Anvand endast pa system som du ager eller har tillstand att testa.
Skannern exploaterar inte sarbarheten; den gor vanliga GET-forfragningar.
