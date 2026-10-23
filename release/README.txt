PHP2Shell Checker 1.0.0
=======================

Defensiv kontroll av PHP och PHP2Shell (CVE-2026-109618, CVE-2026-109619).

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
- Kontrollera SHA-256 i PowerShell:
    Get-FileHash .\PHP2Shell-Checker-Windows-x64.exe -Algorithm SHA256
  Jamfor med SHA256SUMS.txt. Stammer det inte, ladda ner igen.
- EXE-filen ska vara cirka 7,8 MB. Ar den bara nagra kilobyte har du
  sparat en HTML-sida i stallet for programmet.
- Avblockera filen: hogerklicka -> Egenskaper -> Avblockera, eller:
    Unblock-File .\PHP2Shell-Checker-Windows-x64.exe
- Kor fran en lokal mapp, inte fran ZIP, OneDrive eller natverksenhet.
- Kontrollera Smart App Control / S-lage i Windows-sakerhet.
- Testa: .\PHP2Shell-Checker-Windows-x64.exe --version

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
SHA256SUMS.txt innehaller kontrollsummor for Linux-filen, Windows-filen
och Windows-ZIP-filen.

Viktigt
-------
Anvand endast pa system som du ager eller har tillstand att testa.
Skannern exploaterar inte sarbarheten; den gor vanliga GET-forfragningar.
