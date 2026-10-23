PHP2Shell Checker 1.0.0
=======================

Defensiv kontroll av PHP och PHP2Shell (CVE-2026-109618, CVE-2026-109619).

Windows
-------
Dubbelklicka på: PHP2Shell-Checker-Windows-x64.exe
Ett konsolfönster öppnas och webbläsaren startar automatiskt.
Windows SmartScreen kan varna eftersom filen inte är koddignerad.
Välj "Mer information" -> "Kör ändå" om du litar på filen.

Linux
-----
chmod +x PHP2Shell-Checker-Linux-x64
./PHP2Shell-Checker-Linux-x64

Webbläsaren startar automatiskt. Om inte, öppna adressen som skrivs ut.
Använd --no-browser för att bara starta den lokala servern.

Stäng av
--------
Använd knappen "Stäng av" i gränssnittet, stäng konsolfönstret
eller tryck Ctrl+C i terminalen.

Kontrollsummor
--------------
SHA256SUMS.txt innehåller kontrollsummor för båda filerna.

Viktigt
-------
Använd endast på system som du äger eller har tillstånd att testa.
Skannern exploaterar inte sårbarheten; den gör vanliga GET-förfrågningar.
