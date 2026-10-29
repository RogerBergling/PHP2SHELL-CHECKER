# PHP2Shell Checker

En snabb, defensiv skanner med grafiskt gränssnitt för att kontrollera om en webbplats använder PHP, göra en djup versionanalys och avgöra om PHP-versionen påverkas av **PHP2Shell** (CVE-2026-109618 och CVE-2026-109619). Skannern flaggar även **CVE-2026-115560** (`session.upload_progress`) som en separat rekommendation.

Skannern finns som fristående filer:

| Plattform | Fil |
| --- | --- |
| Windows 64-bit (rekommenderas) | [`release/PHP2Shell-Checker-Windows-x64.zip`](release/PHP2Shell-Checker-Windows-x64.zip) |
| Windows 64-bit (endast programmet) | [`release/PHP2Shell-Checker-Windows-x64.exe`](release/PHP2Shell-Checker-Windows-x64.exe) |
| Linux 64-bit | [`release/PHP2Shell-Checker-Linux-x64`](release/PHP2Shell-Checker-Linux-x64) |

Ingen Python-, Java- eller Go-installation behövs för att köra filerna.

## Snabbstart

### Windows

1. Ladda ner `release/PHP2Shell-Checker-Windows-x64.zip`.
2. Högerklicka på ZIP-filen och välj **Extrahera alla…**. Kör sedan `.exe`-filen från den extraherade mappen – inte direkt inifrån ZIP-filen.
3. Ett konsolfönster öppnas och webbläsaren startar gränssnittet automatiskt.
4. Om webbläsaren inte öppnas: öppna adressen som står i konsolfönstret.
5. Stäng av med knappen **Stäng av** i gränssnittet eller genom att stänga konsolfönstret.

> Windows SmartScreen kan varna eftersom filen inte är koddignerad. Välj **Mer information → Kör ändå** om du själv har byggt eller hämtat filen från en betrodd källa. Samma gäller om Windows Defender eller ett annat antivirusprogram flaggar filen – lägg då till den som undantag endast om du litar på källan.

#### Om Windows säger att filen är skadad

Fel som **"Filen eller katalogen är skadad och kan inte läsas"** (0x80070570 / `ERROR_FILE_CORRUPT`), **"This app can't run on your PC"** eller en ZIP som visas som tom beror nästan alltid på att filen på datorn är ofullständig, blockerad eller ligger på ett skadat filsystem – inte på programmet. Filerna i `release/` är verifierade med SHA-256 och ZIP-test.

Kontrollera i denna ordning:

1. **Verifiera filen automatiskt.** I PowerShell, i mappen med filerna:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\verify-windows.ps1
   ```
   Skriptet visar storlek, första byte (`4D 5A` = giltig Windows-binär) och jämför SHA-256 med `SHA256SUMS.txt`. Om du bara hämtade ZIP-filen behöver du även ladda ner `verify-windows.ps1` och `SHA256SUMS.txt` från `release/` och lägga dem bredvid den extraherade EXE-filen.
2. **Jämför kontrollsumman manuellt.**
   ```powershell
   Get-FileHash .\PHP2Shell-Checker-Windows-x64.exe -Algorithm SHA256
   ```
   Hashvärdet ska stå i `release/SHA256SUMS.txt`. Stämmer det inte är filen ofullständigt nedladdad – ladda ner igen.
3. **Kontrollera filstorleken.** `.exe`-filen ska vara **7 993 856 byte** (cirka 7,5 MiB) i version 1.2.0. Är den 0 byte eller bara några kilobyte har nedladdningen misslyckats, eller så har du sparat en HTML-sida i stället för filen.
4. **Avblockera filen.** Högerklicka → **Egenskaper** → kryssa i **Avblockera** (Unblock) → **OK**, eller:
   ```powershell
   Unblock-File .\PHP2Shell-Checker-Windows-x64.exe
   ```
5. **Kör från en lokal mapp.** Starta inte filen direkt från ZIP-filen, OneDrive (filer på begäran), en nätverksenhet eller ett USB-minne som kan vara skadat. Extrahera till till exempel `C:\Temp\PHP2ShellChecker\`.
6. **Kontrollera antivirus.** Windows Defender eller annat skyddsprogram kan blockera eller skriva om osignerade binärfiler. Kontrollera **Windows-säkerhet → Skyddshistorik**. Lägg bara till ett undantag om du litar på källan.
7. **Kontrollera disken.** Om både ZIP och EXE blir skadade, kör som administratör:
   ```powershell
   chkdsk C: /scan
   ```
   Prova också att ladda ner till en annan mapp eller disk. Samma fel för flera filer tyder på filsystem- eller hårdvaruproblem.
8. **Reservväg om nedladdningen fortsätter bli skadad.** Använd textfilen `release/PHP2Shell-Checker-Windows-x64.exe.gz.b64` (base64-kodad gzip, klarar sig förbi filter som skadar binärfiler):
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\restore-windows.ps1
   ```
   Skriptet återställer `.exe`-filen och verifierar SHA-256 automatiskt.
9. **Bygg lokalt i stället.** Om inget annat fungerar, bygg filen på Windows-datorn – då överförs ingen färdig binärfil:
   ```powershell
   winget install --id GoLang.Go -e
   git clone git@github.com:RogerBergling/PHP2SHELL-CHECKER.git
   cd PHP2SHELL-CHECKER
   .\build-windows.bat
   ```
10. **Testa från kommandotolken.** Kör `.\PHP2Shell-Checker-Windows-x64.exe --version`. Skrivs `PHP2Shell Checker 1.2.0` ut fungerar filen, och problemet gäller i så fall starten av webbläsaren eller servern.

> **Smart App Control / S-läge:** Windows 11 kan blockera osignerade program. Kontrollera **Windows-säkerhet → App- och webbläsarkontroll**. Smart App Control kan stängas av om du litar på filen (det går inte att slå på igen utan ominstallation). Windows i **S-läge** kan bara köra program från Microsoft Store.

> **ARM64-dator:** Windows 11 ARM kan köra x64-program via emulering. Fungerar det inte, bygg en egen ARM64-version med `GOARCH=arm64`:
> ```bat
> set CGO_ENABLED=0
> set GOOS=windows
> set GOARCH=arm64
> go build -trimpath -buildvcs=false -ldflags "-s -w" -o PHP2Shell-Checker-Windows-arm64.exe .
> ```

### Linux

```bash
chmod +x release/PHP2Shell-Checker-Linux-x64
./release/PHP2Shell-Checker-Linux-x64
```

Webbläsaren öppnas automatiskt. Om det inte fungerar, öppna adressen som skrivs ut i terminalen. Använd `--no-browser` för att bara starta servern:

```bash
./release/PHP2Shell-Checker-Linux-x64 --no-browser
```

Stäng av med **Stäng av** i gränssnittet eller `Ctrl+C` i terminalen.

## Användning

1. Ange en eller flera webbplatser i textrutan, en per rad:
   ```text
   https://example.com
   example.org
   https://butik.example.se
   ```
2. Eller klicka på **Ladda fil…** och välj en `.txt`/`.csv`-fil med en adress per rad. Du kan också släppa filen direkt i textrutan.
3. Justera inställningarna vid behov och klicka på **Starta skanning**.
4. Resultaten visas direkt allt eftersom skanningen pågår. Klicka på en rad för att se bevis, HTTP-huvuden, PHP-version och rekommendation.
5. Markera raderna för de värdar du vill följa upp. Verktygsfältet **Valda värdar** blir då synligt.
6. **Verifiera valda** gör om kontrollen för de markerade värdarna med nya GET-förfrågningar och uppdaterar bevisen (IP-adress, tidsstämpel och fingeravtryck).
7. **Bevisrapport (HTML)** skapar en utskriftsvänlig rapport med sammanfattning, metod, fynd, rekommendationer och signaturfält. **Bevisrapport (JSON)** ger samma underlag i maskinläsbar form.
8. Exportera alla resultat som **CSV** eller **JSON**. Exporten omfattar alltid hela resultatlistan, oavsett vilket filter eller vilken sökning som är aktiv.

Rader som börjar med `#` eller `;` ignoreras. Adresser utan `http://` eller `https://` testas först med HTTPS och därefter med HTTP om HTTPS inte kan ansluta.

### Inställningar

| Inställning | Standard | Beskrivning |
| --- | --- | --- |
| Tidsgräns | 10 s | Maximal tid per webbplats. |
| Samtidiga | 5 | Antal webbplatser som skannas parallellt. |
| Fördröjning/värd | 250 ms | Minsta tid mellan anrop till samma värd. |
| Följ omdirigeringar | På | Följer upp till 6 omdirigeringar. |
| Djup versionanalys | På | Kombinerar PHP-indikatorer från cookies med versioner från svarshuvuden, HTML, phpinfo-liknande sidor och flera vanliga diagnostiksökvägar. Provar även webbplatsens rot om den aktuella katalogen inte ger en fullständig version. Stoppar så snart en fullständig version hittats, men kan innebära fler anrop och längre skanningstid. |
| Ignorera TLS-fel | Av | Användbart för servrar med trasiga eller självsignerade certifikat. |
| User-Agent | `PHP2ShellChecker/1.2.0 …` | Kan ändras om en sajt blockerar skannern. |

## Bedömningar

| Bedömning | Betydelse |
| --- | --- |
| **Sårbar** | PHP-versionen är äldre än den rättade versionen i samma gren. |
| **Sårbar – EOL** | PHP 8.1 eller äldre. Ingen officiell binär release finns; PHP tillhandahåller källbackporter för 7.4–8.1, i övriga fall krävs leverantörsbackport. |
| **PHP – okänd version** | PHP upptäcktes, men versionen kunde inte fastställas. Sårbarheten kan inte uteslutas. |
| **PHP – åtgärdad** | PHP-versionen är samma som eller nyare än den rättade versionen. |
| **Inga PHP-indikatorer** | Inga tydliga PHP-tecken hittades. Det utesluter inte PHP bakom CDN, WAF eller ett dolt gränssnitt. |
| **Anslutningsfel / Ogiltig URL** | Kontrollen kunde inte genomföras. |

### Rättade PHP-versioner

PHP2Shell påverkar PHP 5.4 och senare. Följande versioner innehåller rättelserna:

- PHP **8.5.12** eller senare
- PHP **8.4.27** eller senare
- PHP **8.3.36** eller senare
- PHP **8.2.35** eller senare
- PHP 8.1 och äldre: end-of-life. PHP-projektet har publicerat källbackporter för 7.4, 8.0 och 8.1; äldre grenar kräver leverantörsbackport.

### CVE-2026-115560 och session.upload_progress

Två dagar efter PHP2Shell-fixarna varnade PHP för ytterligare ett sätt att köra kod: **CVE-2026-115560**. Det påverkar bara webbappar som är konfigurerade på ett ovanligt sätt: applikationen måste sätta `session.serialize_handler` till `php_binary` eller `php_serialize` och sedan byta till `php` i runtime med `ini_set()` före `session_start()`, samtidigt som `session.upload_progress` är aktiverat. PHP bedömer risken som låg. Ingen brådskande fix utfärdas; rättelsen väntas i nästa ordinarie PHP-utgåva.

Rekommendationen är att stänga av funktionen tills dess:

```ini
session.upload_progress.enabled = Off
```

Starta om PHP-FPM/Apache efter ändringen. Kontrollen är separat från PHP2Shell-bedömningen: en sajt kan vara **PHP – åtgärdad** för PHP2Shell och ändå få en påminnelse om `session.upload_progress`.

Eftersom `php.ini` inte kan läsas över HTTP är kontrollen en heuristik:

- **Kontrollera konfigurationen** visas när PHP upptäcks.
- **Möjligen påverkad – kontrollera** visas när sajten dessutom använder en PHP-sessionscookie och har filuppladdning i HTML-svaret. Det är en indikator, inte ett bevis på att applikationen byter `session.serialize_handler` i runtime.

Skannern skickar inga uppladdningar och ändrar inget. Verifiera alltid `session.upload_progress.enabled` på servern.

## Hur kontrollen går till

Skannern är **icke-invasiv** och skickar inga exploit-payloads. Den gör vanliga `GET`-förfrågningar och letar efter PHP-indikatorer:

- HTTP-huvuden som `X-Powered-By: PHP/8.4.26`, `X-PHP-Version`, `X-PHP-Engine`, `X-Server-Powered-By`, `X-Backend-Server` och `Server`.
- Cookies som `PHPSESSID`, `laravel_session`, `ci_session` med flera.
- HTML-referenser till `.php`-filer.
- PHP-felmeddelanden i svaret.
- PHP-version i HTML, inklusive `PHP Version`, `Powered by PHP`, `PHP/8.x`, meta generator, `PHP_VERSION`, JSON-fält och Zend OPcache.
- **Zend Engine-versionen räknas om till rätt PHP-gren** (Zend 4.3.x = PHP 8.3.x, Zend 3.4.x = PHP 7.4.x, Zend 2.6.x = PHP 5.6.x) i stället för att felaktigt tolkas som en PHP-version.
- Alla versionsobservationer sparas som kandidater med källa och styrka. Den mest tillförlitliga källan vinner, men en något svagare källa får komplettera en ofullständig version som `8.4` med exakt patchversion.
- Kända PHP-applikationer som WordPress, Drupal, Joomla, Magento, Laravel och Nextcloud.
- PHP-sessionscookies och filuppladdningsformulär, som underlag för CVE-2026-115560-rekommendationen.
- Med **Djup versionanalys**, när huvudsvaret inte ger en fullständig version, även `index.php`, `phpinfo.php`, `info.php`, `php-info.php`, `phpversion.php`, `test.php` och en slumpmässig `.php`-kontroll i samma katalog. Hittas ingen fullständig version provas samma sökvägar i webbplatsens rot. Alla kontroller loggas i resultatet med URL, HTTP-status och eventuell version.

Om en PHP-version hittas jämförs den med de rättade versionerna ovan. Skannern försöker aldrig utnyttja sårbarheten, ladda upp filer eller ändra något på servern.

## Bevis och rapportering

Resultatlistan kan användas som underlag i en utredning eller för rapportering till säkerhetsledningen:

- **Markera värdar** med kryssrutorna (eller kryssrutan i tabellhuvudet för alla synliga rader). Markeringen behålls när du filtrerar och sorterar.
- **Verifiera valda** kör om den vanliga, icke-invasiva kontrollen för de markerade värdarna och ersätter raderna med färska bevis. Varje resultat innehåller då även vilken IP-adress som svarade, ett SHA-256-fingeravtryck på de första 2 MiB av HTTP-svarskroppen, ett urval av svarshuvuden, alla PHP-versionkandidater med källa/styrka och loggen över djupkontrollerna.
- **Bevisrapport (HTML)** genererar en fristående, utskriftsvänlig rapport med sammanfattning, metodbeskrivning, avgränsning, per-värd-fynd, versionkällor, djupkontroller, rekommendationer och signaturfält. Öppna filen i en webbläsare och skriv ut eller spara som PDF.
- **Bevisrapport (JSON)** ger samma urval i maskinläsbar form för ärendehantering eller vidare bearbetning.

Rapporterna beskriver uttryckligen att kontrollen är icke-invasiv: inga exploit-payloads skickas, inga filer laddas upp och ingen åtkomst etableras. Ett fynd är en indikation på sårbar PHP-version, inte ett bevis på att sårbarheten är utnyttjad.

## Begränsningar

- En webbplats kan använda PHP utan att avslöja versionen. Då visas **PHP – okänd version**.
- CDN-tjänster, WAF:er och anpassade felsidor kan dölja både PHP och versionsinformation.
- En webbplats kan ligga bakom en reverse proxy där PHP körs på en annan server.
- Resultatet är en indikation, inte en garanti. Verifiera alltid mot serverns pakethanterare, kontrollpanel eller hostingleverantör.
- PHP2Shell är en sårbarhet i PHP-motorn. Att uppdatera applikationen, temat eller CMS:et räcker inte – PHP måste uppdateras.

## Säkerhet och etik

- Använd skannern **endast** på system som du äger eller har uttryckligt tillstånd att testa.
- Den lokala servern lyssnar bara på `127.0.0.1` och skyddas av en slumpmässig token per start.
- Inga resultat eller webbplatser skickas till tredje part.
- Skannern är avsedd för defensiv kontroll och inventering.

## Bygga från källkod

Kräver [Go](https://go.dev/) 1.27 eller senare.

```bash
./build.sh
```

Skriptet bygger båda filerna till `release/`, paketerar Windowsversionen som ZIP, skapar en base64-kodad reservfil och skriver `SHA256SUMS.txt`. På Windows kan `build-windows.bat` användas för att bygga och paketera Windowsversionen.

Manuell build:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags "-s -w" \
  -o release/PHP2Shell-Checker-Linux-x64 .

CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags "-s -w" \
  -o release/PHP2Shell-Checker-Windows-x64.exe .
```

`-buildvcs=false` gör bygget reproducerbart: samma källkod och samma Go-version ger alltid samma binär och samma SHA-256, oavsett git-status.

Kör tester:

```bash
go test ./...
```

## Projektstruktur

```text
.
├── main.go                 # Startar lokal server och webbläsare
├── server.go               # HTTP-server, token-skydd och streaming-API
├── scanner.go              # Icke-invasiv PHP-detektering och djup versionanalys
├── advisory.go             # CVE-2026-115560 och session.upload_progress
├── version.go              # Jämförelse mot rättade PHP-versioner
├── web/index.html          # Grafiskt gränssnitt (HTML/CSS/JS)
├── build.sh                # Bygger Linux + Windows och ZIP
├── build-windows.bat       # Bygger Windows lokalt
├── examples/               # Exempellista
└── release/                # Färdiga, startbara filer
```

## Referenser

- [NCSC-NL: php2shell](https://github.com/NCSC-NL/php2shell)
- [PHP:s säkerhetsadvisory (2026-10-21)](https://www.php.net/archive/2026.php#2026-10-21-5)
- [CERT-EU Security Advisory 2026-018](https://cert.europa.eu/publications/security-advisories/2026-018/)
- [Sansec: PHP2Shell](https://sansec.io/research/php2shell)
- [Wiz: PHP2Shell](https://www.wiz.io/blog/php2shell-php-rce)
