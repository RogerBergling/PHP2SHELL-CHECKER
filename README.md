# PHP2Shell Checker

En snabb, defensiv skanner med grafiskt gränssnitt för att kontrollera om en webbplats använder PHP och om PHP-versionen påverkas av **PHP2Shell** (CVE-2026-109618 och CVE-2026-109619).

Skannern finns som två fristående filer:

| Plattform | Fil |
| --- | --- |
| Windows 64-bit | [`release/PHP2Shell-Checker-Windows-x64.exe`](release/PHP2Shell-Checker-Windows-x64.exe) |
| Linux 64-bit | [`release/PHP2Shell-Checker-Linux-x64`](release/PHP2Shell-Checker-Linux-x64) |

Ingen Python-, Java- eller Go-installation behövs för att köra filerna.

## Snabbstart

### Windows

1. Dubbelklicka på `release/PHP2Shell-Checker-Windows-x64.exe`.
2. Ett konsolfönster öppnas och webbläsaren startar gränssnittet automatiskt.
3. Om webbläsaren inte öppnas: öppna adressen som står i konsolfönstret.
4. Stäng av med knappen **Stäng av** i gränssnittet eller genom att stänga konsolfönstret.

> Windows SmartScreen kan varna eftersom filen inte är koddignerad. Välj **Mer information → Kör ändå** om du själv har byggt eller hämtat filen från en betrodd källa.

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
5. Exportera resultaten som **CSV** eller **JSON**.

Rader som börjar med `#` eller `;` ignoreras. Adresser utan `http://` eller `https://` testas först med HTTPS och därefter med HTTP om HTTPS inte kan ansluta.

### Inställningar

| Inställning | Standard | Beskrivning |
| --- | --- | --- |
| Tidsgräns | 10 s | Maximal tid per webbplats. |
| Samtidiga | 5 | Antal webbplatser som skannas parallellt. |
| Fördröjning/värd | 250 ms | Minsta tid mellan anrop till samma värd. |
| Följ omdirigeringar | På | Följer upp till 6 omdirigeringar. |
| Utökad kontroll | På | Gör upp till två extra GET-anrop per sajt: `index.php` och en slumpmässig `.php`-sökväg i samma katalog. |
| Ignorera TLS-fel | Av | Användbart för servrar med trasiga eller självsignerade certifikat. |
| User-Agent | `PHP2ShellChecker/1.0 …` | Kan ändras om en sajt blockerar skannern. |

## Bedömningar

| Bedömning | Betydelse |
| --- | --- |
| **Sårbar** | PHP-versionen är äldre än den rättade versionen i samma gren. |
| **Sårbar – EOL** | PHP 8.1 eller äldre. Ingen officiell fix finns; en leverantörsbackport kan finnas. |
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
- PHP 8.1 och äldre: end-of-life, kräver leverantörsbackport

## Hur kontrollen går till

Skannern är **icke-invasiv** och skickar inga exploit-payloads. Den gör vanliga `GET`-förfrågningar och letar efter PHP-indikatorer:

- HTTP-huvuden som `X-Powered-By: PHP/8.4.26`, `Server` och `X-PHP-Version`.
- Cookies som `PHPSESSID`, `laravel_session`, `ci_session` med flera.
- HTML-referenser till `.php`-filer.
- PHP-felmeddelanden i svaret.
- PHP-version i HTML (till exempel phpinfo eller `Powered by PHP`).
- Kända PHP-applikationer som WordPress, Drupal, Joomla, Magento, Laravel och Nextcloud.
- Med **Utökad kontroll** även `index.php` och en slumpmässig `.php`-sökväg i samma katalog.

Om en PHP-version hittas jämförs den med de rättade versionerna ovan. Skannern försöker aldrig utnyttja sårbarheten, ladda upp filer eller ändra något på servern.

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

Skriptet bygger båda filerna till `release/` och skriver `SHA256SUMS.txt`. På Windows kan `build-windows.bat` användas för att bygga Windowsversionen.

Manuell build:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" \
  -o release/PHP2Shell-Checker-Linux-x64 .

CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" \
  -o release/PHP2Shell-Checker-Windows-x64.exe .
```

Kör tester:

```bash
go test ./...
```

## Projektstruktur

```text
.
├── main.go                 # Startar lokal server och webbläsare
├── server.go               # HTTP-server, token-skydd och streaming-API
├── scanner.go              # Icke-invasiv PHP/versionsdetektering
├── version.go              # Jämförelse mot rättade PHP-versioner
├── web/index.html          # Grafiskt gränssnitt (HTML/CSS/JS)
├── build.sh                # Bygger Linux + Windows
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
