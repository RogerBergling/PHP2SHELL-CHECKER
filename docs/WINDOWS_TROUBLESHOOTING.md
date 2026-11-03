# Windows-felsökning

Den här guiden gäller releasefilerna i `release/` för PHP2Shell Checker 1.5.0.

## SmartScreen eller antivirus varnar

Windows SmartScreen kan varna eftersom filen inte är koddignerad. Verifiera
först SHA-256 mot en betrodd källa. Om du själv har byggt filen eller hämtat
den från en betrodd release kan du välja **Mer information → Kör ändå**.
Kontakta annars IT-supporten.

Samma gäller om Windows Defender eller ett annat antivirusprogram flaggar
filen. Lägg endast till ett undantag efter IT-godkännande och endast för den
verifierade filen. Inaktivera aldrig skyddet brett.

## Harmony EDR eller annat skyddsprogram blockerar filen

EXE-filen är en osignerad Go-binär med låg spridning och kan därför klassas som
misstänkt. Det åtgärdas inte med en kodändring.

Låt IT-administratören:

1. verifiera SHA-256,
2. godkänna filen i EDR:ens allowlist,
3. skicka en false-positive-rapport till skyddsleverantören.

För bred distribution krävs code signing med ett betrott certifikat.
EV-certifikat ger snabbare rykte. Signera aldrig med en egen certifikatkedja och
försök inte kringgå EDR.

Se [CODE_SIGNING.md](CODE_SIGNING.md) för signeringsstöd, `signtool` och
`-RequireSignature`.

## "Filen eller katalogen är skadad och kan inte läsas"

Fel som **"Filen eller katalogen är skadad och kan inte läsas"**
(0x80070570 / `ERROR_FILE_CORRUPT`), **"This app can't run on your PC"** eller
en ZIP som visas som tom beror nästan alltid på att filen på datorn är
ofullständig, blockerad eller ligger på ett skadat filsystem – inte på
programmet. Filerna i `release/` är verifierade med SHA-256 och ZIP-test.

Kontrollera i denna ordning:

1. **Verifiera filen automatiskt.** I PowerShell, i mappen med filerna:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\verify-windows.ps1
   ```

   Skriptet visar storlek, första byte (`4D 5A` = giltig Windows-binär) och
   jämför SHA-256 med `SHA256SUMS.txt` eller EXE-filens `.sha256`.
   `verify-windows.ps1` och `.sha256`-filen finns i ZIP-filen. Om du bara
   hämtade EXE-filen kan du ladda ner dem från `release/`. Lägg till
   `-RequireSignature` om en giltig Authenticode-signatur måste krävas.

2. **Jämför kontrollsumman manuellt.**

   ```powershell
   Get-FileHash .\PHP2Shell-Checker-Windows-x64.exe -Algorithm SHA256
   ```

   Hashvärdet ska stå i `release/SHA256SUMS.txt`. Stämmer det inte är filen
   ofullständigt nedladdad – ladda ner igen.

3. **Kontrollera filstorleken.** `.exe`-filen ska vara **8 024 576 byte**
   (cirka 7,5 MiB) i version 1.5.0. Är den 0 byte eller bara några kilobyte har
   nedladdningen misslyckats, eller så har du sparat en HTML-sida i stället för
   filen.

4. **Avblockera filen.** Högerklicka → **Egenskaper** → kryssa i
   **Avblockera** (Unblock) → **OK**, eller:

   ```powershell
   Unblock-File .\PHP2Shell-Checker-Windows-x64.exe
   ```

5. **Kör från en lokal mapp.** Starta inte filen direkt från ZIP-filen,
   OneDrive (filer på begäran), en nätverksenhet eller ett USB-minne som kan
   vara skadat. Extrahera till exempel till `C:\Temp\PHP2ShellChecker\`.

6. **Kontrollera antivirus.** Windows Defender eller annat skyddsprogram kan
   blockera eller skriva om osignerade binärfiler. Kontrollera
   **Windows-säkerhet → Skyddshistorik**. Lägg bara till ett undantag om du
   litar på källan.

7. **Kontrollera disken.** Om både ZIP och EXE blir skadade, kör som
   administratör:

   ```powershell
   chkdsk C: /scan
   ```

   Prova också att ladda ner till en annan mapp eller disk. Samma fel för flera
   filer tyder på filsystem- eller hårdvaruproblem.

8. **Reservväg om nedladdningen fortsätter bli skadad.** Använd textfilen
   `release/PHP2Shell-Checker-Windows-x64.exe.gz.b64` (base64-kodad gzip, klarar
   sig förbi filter som skadar binärfiler):

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\restore-windows.ps1
   ```

   Skriptet återställer `.exe`-filen och verifierar SHA-256 automatiskt.

9. **Bygg lokalt i stället.** Om inget annat fungerar, bygg filen på
   Windows-datorn – då överförs ingen färdig binärfil:

   ```powershell
   winget install --id GoLang.Go -e
   git clone git@github.com:RogerBergling/PHP2SHELL-CHECKER.git
   cd PHP2SHELL-CHECKER
   .\build-windows.bat
   ```

10. **Testa från kommandotolken.**

    ```powershell
    .\PHP2Shell-Checker-Windows-x64.exe --version
    ```

    Skrivs `PHP2Shell Checker 1.5.0` följt av buildnummer, byggtid och commit
    ut fungerar filen, och problemet gäller i så fall starten av webbläsaren
    eller servern.

## Smart App Control och S-läge

Windows 11 kan blockera osignerade program. Kontrollera
**Windows-säkerhet → App- och webbläsarkontroll**. Smart App Control kan stängas
av om du litar på filen. Det går inte att slå på igen utan ominstallation.
Windows i **S-läge** kan bara köra program från Microsoft Store.

## Windows på ARM64

Windows 11 ARM kan köra x64-program via emulering. Fungerar det inte, bygg en
egen ARM64-version:

```bat
set CGO_ENABLED=0
set GOOS=windows
set GOARCH=arm64
go build -trimpath -buildvcs=false -ldflags "-s -w" -o PHP2Shell-Checker-Windows-arm64.exe .
```
