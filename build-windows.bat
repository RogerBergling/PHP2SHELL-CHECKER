@echo off
setlocal
cd /d "%~dp0"

set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64

set "BUILD_TIME=development"
for /f "delims=" %%i in ('powershell -NoProfile -ExecutionPolicy Bypass -File build-time.ps1') do set "BUILD_TIME=%%i"
set "BUILD_NUMBER=0"
for /f "delims=" %%i in ('git rev-list --count HEAD 2^>nul') do set "BUILD_NUMBER=%%i"
set "BUILD_COMMIT=unknown"
for /f "delims=" %%i in ('git rev-parse --short HEAD 2^>nul') do set "BUILD_COMMIT=%%i"
set "LDFLAGS=-s -w -X main.buildTime=%BUILD_TIME% -X main.buildNumber=%BUILD_NUMBER% -X main.buildCommit=%BUILD_COMMIT%"

if not exist release mkdir release

echo Bygger PHP2Shell Checker for Windows (build #%BUILD_NUMBER%, %BUILD_TIME%, %BUILD_COMMIT%)...
go build -trimpath -buildvcs=false -ldflags "%LDFLAGS%" -o "release\PHP2Shell-Checker-Windows-x64.exe" .
if errorlevel 1 (
  echo Bygget misslyckades.
  exit /b 1
)

if defined WINDOWS_CERT_THUMBPRINT (
  echo Signerar EXE...
  powershell -NoProfile -ExecutionPolicy Bypass -File sign-windows.ps1 -Path "release\PHP2Shell-Checker-Windows-x64.exe" -Thumbprint "%WINDOWS_CERT_THUMBPRINT%"
  if errorlevel 1 (
    echo Signeringen misslyckades.
    exit /b 1
  )
)

echo Skapar EXE-kontrollsumma...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$h=(Get-FileHash 'release\PHP2Shell-Checker-Windows-x64.exe' -Algorithm SHA256).Hash.ToLower(); $h + '  PHP2Shell-Checker-Windows-x64.exe' | Set-Content -Encoding ASCII 'release\PHP2Shell-Checker-Windows-x64.exe.sha256'"
if errorlevel 1 (
  echo Kunde inte skapa EXE-kontrollsumma.
  exit /b 1
)

copy /Y LICENSE release\LICENSE >nul
copy /Y THIRD_PARTY_NOTICES release\THIRD_PARTY_NOTICES >nul

echo Paketerar ZIP...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Compress-Archive -Force -Path 'release\PHP2Shell-Checker-Windows-x64.exe','release\PHP2Shell-Checker-Windows-x64.exe.sha256','release\verify-windows.ps1','release\README.txt','release\LICENSE','release\THIRD_PARTY_NOTICES' -DestinationPath 'release\PHP2Shell-Checker-Windows-x64.zip'"
if errorlevel 1 (
  echo Kunde inte skapa ZIP.
  exit /b 1
)

echo.
echo Klart:
echo   release\PHP2Shell-Checker-Windows-x64.exe
echo   release\PHP2Shell-Checker-Windows-x64.zip
echo.
echo SHA256 for EXE:
certutil -hashfile "release\PHP2Shell-Checker-Windows-x64.exe" SHA256
