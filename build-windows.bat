@echo off
setlocal
cd /d "%~dp0"

set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64

if not exist release mkdir release

echo Bygger PHP2Shell Checker for Windows...
go build -trimpath -buildvcs=false -ldflags "-s -w" -o "release\PHP2Shell-Checker-Windows-x64.exe" .
if errorlevel 1 (
  echo Bygget misslyckades.
  exit /b 1
)

echo Skapar EXE-kontrollsumma...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$h=(Get-FileHash 'release\PHP2Shell-Checker-Windows-x64.exe' -Algorithm SHA256).Hash.ToLower(); $h + '  PHP2Shell-Checker-Windows-x64.exe' | Set-Content -Encoding ASCII 'release\PHP2Shell-Checker-Windows-x64.exe.sha256'"
if errorlevel 1 (
  echo Kunde inte skapa EXE-kontrollsumma.
  exit /b 1
)

echo Paketerar ZIP...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Compress-Archive -Force -Path 'release\PHP2Shell-Checker-Windows-x64.exe','release\PHP2Shell-Checker-Windows-x64.exe.sha256','release\verify-windows.ps1','release\README.txt' -DestinationPath 'release\PHP2Shell-Checker-Windows-x64.zip'"
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
