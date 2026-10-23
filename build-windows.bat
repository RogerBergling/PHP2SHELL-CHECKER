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

echo Paketerar ZIP...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Compress-Archive -Force -Path 'release\PHP2Shell-Checker-Windows-x64.exe','release\README.txt' -DestinationPath 'release\PHP2Shell-Checker-Windows-x64.zip'"
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
