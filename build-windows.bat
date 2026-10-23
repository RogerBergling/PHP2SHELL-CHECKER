@echo off
setlocal
cd /d "%~dp0"

set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64

if not exist release mkdir release

echo Bygger PHP2Shell Checker for Windows...
go build -trimpath -ldflags "-s -w" -o "release\PHP2Shell-Checker-Windows-x64.exe" .
if errorlevel 1 (
  echo Bygget misslyckades.
  exit /b 1
)

echo.
echo Klart: release\PHP2Shell-Checker-Windows-x64.exe
