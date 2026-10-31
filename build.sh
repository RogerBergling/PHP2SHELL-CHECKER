#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

GO_BIN="${GO:-go}"
for tool in "$GO_BIN" zip gzip base64 sha256sum; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Saknar verktyget: $tool" >&2
    exit 1
  fi
done

VERSION="$("$GO_BIN" run . --version | awk '{print $3}')"
mkdir -p release

echo "Bygger PHP2Shell Checker ${VERSION}..."

# -buildvcs=false gör att binärerna blir identiska oavsett git-status.
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$GO_BIN" build \
  -trimpath \
  -buildvcs=false \
  -ldflags "-s -w" \
  -o "release/PHP2Shell-Checker-Linux-x64" .

CGO_ENABLED=0 GOOS=windows GOARCH=amd64 "$GO_BIN" build \
  -trimpath \
  -buildvcs=false \
  -ldflags "-s -w" \
  -o "release/PHP2Shell-Checker-Windows-x64.exe" .

chmod +x "release/PHP2Shell-Checker-Linux-x64"

# Windowsversionen finns även som ZIP. ZIP har inbyggd CRC-kontroll, vilket
# gör det lättare att upptäcka en ofullständig nedladdning. Verifieringsskriptet
# och EXE-hashen följer med så att ZIP-filen kan kontrolleras direkt efter
# extrahering, även utan SHA256SUMS.txt.
rm -f "release/PHP2Shell-Checker-Windows-x64.zip"
(
  cd release
  sha256sum "PHP2Shell-Checker-Windows-x64.exe" > "PHP2Shell-Checker-Windows-x64.exe.sha256"
  zip -q -9 "PHP2Shell-Checker-Windows-x64.zip" \
    "PHP2Shell-Checker-Windows-x64.exe" \
    "PHP2Shell-Checker-Windows-x64.exe.sha256" \
    "verify-windows.ps1" \
    "README.txt"
)

# Extra reservväg: base64-kodad gzip av EXE-filen. Text klarar sig förbi
# nedladdningsfilter som skadar eller blockerar binärfiler. Återställs med
# release/restore-windows.ps1.
gzip -9 -n -c "release/PHP2Shell-Checker-Windows-x64.exe" \
  | base64 -w 76 > "release/PHP2Shell-Checker-Windows-x64.exe.gz.b64"

(
  cd release
  sha256sum \
    "PHP2Shell-Checker-Linux-x64" \
    "PHP2Shell-Checker-Windows-x64.exe" \
    "PHP2Shell-Checker-Windows-x64.exe.sha256" \
    "PHP2Shell-Checker-Windows-x64.zip" \
    "PHP2Shell-Checker-Windows-x64.exe.gz.b64" > SHA256SUMS.txt
)

echo
echo "Klart:"
ls -lh release
echo
echo "Kontrollsummor finns i release/SHA256SUMS.txt"
