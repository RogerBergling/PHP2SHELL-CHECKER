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

VERSION="$("$GO_BIN" run . --version | awk 'NR == 1 {print $3}')"
BUILD_NUMBER="$(git rev-list --count HEAD 2>/dev/null || echo 0)"
BUILD_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUILD_TIME="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
  BUILD_TIME="$(date -u -d "@${SOURCE_DATE_EPOCH}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || printf '%s' "$BUILD_TIME")"
fi
LDFLAGS="-s -w -X main.buildTime=${BUILD_TIME} -X main.buildNumber=${BUILD_NUMBER} -X main.buildCommit=${BUILD_COMMIT}"
mkdir -p release

echo "Bygger PHP2Shell Checker ${VERSION} (build #${BUILD_NUMBER}, ${BUILD_TIME}, ${BUILD_COMMIT})..."

# -buildvcs=false undviker VCS-beroende. Buildnummer, byggtid och commit
# injiceras separat så att gränssnittet kan visa exakt vilken build som körs.
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$GO_BIN" build \
  -trimpath \
  -buildvcs=false \
  -ldflags "$LDFLAGS" \
  -o "release/PHP2Shell-Checker-Linux-x64" .

CGO_ENABLED=0 GOOS=windows GOARCH=amd64 "$GO_BIN" build \
  -trimpath \
  -buildvcs=false \
  -ldflags "$LDFLAGS" \
  -o "release/PHP2Shell-Checker-Windows-x64.exe" .

chmod +x "release/PHP2Shell-Checker-Linux-x64"

# Windowsversionen finns även som ZIP. ZIP har inbyggd CRC-kontroll, vilket
# gör det lättare att upptäcka en ofullständig nedladdning. Verifieringsskriptet
# och EXE-hashen följer med så att ZIP-filen kan kontrolleras direkt efter
# extrahering, även utan SHA256SUMS.txt.
rm -f "release/PHP2Shell-Checker-Windows-x64.zip"
cp LICENSE THIRD_PARTY_NOTICES release/
(
  cd release
  sha256sum "PHP2Shell-Checker-Windows-x64.exe" > "PHP2Shell-Checker-Windows-x64.exe.sha256"
  zip -q -9 "PHP2Shell-Checker-Windows-x64.zip" \
    "PHP2Shell-Checker-Windows-x64.exe" \
    "PHP2Shell-Checker-Windows-x64.exe.sha256" \
    "verify-windows.ps1" \
    "README.txt" \
    "LICENSE" \
    "THIRD_PARTY_NOTICES"
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
    "PHP2Shell-Checker-Windows-x64.exe.gz.b64" \
    "LICENSE" \
    "THIRD_PARTY_NOTICES" > SHA256SUMS.txt
)

echo
echo "Klart:"
ls -lh release
echo
echo "Kontrollsummor finns i release/SHA256SUMS.txt"
