#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

GO_BIN="${GO:-go}"
VERSION="$("$GO_BIN" run . --version | awk '{print $3}')"
mkdir -p release

echo "Bygger PHP2Shell Checker ${VERSION}..."

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$GO_BIN" build \
  -trimpath \
  -ldflags "-s -w" \
  -o "release/PHP2Shell-Checker-Linux-x64" .

CGO_ENABLED=0 GOOS=windows GOARCH=amd64 "$GO_BIN" build \
  -trimpath \
  -ldflags "-s -w" \
  -o "release/PHP2Shell-Checker-Windows-x64.exe" .

chmod +x "release/PHP2Shell-Checker-Linux-x64"

(
  cd release
  sha256sum \
    "PHP2Shell-Checker-Linux-x64" \
    "PHP2Shell-Checker-Windows-x64.exe" > SHA256SUMS.txt
)

echo
echo "Klart:"
ls -lh release
echo
echo "Kontrollsummor finns i release/SHA256SUMS.txt"
