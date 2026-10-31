#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

version="$(sed -n 's/.*appVersion[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' server.go | head -1)"
if [ -z "$version" ]; then
  echo "FEL: kunde inte läsa appVersion från server.go" >&2
  exit 1
fi

cd release

echo "Verifierar SHA-256..."
sha256sum -c SHA256SUMS.txt

echo "Verifierar Windows-EXE mot .sha256..."
sha256sum -c PHP2Shell-Checker-Windows-x64.exe.sha256

echo "Verifierar ZIP..."
unzip -tq PHP2Shell-Checker-Windows-x64.zip

echo "Verifierar base64/gzip-reservfil..."
base64 -d PHP2Shell-Checker-Windows-x64.exe.gz.b64 | gzip -t

echo "Kontrollerar Windows-huvud (MZ)..."
magic="$(od -An -tx1 -N2 PHP2Shell-Checker-Windows-x64.exe | tr -d ' \n')"
if [ "$magic" != "4d5a" ]; then
  echo "FEL: Windows-EXE saknar MZ-huvud (fick $magic)" >&2
  exit 1
fi

echo "Kontrollerar Linux-version..."
actual_version="$(./PHP2Shell-Checker-Linux-x64 --version)"
if [ "$actual_version" != "PHP2Shell Checker $version" ]; then
  echo "FEL: Linux-binären rapporterar '$actual_version', förväntade 'PHP2Shell Checker $version'" >&2
  exit 1
fi

echo "Kontrollerar dokumenterad EXE-storlek..."
readme_size="$(sed -n 's/.*\*\*\([0-9][0-9 ]*\) byte\*\*.*/\1/p' ../README.md | head -1 | tr -d ' ')"
exe_size="$(wc -c < PHP2Shell-Checker-Windows-x64.exe | tr -d ' ')"
if [ -n "$readme_size" ] && [ "$readme_size" != "$exe_size" ]; then
  echo "FEL: README anger $readme_size byte men EXE är $exe_size byte" >&2
  exit 1
fi

echo "Kontrollerar release-README..."
head -1 README.txt | grep -q "PHP2Shell Checker $version"

echo
echo "OK: release-paketet är intakt och versionen stämmer."
