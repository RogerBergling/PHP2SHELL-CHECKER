# Contributing

## Requirements

- Go 1.27 or newer
- `zip`, `gzip`, `base64` and `sha256sum` for release builds
- PowerShell on Windows for packaged verification scripts

The application has no third-party Go modules.

## Local checks

```bash
gofmt -l .
go vet ./...
go test ./...
go test -race ./...
```

Optional but recommended:

```bash
go install honnef.co/go/tools/cmd/staticcheck@v0.8.2
go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
staticcheck ./...
govulncheck ./...
```

Fuzz targets can be run with, for example:

```bash
go test -run '^$' -fuzz FuzzAnalyzePage -fuzztime 30s
```

## Release process

1. Update `appVersion` in `server.go`.
2. Update the version and EXE size in `README.md` and `release/README.txt`.
3. Update `CHANGELOG.md`.
4. Run the full test suite.
5. Build the release:

   ```bash
   ./build.sh
   ```

6. Verify the bundle:

   ```bash
   ./verify-release.sh
   ```

7. Commit the source, documentation and rebuilt `release/` artifacts together.

Do not reuse an old release binary with a new version string. Rebuild both
Linux and Windows binaries from the same commit.

## Code style

- Keep the scanner non-invasive: ordinary GET requests only, no exploit
  payloads and no uploads.
- New detection heuristics should include a regression test.
- Keep evidence fields additive so older JSON/CSV consumers keep working.
- Prefer standard-library dependencies unless there is a strong reason.

## Reporting security issues

See [SECURITY.md](SECURITY.md).
