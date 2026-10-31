# Changelog

All notable changes are documented here. The project follows semantic
versioning for the application and the local API.

## [1.2.1] - 2026-10-31

### Added

- CI pipeline for formatting, vet, race tests, staticcheck, govulncheck,
  cross-builds and release verification.
- Fuzz tests for URL normalization, PHP version parsing, page analysis and
  deep-check path handling.
- Self-verifying Windows ZIP: `verify-windows.ps1` and an EXE `.sha256` file
  are included in the package.
- `verify-release.sh` for checksums, ZIP/gzip integrity, MZ header, documented
  EXE size and binary version.
- `SECURITY.md`, `CONTRIBUTING.md` and local API documentation.
- `apiVersion` in `/api/health` and `schemaVersion` in JSON exports.

### Security

- API token generation now fails closed if `crypto/rand` fails instead of
  falling back to a predictable static token.
- Added `Permissions-Policy` and stricter HTTP server read limits.
- Added graceful handling of `SIGTERM` in addition to `Ctrl+C`.

### Changed

- Windows ZIP now contains the verification script and EXE checksum.

## [1.2.0] - 2026-10-29

### Added

- Deep PHP version analysis with ranked version candidates.
- Additional header, HTML, JSON, meta-generator, Zend OPcache and phpinfo
  detection.
- Document-root fallback and more diagnostic probes.
- Deep-check evidence in the UI, HTML report, JSON and CSV.
- Version candidates and deep-check details in exports.

### Fixed

- Zend Engine versions are converted to the corresponding PHP release.
  Zend `4.3.14` is now correctly interpreted as PHP `8.3.14`, not PHP
  `4.3.14`.
- Incomplete versions such as `8.4` can be completed from a more precise
  source such as a phpinfo page.

## [1.1.1] - 2026-10-29

### Fixed

- CSV and JSON exports now include all results, not only the filtered view.
- CSV export neutralizes spreadsheet formula injection.
- User-Agent input is trimmed, length-limited and CRLF-sanitized.
- Invalid or overflowing PHP version numbers are rejected.
- Version and User-Agent defaults now come from one source.

### Added

- Regression tests for authorization, security headers, evidence and version
  parsing.

## [1.1.0] - 2026-10-23

### Added

- Separate advisory for CVE-2026-115560 and `session.upload_progress`.
- Windows download verification and base64/gzip fallback.

## [1.0.0] - 2026-10-23

### Added

- Initial local web UI, PHP2Shell version assessment and release binaries.
