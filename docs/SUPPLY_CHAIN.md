# Supply-chain and release security

## Repository controls

Enable these GitHub controls for the `main` branch:

- Require pull requests and at least one approving review.
- Require the CI `test` and `windows` jobs before merging.
- Require signed commits.
- Block force pushes and branch deletion.
- Enable secret scanning and push protection.
- Restrict who can create release tags.

## Actions pinning

GitHub Actions are pinned to full commit SHAs in `.github/workflows/ci.yml`.
Dependabot may update the pinned action versions, but every update must be
reviewed like source code.

## Go toolchain

The module declares the exact patch toolchain in `go.mod`:

```text
toolchain go1.27.3
```

CI installs the same version explicitly. Update the patch version deliberately
and rerun the full validation suite and release verification.

## Release process

1. Update `appVersion` and `CHANGELOG.md`.
2. Update documented version and binary size.
3. Run `go test`, `go vet`, `staticcheck`, `govulncheck`, fuzz targets and the
   performance benchmark.
4. Build with `./build.sh` or `build-windows.bat`.
5. Sign the Windows EXE with `sign-windows.ps1` and a trusted certificate.
6. Run `./verify-release.sh` and `verify-windows.ps1 -RequireSignature`.
7. Create an immutable signed Git tag.
8. Publish the release through GitHub Releases with:
   - signed Windows EXE and ZIP,
   - Linux binary,
   - base64 fallback,
   - `SHA256SUMS.txt`,
   - signature files,
   - SBOM,
   - release notes.
9. Submit the signed Windows hash to EDR vendors for reputation and
   false-positive review.

## SBOM and provenance

Generate an SBOM for every published release. Recommended formats are
CycloneDX and SPDX. Attach the SBOM to the release and, where supported, publish
SLSA provenance/artifact attestations for the binaries.

The application has no third-party Go modules, but the Go runtime and standard
library must still be listed in the SBOM and covered by
`THIRD_PARTY_NOTICES`.

## Artifact integrity

SHA-256 checksums detect corruption but do not authenticate the publisher.
For enterprise distribution, sign both the binaries and the checksum file.

Recommended tools:

- Authenticode for Windows.
- minisign, cosign or GPG for Linux binaries and checksums.
- Signed Git tags for the exact source commit.

## Release repository hygiene

The checked-in `release/` artifacts are convenient for direct downloads but
increase repository size and history. For enterprise distribution, prefer
immutable GitHub Releases and keep only release metadata in the repository.
