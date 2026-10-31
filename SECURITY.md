# Security Policy

## Supported versions

Security fixes are provided for the latest released 1.x version. Older
binaries in `release/` should be replaced with the current release.

| Version | Supported |
| --- | --- |
| 1.3.x | Yes |
| 1.2.x and older | No |

## Reporting a vulnerability

Please **do not open a public GitHub issue** for a security problem.

Use GitHub's private vulnerability reporting:

1. Open the repository on GitHub.
2. Go to **Security** → **Advisories** → **Report a vulnerability**.
3. Include:
   - affected version,
   - platform,
   - reproduction steps,
   - impact,
   - any suggested fix.

Please avoid including real customer data, access tokens, cookies or other
secrets in the report.

## Scope

Relevant reports include, for example:

- bypasses of the local token, Host or Origin checks,
- command or HTML injection in the UI or reports,
- unsafe handling of scanned response data,
- release-package tampering or checksum problems,
- privilege escalation or unexpected file/network access.

The following are not vulnerabilities in this project:

- findings produced by scanning an intentionally vulnerable target,
- CDN, WAF or reverse-proxy behaviour that hides PHP,
- EDR or antivirus products blocking the unsigned Windows binary,
- outdated PHP versions on the scanned target.

## Disclosure

Please allow a reasonable period for a fix and a coordinated release before
publishing details. Credit can be included on request.
