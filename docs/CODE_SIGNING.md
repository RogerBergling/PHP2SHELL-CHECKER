# Windows code signing

An unsigned executable can trigger SmartScreen, AppLocker, WDAC, Windows
Defender and third-party EDR products such as Check Point Harmony. A SHA-256
checksum proves integrity, but it does not prove who built the file.

Sign the release EXE with a trusted Authenticode certificate and a timestamp.
An EV certificate gives the strongest reputation, but OV certificates are also
valid when combined with EDR allowlisting and vendor false-positive review.

## Certificate options

Use one of these:

1. **Certificate store (recommended for build agents)**
   Install the certificate and private key in the Windows certificate store and
   pass the SHA-1 thumbprint.
2. **PFX file**
   Keep the PFX and password in a secret manager. Never commit either file.

## Sign with a certificate-store thumbprint

```powershell
.\sign-windows.ps1 `
  -Path .\release\PHP2Shell-Checker-Windows-x64.exe `
  -Thumbprint 0123456789ABCDEF0123456789ABCDEF01234567
```

## Sign with a PFX

```powershell
$secure = Read-Host 'PFX password' -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    .\sign-windows.ps1 `
      -Path .\release\PHP2Shell-Checker-Windows-x64.exe `
      -PfxPath C:\secrets\codesign.pfx `
      -PfxPassword $password
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    Remove-Variable password -ErrorAction SilentlyContinue
}
```

The script signs with SHA-256 and a timestamp, then runs:

```text
signtool verify /pa /v <exe>
```

## Build integration

`build-windows.bat` signs automatically when `WINDOWS_CERT_THUMBPRINT` is set:

```bat
set WINDOWS_CERT_THUMBPRINT=0123456789ABCDEF0123456789ABCDEF01234567
build-windows.bat
```

The signing step runs before the checksum and ZIP are created, so the packaged
EXE is the signed file.

## Verify the signature

On Windows:

```powershell
Get-AuthenticodeSignature .\release\PHP2Shell-Checker-Windows-x64.exe
```

For an enterprise-required signature check:

```powershell
powershell -ExecutionPolicy Bypass -File .\verify-windows.ps1 -RequireSignature
```

`verify-windows.ps1` still verifies the SHA-256 checksum. `-RequireSignature`
additionally requires a valid Authenticode signature.

## CI secrets

Keep the PFX and password in GitHub Actions secrets or an enterprise secret
manager. Never put them in a workflow file, repository variable or release
artifact. Prefer a certificate-store deployment on a dedicated Windows signing
runner.

## EDR false positives

Code signing reduces but does not eliminate false positives. Submit the signed
binary hash and sample to the EDR vendor for reclassification, and ask the
enterprise administrator to allowlist the publisher or hash.

Suggested submission details:

- product: PHP2Shell Checker
- version and SHA-256
- publisher/common name
- why it is a defensive scanner
- link to this repository and security policy
