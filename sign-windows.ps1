# Signs and verifies the Windows release binary with Authenticode.
#
# Recommended: install the certificate in the Windows certificate store and
# pass its SHA-1 thumbprint. For CI, pass a PFX path and password via secret
# environment variables. Never commit a PFX file or its password.
#
# Example:
#   .\sign-windows.ps1 -Path .\release\PHP2Shell-Checker-Windows-x64.exe `
#       -Thumbprint 0123456789ABCDEF0123456789ABCDEF01234567

param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$Thumbprint,
    [string]$PfxPath,
    [string]$PfxPassword,
    [string]$TimestampUrl = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Error "Hittar inte filen: $Path"
    exit 2
}

$signtool = $null
$command = Get-Command signtool.exe -ErrorAction SilentlyContinue
if ($command) {
    $signtool = $command.Source
} else {
    $kits = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" `
        -ErrorAction SilentlyContinue | Sort-Object FullName -Descending
    if ($kits) {
        $signtool = $kits[0].FullName
    }
}

if (-not $signtool) {
    Write-Error 'signtool.exe hittades inte. Installera Windows SDK eller lagg det i PATH.'
    exit 3
}

if (-not $PfxPassword -and $env:WINDOWS_PFX_PASSWORD) {
    $PfxPassword = $env:WINDOWS_PFX_PASSWORD
}

$signArgs = @('sign', '/fd', 'SHA256', '/tr', $TimestampUrl, '/td', 'SHA256')
if ($Thumbprint) {
    $signArgs += @('/sha1', $Thumbprint)
} elseif ($PfxPath) {
    $signArgs += @('/f', $PfxPath)
    if ($PfxPassword) {
        $signArgs += @('/p', $PfxPassword)
    }
} else {
    Write-Error 'Ange -Thumbprint eller -PfxPath.'
    exit 4
}
$signArgs += $Path

Write-Host "Signerar $Path..."
& $signtool @signArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "Signeringen misslyckades (exit $LASTEXITCODE)."
    exit $LASTEXITCODE
}

Write-Host 'Verifierar signaturen...'
& $signtool verify /pa /v $Path
if ($LASTEXITCODE -ne 0) {
    Write-Error "Signaturverifieringen misslyckades (exit $LASTEXITCODE)."
    exit $LASTEXITCODE
}

Write-Host 'OK: filen ar signerad och signaturen verifierades.'
exit 0
