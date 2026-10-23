# Aterstaller PHP2Shell-Checker-Windows-x64.exe fran textfilen
# PHP2Shell-Checker-Windows-x64.exe.gz.b64 och verifierar SHA-256.
#
# Anvand denna om vanlig nedladdning av EXE/ZIP blir skadad eller blockeras.
# Kor i mappen dar .b64-filen och SHA256SUMS.txt ligger:
#   powershell -ExecutionPolicy Bypass -File .\restore-windows.ps1

$ErrorActionPreference = 'Stop'

$dir     = Split-Path -Parent $MyInvocation.MyCommand.Path
$b64Path = Join-Path $dir 'PHP2Shell-Checker-Windows-x64.exe.gz.b64'
$gzPath  = Join-Path $dir 'PHP2Shell-Checker-Windows-x64.exe.gz'
$exePath = Join-Path $dir 'PHP2Shell-Checker-Windows-x64.exe'
$sums    = Join-Path $dir 'SHA256SUMS.txt'

if (-not (Test-Path -LiteralPath $b64Path)) {
    Write-Host "Hittar inte $b64Path"
    exit 2
}

Write-Host 'Avkodar base64...'
$bytes = [Convert]::FromBase64String((Get-Content -LiteralPath $b64Path -Raw))
[IO.File]::WriteAllBytes($gzPath, $bytes)

Write-Host 'Packar upp...'
$input  = [IO.File]::OpenRead($gzPath)
$output = [IO.File]::Create($exePath)
try {
    $gzip = New-Object System.IO.Compression.GZipStream(
        $input,
        [System.IO.Compression.CompressionMode]::Decompress)
    try {
        $gzip.CopyTo($output)
    } finally {
        $gzip.Dispose()
    }
} finally {
    $output.Dispose()
    $input.Dispose()
}
Remove-Item -LiteralPath $gzPath -Force

$expected = (Select-String -LiteralPath $sums -Pattern 'PHP2Shell-Checker-Windows-x64\.exe$' |
    Select-Object -First 1).Line -split '\s+' | Select-Object -First 1
$actual = (Get-FileHash -LiteralPath $exePath -Algorithm SHA256).Hash.ToLower()

Write-Host ("Forvantad:  {0}" -f $expected)
Write-Host ("Faktisk:    {0}" -f $actual)

if ($actual -ne $expected) {
    Write-Host ''
    Write-Host 'FEL: kontrollsumman stammer inte. Aven textfilen ar skadad.'
    exit 1
}

try {
    Unblock-File -LiteralPath $exePath -ErrorAction Stop
} catch {
    # Unblock-File finns bara pa Windows; ignorera pa andra system.
}

Write-Host ''
Write-Host 'OK: PHP2Shell-Checker-Windows-x64.exe ar aterstalld och verifierad.'
Write-Host 'Kor programmet med:  .\PHP2Shell-Checker-Windows-x64.exe --version'
exit 0
