# Verifierar en nedladdad PHP2Shell Checker-fil mot SHA256SUMS.txt.
#
# Kor sahar (i mappen dar filerna ligger):
#   powershell -ExecutionPolicy Bypass -File .\verify-windows.ps1
#
# Eller med en annan sokvag:
#   powershell -ExecutionPolicy Bypass -File .\verify-windows.ps1 -Path C:\Temp\PHP2Shell-Checker-Windows-x64.exe

param([string]$Path)

$ErrorActionPreference = 'Stop'

$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Path) { $Path = Join-Path $dir 'PHP2Shell-Checker-Windows-x64.exe' }
$sums = Join-Path $dir 'SHA256SUMS.txt'
$name = Split-Path -Leaf $Path

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Host "Hittar inte filen: $Path"
    exit 2
}

try {
    $item = Get-Item -LiteralPath $Path
    Write-Host ("Fil:        {0}" -f $item.FullName)
    Write-Host ("Storlek:    {0} byte" -f $item.Length)

    if ($item.Length -eq 0) {
        Write-Host ''
        Write-Host 'Filen ar 0 byte. Nedladdningen misslyckades - ladda ner igen.'
        exit 2
    }

    $stream = [IO.File]::OpenRead($item.FullName)
    $buffer = New-Object byte[] 2
    $read = $stream.Read($buffer, 0, 2)
    $stream.Dispose()
    $magic = ($buffer[0..($read - 1)] | ForEach-Object { $_.ToString('X2') }) -join ' '
    Write-Host ("Forsta byte: {0}" -f $magic)
} catch {
    Write-Host ''
    Write-Host ("Kunde inte lasa filen: {0}" -f $_.Exception.Message)
    Write-Host 'Detta ar ett filsystemsfel (0x80070570), inte ett fel i programmet.'
    Write-Host 'Ladda ner filen igen, till en annan mapp eller disk, och kor chkdsk.'
    exit 3
}

$expected = (Select-String -LiteralPath $sums -Pattern ([regex]::Escape($name) + '$') |
    Select-Object -First 1).Line -split '\s+' | Select-Object -First 1

if (-not $expected) {
    Write-Host "Hittar ingen kontrollsumma for $name i SHA256SUMS.txt"
    exit 4
}

$actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower()

Write-Host ("Forvantad:  {0}" -f $expected)
Write-Host ("Faktisk:    {0}" -f $actual)

if ($actual -ne $expected) {
    Write-Host ''
    Write-Host 'FEL: kontrollsumman stammer inte. Filen ar ofullstandig eller andrad.'
    Write-Host 'Ladda ner filen igen. Om felet aterkommer, anvand reservvagen:'
    Write-Host '  1. Ladda ner PHP2Shell-Checker-Windows-x64.exe.gz.b64 (textfil).'
    Write-Host '  2. Kor: powershell -ExecutionPolicy Bypass -File .\restore-windows.ps1'
    exit 1
}

Write-Host ''
Write-Host 'OK: filen ar intakt.'
exit 0
