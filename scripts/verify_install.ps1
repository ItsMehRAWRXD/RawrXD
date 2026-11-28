#requires -Version 5.1
<#
.SYNOPSIS
  Verifies a portable RawrXD installation from a directory outside the build
  tree with no developer-specific RAWRXD_* overrides (M-CFG-07).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InstallDir,
    [string]$CliName = 'rawr.exe'
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path $InstallDir)) { throw "install dir not found: $InstallDir" }
$cli = Get-ChildItem -LiteralPath $InstallDir -Recurse -Filter $CliName -File | Select-Object -First 1
if (-not $cli) { $cli = Get-ChildItem -LiteralPath $InstallDir -Recurse -Filter 'RawrXD-CLI-V2.exe' -File | Select-Object -First 1 }
if (-not $cli) { throw "$CliName not found under $InstallDir" }

$old = @{}
foreach ($k in [Environment]::GetEnvironmentVariables().Keys) {
    if ($k -like 'RAWRXD_*') { $old[$k] = [Environment]::GetEnvironmentVariable($k); [Environment]::SetEnvironmentVariable($k, $null) }
}

try {
    $ErrorActionPreference = 'Continue'
    $out = & $cli.FullName --help 2>$null
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    Write-Host "exit=$code"
    Write-Host ($out -join "`n")
    if ($code -ne 0) { throw "CLI --help failed with exit $code" }
    if (-not (Test-Path (Join-Path $InstallDir 'share/rawrxd'))) {
        Write-Warning 'share/rawrxd missing (shaders/registry not installed)'
    }
    Write-Host 'PORTABLE_INSTALL=PASS'
} finally {
    foreach ($k in $old.Keys) { [Environment]::SetEnvironmentVariable($k, $old[$k]) }
}