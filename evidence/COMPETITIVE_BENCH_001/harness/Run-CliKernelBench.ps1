#Requires -Version 5.1
<#
.SYNOPSIS
  Minimal CLI kernel stub: SovereignCLI status/version/validate/benchmark.
.NOTES
  PROMOTE=0 · NOT_RUN != PASS
#>
param(
    [string]$CliExe = (Join-Path $PSScriptRoot '..\..\..\bin\SovereignCLI.exe'),
    [string]$OutDir = (Join-Path $PSScriptRoot '..\logs'),
    [int]$BenchIter = 100
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
if (-not (Test-Path $CliExe)) {
    Write-Host "CLI_KERNEL=NOT_RUN missing=$CliExe"
    exit 2
}
$sha = (Get-FileHash $CliExe -Algorithm SHA256).Hash
Write-Host "COMMAND_BASE=$CliExe"
Write-Host "SHA256=$sha"
$fail = 0
foreach ($args in @(@('status'), @('version'), @('validate'), @('benchmark', '--iter', "$BenchIter"))) {
    $tag = ($args -join '_')
    $out = Join-Path $OutDir "cli_$tag.out.txt"
    $err = Join-Path $OutDir "cli_$tag.err.txt"
    $p = Start-Process -FilePath $CliExe -ArgumentList $args -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $out -RedirectStandardError $err
    Write-Host "RUN=$($args -join ' ') EXIT=$($p.ExitCode)"
    if ($p.ExitCode -ne 0) { $fail++ }
}
exit $(if ($fail -gt 0) { 1 } else { 0 })
