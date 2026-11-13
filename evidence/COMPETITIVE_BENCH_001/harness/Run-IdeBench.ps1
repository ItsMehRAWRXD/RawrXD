#Requires -Version 5.1
<#
.SYNOPSIS
  Minimal IDE-Bench stub: proves IDE binary presence + SHA; optional --help smoke.
  Does NOT invent parity scores or launch interactive GUI as PASS.
.NOTES
  PROMOTE=0 · NOT_RUN != PASS · SOURCE_WIRED != RUNTIME_REACHED
#>
param(
    [string]$IdeExe = (Join-Path $PSScriptRoot '..\..\..\bin\RawrXD-Win32IDE.exe'),
    [string]$OutDir = (Join-Path $PSScriptRoot '..\logs'),
    [switch]$TryHelp
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
if (-not (Test-Path $IdeExe)) {
    Write-Host "IDE_BENCH=NOT_RUN missing=$IdeExe"
    exit 2
}
$item = Get-Item $IdeExe
$sha = (Get-FileHash $IdeExe -Algorithm SHA256).Hash
$report = Join-Path $OutDir 'ide_bench_presence.txt'
@(
    "SUITE=IDE_BENCH_PRESENCE"
    "COMMAND=Get-FileHash $IdeExe"
    "PATH=$($item.FullName)"
    "SIZE=$($item.Length)"
    "SHA256=$sha"
    "PROMOTE=0"
    "GUI_E2E=NOT_RUN"
    "PARITY_SCORE=NOT_MEASURED"
) | Set-Content -Path $report -Encoding ASCII
Write-Host (Get-Content $report -Raw)
if ($TryHelp) {
    $job = Start-Job { param($e) & $e --help 2>&1; $LASTEXITCODE } -ArgumentList $IdeExe
    $ok = Wait-Job $job -Timeout 5
    if (-not $ok) {
        Stop-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        Write-Host 'IDE_HELP=TIMEOUT (GUI binary; no CLI help contract)'
        exit 0
    }
    Receive-Job $job
    Remove-Job $job -Force -ErrorAction SilentlyContinue
}
exit 0
