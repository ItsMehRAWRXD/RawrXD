#Requires -Version 5.1
<#
.SYNOPSIS
  Minimal Terminal-Bench stub: invokes real terminal_gate.exe (no fake scores).
.NOTES
  PROMOTE=0 · NOT_RUN != PASS
#>
param(
    [string]$TerminalGateExe = (Join-Path $PSScriptRoot '..\..\FOUR_PANEL_COMPLETION_001\bin\terminal_gate.exe'),
    [string]$OutDir = (Join-Path $PSScriptRoot '..\logs')
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
if (-not (Test-Path $TerminalGateExe)) {
    Write-Host "TERMINAL_BENCH=NOT_RUN missing=$TerminalGateExe"
    exit 2
}
$sha = (Get-FileHash $TerminalGateExe -Algorithm SHA256).Hash
$out = Join-Path $OutDir 'terminal_bench_run.out.txt'
$err = Join-Path $OutDir 'terminal_bench_run.err.txt'
$wd = Split-Path $TerminalGateExe -Parent
$p = Start-Process -FilePath $TerminalGateExe -WorkingDirectory $wd -NoNewWindow -Wait -PassThru `
    -RedirectStandardOutput $out -RedirectStandardError $err
Write-Host "COMMAND=$TerminalGateExe"
Write-Host "SHA256=$sha"
Write-Host "EXIT=$($p.ExitCode)"
Get-Content $out -ErrorAction SilentlyContinue
exit $p.ExitCode
