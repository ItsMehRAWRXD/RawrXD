# Dot-source this file in PowerShell to expose rawr run immediately without
# changing or replacing the existing rawr.exe:
# . F:\rawrxd\tools\rawr_parity_final\activate.ps1
# This session-local function is a bridge; native CLI integration is documented.
$global:RawrAgentExecutable = Join-Path (Split-Path -Parent $PSCommandPath) 'build\Release\rawr_run.exe'
if (-not (Test-Path $global:RawrAgentExecutable)) {
    $global:RawrAgentExecutable = Join-Path (Split-Path -Parent $PSCommandPath) 'build\rawr_run.exe'
}
if (-not (Test-Path $global:RawrAgentExecutable)) {
    $global:RawrAgentExecutable = Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))) 'build_rawr_run\Release\rawr_run.exe'
}
if (-not (Test-Path $global:RawrAgentExecutable)) {
    throw "Build rawr_run.exe first with CMake (see INTEGRATE_INTO_RAWR.md) or update RawrAgentExecutable."
}
$original = Get-Command rawr.exe -ErrorAction SilentlyContinue | Select-Object -First 1
$global:RawrOriginalExecutable = if ($original) { $original.Source } else { $null }
function global:rawr {
    if ($args.Count -gt 0 -and $args[0] -eq 'run') {
        & $global:RawrAgentExecutable @args
        return
    }
    if ($global:RawrOriginalExecutable) {
        & $global:RawrOriginalExecutable @args
        return
    }
    throw 'Original rawr.exe not available; only rawr run is supported.'
}
Write-Host "RawrXD agent session command ready: rawr run <model> '<task>'"
