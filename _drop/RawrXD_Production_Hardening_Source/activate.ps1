# Dot-source this file in PowerShell to expose `rawr run` immediately without
# changing or replacing the existing rawr.exe:
#   . F:\rawrxd\tools\rawrxd_parity_final\activate.ps1
# This session-local function is a bridge; native CLI integration is documented
# in PRODUCTION_FINALIZATION.md.

# Locate the runner across every configuration this drop can produce in.
# Order matters: prefer the hardened Release build, fall back to the ASan Debug
# build (which lives in a separate binary dir), then a flat build dir.
$dropRoot   = Split-Path -Parent $PSCommandPath
$candidates = @(
    Join-Path $dropRoot 'build\Release\rawr_run.exe'
    Join-Path $dropRoot 'build\rawr_run.exe'
    Join-Path $dropRoot 'build_asan\Debug\rawr_run.exe'
    Join-Path $dropRoot 'build\bin\Release\rawr_run.exe'
)
$found = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

if (-not $found) {
    throw @"
rawr_run.exe not found. Build it first:

  cmake -S '$dropRoot' -B '$dropRoot\build' -A x64 -DCMAKE_BUILD_TYPE=Release
  cmake --build '$dropRoot\build' --config Release

(see PRODUCTION_FINALIZATION.md)
"@
}

$global:RawrAgentExecutable = $found

# Remember the pre-existing rawr.exe so non-`run` invocations still work.
$original = Get-Command rawr.exe -ErrorAction SilentlyContinue | Select-Object -First 1
$global:RawrOriginalExecutable = if ($original) { $original.Source } else { $null }

# Defensive: refuse to silently use an unhardened runner. The mitigations below
# are what the production drop guarantees; if they are absent the binary was
# built with RAWRXD_ENABLE_HARDENING=OFF and should not be used in production.
function Test-RawrRunnerHardened {
    param([string]$Path)
    try {
        $b   = [System.IO.File]::ReadAllBytes($Path)
        $pe  = [BitConverter]::ToUInt32($b, 0x3C)
        $opt = $pe + 24
        if ([Text.Encoding]::ASCII.GetString($b, $pe, 4) -ne "PE`0`0") { return $false }
        $c = [BitConverter]::ToUInt16($b, $opt + 70)
        return [bool]($c -band 0x0040) -and [bool]($c -band 0x0100) -and [bool]($c -band 0x4000)
    } catch { return $false }
}

$global:RawrAgentHardened = Test-RawrRunnerHardened $global:RawrAgentExecutable

function global:rawr {
    if ($args.Count -gt 0 -and $args[0] -eq 'run') {
        & $global:RawrAgentExecutable @args
        return
    }
    if ($global:RawrOriginalExecutable) {
        & $global:RawrOriginalExecutable @args
        return
    }
    throw 'Original rawr.exe not available; only `rawr run` is supported by this bridge.'
}

Write-Host "RawrXD agent session command ready: rawr run <model> '<task>'"
Write-Host "  runner   : $global:RawrAgentExecutable"
if ($global:RawrAgentHardened) {
    Write-Host "  hardening: OK (ASLR + DEP + CFG present in PE headers)" -ForegroundColor Green
} else {
    Write-Host "  hardening: MISSING - rebuild with -DRAWRXD_ENABLE_HARDENING=ON" -ForegroundColor Yellow
}
Write-Host "  execute  : --allow-exec enables arbitrary processes (trusted sandbox only)"
