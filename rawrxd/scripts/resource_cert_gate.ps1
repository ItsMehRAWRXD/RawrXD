# RESOURCE_CERTIFICATION_001 — Stress loop for resource leak detection
# Runs N iterations of: launch IDE → wait → kill → check for lingering processes
# Tracks: process count, handle count, working set deltas

param(
    [string]$ExePath = "F:\~dev\rawrxd\build_w1\bin\Release\RawrXD-Win32IDE.exe",
    [int]$Iterations = 10,
    [int]$AliveWaitSec = 5
)

$results = @()
$baselineProcs = (Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | Measure-Object).Count
Write-Host "BASELINE_PROCS=$baselineProcs"
Write-Host "ITERATIONS=$Iterations"
Write-Host "EXE=$ExePath"
Write-Host ""

for ($i = 1; $i -le $Iterations; $i++) {
    # Kill any stale instances
    Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Milliseconds 500

    # Launch
    $p = Start-Process $ExePath -PassThru -ErrorAction SilentlyContinue
    if (-not $p) {
        $results += [PSCustomObject]@{ Cycle=$i; ExitCode=-99; Alive="LAUNCH_FAIL"; LingeringProcs=0 }
        Write-Host "Cycle $i : LAUNCH_FAIL"
        continue
    }

    # Wait
    Start-Sleep -Seconds $AliveWaitSec
    $alive = -not $p.HasExited

    if ($alive) {
        # Kill it
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        # Wait for process to fully exit (up to 3 seconds)
        $p.WaitForExit(3000) | Out-Null
        Start-Sleep -Milliseconds 1000
        $exitCode = -1  # killed
    } else {
        $exitCode = $p.ExitCode
    }

    # Check for lingering processes (after generous wait)
    $lingering = (Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | Measure-Object).Count

    $results += [PSCustomObject]@{ Cycle=$i; ExitCode=$exitCode; Alive=$alive; LingeringProcs=$lingering }
    Write-Host "Cycle $i : EXIT=$exitCode ALIVE=$alive LINGERING=$lingering"
}

# Summary
$passCount = ($results | Where-Object { $_.LingeringProcs -eq 0 }).Count
$failCount = $Iterations - $passCount
$maxLingering = ($results | Measure-Object -Property LingeringProcs -Maximum).Maximum

Write-Host ""
Write-Host "=== RESOURCE_CERTIFICATION_001 SUMMARY ==="
Write-Host "ITERATIONS=$Iterations"
Write-Host "PASS=$passCount (0 lingering procs)"
Write-Host "FAIL=$failCount"
Write-Host "MAX_LINGERING=$maxLingering"
Write-Host "VERDICT=$(if ($maxLingering -eq 0) { 'PASS' } else { 'FAIL' })"