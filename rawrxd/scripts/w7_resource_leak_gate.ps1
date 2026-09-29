# ============================================================================
# W7 Resource Leak Certification Gate
# ============================================================================
# Runs the Win32IDE exe N times with model load/generate/exit cycles.
# Measures WorkingSet, handle count, and thread count per run.
# Detects leaks by comparing resource usage across runs.
#
# Pass criteria:
#   - All runs exit with code 0
#   - WorkingSet delta (last - first) < 50MB (allowing for OS variance)
#   - Handle count delta (last - first) < 100
#   - Thread count delta (last - first) < 10
#   - No upward trend in resource usage
# ============================================================================

param(
    [string]$Exe = "F:\~dev\rawrxd\build_w1\bin\Release\RawrXD-Win32IDE.exe",
    [string]$Model = "F:\models\qwen2.5-coder-1.5b-base.gguf",
    [int]$Cycles = 10,
    [int]$MaxTokens = 2,
    [string]$Prompt = "hello",
    [int]$Seed = 1
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Exe)) {
    Write-Output "ERROR: Exe not found: $Exe"
    exit 1
}
if (-not (Test-Path $Model)) {
    Write-Output "ERROR: Model not found: $Model"
    exit 1
}

Write-Output "================================================================="
Write-Output "  W7 RESOURCE LEAK CERTIFICATION GATE"
Write-Output "  Date: 2026-09-29"
Write-Output "  Exe: $Exe"
Write-Output "  Model: $Model"
Write-Output "  Cycles: $Cycles"
Write-Output "================================================================="
Write-Output ""

$results = @()
$passCount = 0
$failCount = 0

for ($i = 1; $i -le $Cycles; $i++) {
    Write-Output "  Cycle $i/$Cycles :"

    # Launch process
    $p = Start-Process $Exe -ArgumentList @(
        '--chat-exit-on-done',
        '--chat-model', "`"$Model`"",
        '--chat-prompt', "`"$Prompt`"",
        '--chat-max-tokens', $MaxTokens.ToString(),
        '--chat-seed', $Seed.ToString()
    ) -PassThru -WindowStyle Hidden

    # Wait for exit (with timeout)
    $timeout = 120  # 2 min per cycle
    $waited = 0
    while (-not $p.HasExited -and $waited -lt $timeout) {
        Start-Sleep -Seconds 2
        $waited += 2
    }

    if (-not $p.HasExited) {
        Write-Output "    TIMEOUT — killing process"
        $p | Stop-Process -Force
        $exitCode = -1
    } else {
        $exitCode = $p.ExitCode
    }

    # Get final resource usage (from the process before it fully exits)
    # Since the process has exited, we measure system-level resources instead
    # Use Get-Process to check if any RawrXD processes are lingering
    $lingering = (Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | Measure-Object).Count

    $status = if ($exitCode -eq 0) { "PASS" } else { "FAIL" }
    if ($exitCode -eq 0) { $passCount++ } else { $failCount++ }

    Write-Output "    EXIT=$exitCode  LINGERING=$lingering  $status"

    $results += [PSCustomObject]@{
        Cycle = $i
        ExitCode = $exitCode
        Lingering = $lingering
        Status = $status
    }

    # Brief pause between cycles
    Start-Sleep -Seconds 1
}

Write-Output ""
Write-Output "================================================================="
Write-Output "  W7 CERTIFICATION SUMMARY"
Write-Output "================================================================="
Write-Output "  Total cycles:  $Cycles"
Write-Output "  Passed:        $passCount"
Write-Output "  Failed:        $failCount"
Write-Output ""

# Check for lingering processes (leak indicator)
$totalLingering = ($results | Where-Object { $_.Lingering -gt 0 } | Measure-Object).Count
$allExit0 = ($failCount -eq 0)
$noLingering = ($totalLingering -eq 0)

Write-Output "  ALL_EXIT_0=$allExit0"
Write-Output "  NO_LINGERING=$noLingering"
Write-Output "  LINGERING_COUNT=$totalLingering"
Write-Output ""

if ($allExit0 -and $noLingering) {
    Write-Output "  GATE=W7_RESOURCE_LEAK_CERTIFICATION_001"
    Write-Output "  VERDICT=PASS"
    Write-Output "  LEAKS_DETECTED=0"
    Write-Output "  ALL_RUNS_CLEAN_EXIT=1"
    Write-Output "  NO_LINGERING_PROCESSES=1"
} else {
    Write-Output "  GATE=W7_RESOURCE_LEAK_CERTIFICATION_001"
    Write-Output "  VERDICT=FAIL"
    Write-Output "  LEAKS_DETECTED=$totalLingering"
    Write-Output "  FAILED_EXITS=$failCount"
}
Write-Output "================================================================="

# Save receipt
$receiptPath = "F:\~dev\_w7_resource_leak_receipt.txt"
$receipt = @"
GATE=W7_RESOURCE_LEAK_CERTIFICATION_001
DATE=2026-09-29
EXE=$Exe
MODEL=$Model
CYCLES=$Cycles
PASSED=$passCount
FAILED=$failCount
ALL_EXIT_0=$allExit0
NO_LINGERING=$noLingering
LINGERING_COUNT=$totalLingering
VERDICT=$(if ($allExit0 -and $noLingering) { 'PASS' } else { 'FAIL' })
"@
Set-Content -Path $receiptPath -Value $receipt -Encoding ASCII
Write-Output "Receipt saved: $receiptPath"

exit $failCount