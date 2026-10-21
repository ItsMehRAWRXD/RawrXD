# B013 Correctness + Long-Run Residency Stability Experiment Runner v2
# Runs b013_stability_test.exe for all 6 scenarios with PER-SCENARIO immutable logs.
# Each scenario gets its own stdout, stderr, and JSON result file.
# Prevents evidence loss from shared-file overwrite.

$modelPath = "F:\Franken\BackwardsUnlock\1b\unlock-1B-Q4_K_M.gguf"
$exePath = "d:\rawrxd\build-pmm-validate\bin\b013_stability_test.exe"
$resultsFile = "d:\rawrxd\B013\performance\b013_raw_results.jsonl"
$logDir = "d:\rawrxd\B013\logs"

$scenarios = @(0, 1, 2, 3, 4, 5)
$scenarioNames = @(
    "repeated_generations",
    "unload_reload",
    "context_reset",
    "memory_growth",
    "equivalence_b010_b011",
    "sustained_run"
)

if (!(Test-Path $exePath)) {
    Write-Error "Binary not found: $exePath"
    exit 1
}

# Ensure log directory exists
if (!(Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

# Clear previous aggregate results
if (Test-Path $resultsFile) {
    Remove-Item $resultsFile
}

$runSummary = @()

for ($i = 0; $i -lt $scenarios.Count; $i++) {
    $scenario = $scenarios[$i]
    $name = $scenarioNames[$i]
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $stdoutPath = "$logDir\scenario_$($scenario.ToString().PadLeft(2,'0'))_${name}_${timestamp}.stdout.log"
    $stderrPath = "$logDir\scenario_$($scenario.ToString().PadLeft(2,'0'))_${name}_${timestamp}.stderr.log"
    $jsonPath   = "$logDir\scenario_$($scenario.ToString().PadLeft(2,'0'))_${name}_${timestamp}.json"

    Write-Host "========================================"
    Write-Host "[$timestamp] Running scenario $scenario : $name ..."
    Write-Host "  stdout -> $stdoutPath"
    Write-Host "  stderr -> $stderrPath"
    Write-Host "  json   -> $jsonPath"
    Write-Host "========================================"

    $startTime = Get-Date
    $env:RAWRXD_TEST_MODEL = $modelPath

    $proc = Start-Process -FilePath $exePath -ArgumentList "$scenario" -PassThru -Wait `
        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    $exitCode = $proc.ExitCode
    $endTime = Get-Date
    $elapsed = [math]::Round(($endTime - $startTime).TotalSeconds, 1)

    $status = if ($exitCode -eq 0) { "PASS" } else { "FAIL/CRASH" }
    $crash = if ($exitCode -ne 0) { $true } else { $false }

    Write-Host "  Status: $status | ExitCode: $exitCode | Elapsed: ${elapsed}s"

    # Extract JSON block from stdout into its own file
    $stdout = Get-Content $stdoutPath -Raw -ErrorAction SilentlyContinue
    $jsonStart = $stdout.IndexOf("{")
    $jsonEnd = $stdout.LastIndexOf("}")
    $jsonExtracted = $false
    if ($jsonStart -ge 0 -and $jsonEnd -gt $jsonStart) {
        $jsonBlock = $stdout.Substring($jsonStart, $jsonEnd - $jsonStart + 1)
        Set-Content -Path $jsonPath -Value $jsonBlock -NoNewline
        Add-Content -Path $resultsFile -Value $jsonBlock
        $jsonExtracted = $true
        Write-Host "  JSON extracted -> $jsonPath"
    } else {
        Write-Warning "  Could not extract JSON from stdout"
    }

    $runSummary += [PSCustomObject]@{
        Scenario      = $scenario
        Name          = $name
        StartTime     = $startTime.ToString("yyyy-MM-dd HH:mm:ss")
        EndTime       = $endTime.ToString("yyyy-MM-dd HH:mm:ss")
        ElapsedSec    = $elapsed
        ExitCode      = $exitCode
        Status        = $status
        Crash         = $crash
        JsonExtracted = $jsonExtracted
        StdoutPath    = $stdoutPath
        StderrPath    = $stderrPath
        JsonPath      = $jsonPath
    }
}

# Write run summary
$summaryPath = "$logDir\B013_run_summary_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$runSummary | Export-Csv -Path $summaryPath -NoTypeInformation

Write-Host "========================================"
Write-Host "All scenarios complete."
Write-Host "Summary: $summaryPath"
Write-Host "Results: $resultsFile"
Write-Host "========================================"

# Print summary table
$runSummary | Format-Table -AutoSize
