# B013 Scenario Runner — Runs scenarios 0-4 sequentially with per-scenario logging
# Usage: powershell -ExecutionPolicy Bypass -File b013_run_all.ps1

$modelPath = "F:\Franken\BackwardsUnlock\1b\unlock-1B-Q4_K_M.gguf"
$binDir = "D:\rawrxd\build-pmm-validate\bin"
$logDir = "D:\rawrxd\B013\logs"
$resultsFile = "$logDir\b013_raw_results.jsonl"

$scenarios = @(
    @{ id=0; name="repeated_generations"; desc="5 generations back-to-back" },
    @{ id=1; name="unload_reload"; desc="Load, generate, unload, reload" },
    @{ id=2; name="context_reset"; desc="Generate, reset, generate again" },
    @{ id=3; name="memory_growth"; desc="10 generations, track working set" },
    @{ id=4; name="equivalence_b010_b011"; desc="B010 vs B011 first-token equivalence" }
)

$env:RAWRXD_TEST_MODEL = $modelPath
Set-Location $binDir

# Clear previous results
if (Test-Path $resultsFile) { Remove-Item $resultsFile }

foreach ($scenario in $scenarios) {
    $id = $scenario.id
    $name = $scenario.name
    $logFile = "$logDir\scenario_0${id}_${name}.log"
    $startTime = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    
    Write-Host "`n========================================"
    Write-Host "Running scenario $id : $name"
    Write-Host "Start: $startTime"
    Write-Host "Log: $logFile"
    Write-Host "========================================"
    
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $proc = Start-Process -FilePath ".\b013_stability_test.exe" -ArgumentList "$id" `
        -RedirectStandardOutput $logFile -RedirectStandardError "$logFile.err" `
        -PassThru -Wait
    $sw.Stop()
    
    $exitCode = $proc.ExitCode
    $elapsedMs = $sw.ElapsedMilliseconds
    $endTime = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    
    # Extract key metrics from log
    $hitRate = "N/A"
    $acquisitions = "N/A"
    $maps = "N/A"
    $unmaps = "N/A"
    $residentBytes = "N/A"
    $firstToken = "N/A"
    $tokensGenerated = "N/A"
    $workingSetDelta = "N/A"
    $overallPass = "UNKNOWN"
    
    if (Test-Path $logFile) {
        $logContent = Get-Content $logFile -Raw
        
        if ($logContent -match "Hit rate\s+:\s+([\d.]+)%") { $hitRate = $matches[1] + "%" }
        if ($logContent -match "Acquisitions\s+:\s+(\d+)") { $acquisitions = $matches[1] }
        if ($logContent -match "Maps\s+:\s+(\d+)") { $maps = $matches[1] }
        if ($logContent -match "Unmaps\s+:\s+(\d+)") { $unmaps = $matches[1] }
        if ($logContent -match "Bytes resident\s+:\s+(\d+)") { $residentBytes = $matches[1] }
        if ($logContent -match "generated=(\d+) tokens") { $tokensGenerated = $matches[1] }
        if ($logContent -match '"first_token"\s*:\s*(\d+)') { $firstToken = $matches[1] }
        if ($logContent -match '"overall_pass"\s*:\s*"(PASS|FAIL)"') { $overallPass = $matches[1] }
        if ($logContent -match "working_set_delta\s*:\s*(-?\d+)") { $workingSetDelta = $matches[1] }
    }
    
    $result = @{
        scenario_id = $id
        scenario_name = $name
        start_time = $startTime
        end_time = $endTime
        exit_code = $exitCode
        elapsed_ms = $elapsedMs
        overall_pass = $overallPass
        hit_rate = $hitRate
        acquisitions = $acquisitions
        maps = $maps
        unmaps = $unmaps
        resident_bytes = $residentBytes
        first_token = $firstToken
        tokens_generated = $tokensGenerated
        working_set_delta = $workingSetDelta
    } | ConvertTo-Json -Compress
    
    Add-Content -Path $resultsFile -Value $result
    
    Write-Host "Exit code: $exitCode"
    Write-Host "Elapsed: $elapsedMs ms"
    Write-Host "Overall pass: $overallPass"
    Write-Host "Hit rate: $hitRate"
    Write-Host "========================================"
}

Write-Host "`nAll scenarios complete. Results written to: $resultsFile"
