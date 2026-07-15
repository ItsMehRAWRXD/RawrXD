# test_regression.ps1 - Automated regression test for RawrXD
# Phase 2 Stabilization: Full pipeline validation
# Usage: .\test_regression.ps1 [-SkipBuild] [-StressIterations 100]
# Auto-starts rawrxd-cli server for pipe tests, cleans up after

param(
    [switch]$SkipBuild = $false,
    [int]$StressIterations = 100
)

# === STALE BINARY GUARD ===
# Only check for staleness if EXE already exists. If EXE is missing, that's
# fine - we'll build it. But if EXE exists and is older than OBJ, that's stale.
$exe = 'd:\rawrxd\build\bin\rawrxd-cli.exe'
$obj = 'd:\rawrxd\build\CMakeFiles\rawrxd.dir\src\cli\cli_main.cpp.obj'

if ((Test-Path $exe) -and (Test-Path $obj)) {
    if ((Get-Item $exe).LastWriteTime -lt (Get-Item $obj).LastWriteTime) {
        Write-Host "[FATAL] Stale binary detected before starting tests!" -ForegroundColor Red
        Write-Host "  Rebuild with: .\ninja-build.ps1 rawrxd" -ForegroundColor Yellow
        exit 1
    }
}
# If EXE doesn't exist, we'll build it. If OBJ doesn't exist, ninja will fail.
# === END STALE BINARY GUARD ===

$ErrorActionPreference = "Stop"
$results = @()
$startTime = Get-Date
$buildDir = 'd:\rawrxd\build'

function Write-Result {
    param([string]$Test, [bool]$Passed, [string]$Message = "")
    $status = $(if ($Passed) { "PASS" } else { "FAIL" }
    $color = $(if ($Passed) { "Green" } else { "Red" }
    Write-Host "[$status] $Test" -ForegroundColor $color
    if ($Message) { Write-Host "       $Message" -ForegroundColor Gray }
    ${script:results} += [PSCustomObject]@{ Test = $Test; Passed = $Passed; Message = $Message }
}

Write-Host "=========================================="
Write-Host "RawrXD Regression Test Suite"
Write-Host "Started: $startTime"
Write-Host "=========================================="
Write-Host ""

# Test 1: Build with proper environment
if (-not $SkipBuild) {
    Write-Host "[TEST] Building rawrxd..." -ForegroundColor Cyan
    try {
        & .\ninja-build.ps1 rawrxd 2>&1 | Tee-Object -Variable buildOutput
        if ($LASTEXITCODE -ne 0) { throw "Build failed with exit code $LASTEXITCODE" }
        Write-Result "Build (ninja-build.ps1)" $true
    } catch {
        Write-Result "Build (ninja-build.ps1)" $false $_.Exception.Message
        exit 1
    }
    Write-Host ""

    # Test 2: Build hotpatch client
    Write-Host "[TEST] Building rawrxd-hotpatch..." -ForegroundColor Cyan
    try {
        & .\ninja-build.ps1 rawrxd-hotpatch 2>&1 | Tee-Object -Variable buildOutput2
        if ($LASTEXITCODE -ne 0) { throw "Build failed with exit code $LASTEXITCODE" }
        Write-Result "Build (rawrxd-hotpatch)" $true
    } catch {
        Write-Result "Build (rawrxd-hotpatch)" $false $_.Exception.Message
    }
    Write-Host ""
} else {
    Write-Host "[SKIP] Build tests (SkipBuild specified)" -ForegroundColor Yellow
    Write-Result "Build (ninja-build.ps1)" $true "Skipped"
    Write-Result "Build (rawrxd-hotpatch)" $true "Skipped"
}

# Test 3: Binary freshness check
Write-Host "[TEST] Verifying binary freshness..." -ForegroundColor Cyan
try {
    & .\test_precheck.ps1
    if ($LASTEXITCODE -ne 0) { throw "Freshness check failed" }
    Write-Result "Binary Freshness" $true
} catch {
    Write-Result "Binary Freshness" $false $_.Exception.Message
}
Write-Host ""

# Test 4: Named pipe connectivity (auto-start server if not running)
Write-Host "[TEST] Named pipe connectivity..." -ForegroundColor Cyan
$serverProcess = $null
try {
    # Check if server is already running
    $existingServer = Get-Process -Name "rawrxd-cli" -ErrorAction SilentlyContinue
    if (-not $existingServer) {
        Write-Host "  [INFO] Starting rawrxd-cli server..." -ForegroundColor Gray
        $serverProcess = Start-Process -FilePath "$buildDir\bin\rawrxd-cli.exe" `
            -ArgumentList "--headless" -WindowStyle Hidden -PassThru
        Start-Sleep -Milliseconds 500
    } else {
        Write-Host "  [INFO] Server already running (PID: $($existingServer.Id))" -ForegroundColor Gray
    }
    
    & .\test_named_pipe.ps1 -TimeoutSeconds 5
    if ($LASTEXITCODE -ne 0) { throw "Pipe test failed" }
    Write-Result "Named Pipe IPC" $true
} catch {
    Write-Result "Named Pipe IPC" $false $_.Exception.Message
} finally {
    # Cleanup: stop server if we started it
    if ($serverProcess -and -not $serverProcess.HasExited) {
        Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue
        Write-Host "  [INFO] Stopped server (PID: $($serverProcess.Id))" -ForegroundColor Gray
    }
}
Write-Host ""

# Test 5: Hotpatch client executable exists
Write-Host "[TEST] Hotpatch client executable..." -ForegroundColor Cyan
$hotpatchExe = 'd:\rawrxd\build\bin\rawrxd-hotpatch.exe'
if (Test-Path $hotpatchExe) {
    Write-Result "Hotpatch Client Binary" $true
} else {
    Write-Result "Hotpatch Client Binary" $false "Missing: $hotpatchExe"
}
Write-Host ""

# Test 6: Stress test (auto-start server if not running)
Write-Host "[TEST] Stress test ($StressIterations rapid connections)..." -ForegroundColor Cyan
$stressServerProcess = $null
$stressPass = 0
$stressFail = 0
try {
    # Check if server is already running
    $existingServer = Get-Process -Name "rawrxd-cli" -ErrorAction SilentlyContinue
    if (-not $existingServer) {
        Write-Host "  [INFO] Starting rawrxd-cli server for stress test..." -ForegroundColor Gray
        $stressServerProcess = Start-Process -FilePath "$buildDir\bin\rawrxd-cli.exe" `
            -ArgumentList "--headless" -WindowStyle Hidden -PassThru
        Start-Sleep -Milliseconds 500
    }
    
    for ($i = 1; $i -le $StressIterations; $i++) {
        try {
            $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".", "RawrXD_Inference", 
                [System.IO.Pipes.PipeDirection]::InOut, 
                [System.IO.Pipes.PipeOptions]::None)
            $pipe.Connect(1000)
            $pipe.Close()
            $stressPass++
        } catch {
            $stressFail++
        }
        if ($i % 10 -eq 0) { Write-Host "  Progress: $i/$StressIterations" -ForegroundColor Gray }
    }
    $stressResult = $stressFail -eq 0
    Write-Result "Stress Test ($StressIterations connections)" $stressResult "Passed: $stressPass, Failed: $stressFail"
} catch {
    Write-Result "Stress Test ($StressIterations connections)" $false $_.Exception.Message
} finally {
    # Cleanup: stop server if we started it
    if ($stressServerProcess -and -not $stressServerProcess.HasExited) {
        Stop-Process -Id $stressServerProcess.Id -Force -ErrorAction SilentlyContinue
        Write-Host "  [INFO] Stopped server (PID: $($stressServerProcess.Id))" -ForegroundColor Gray
    }
}
Write-Host ""

# Summary
$endTime = Get-Date
$duration = $endTime - $startTime
$passed = ($results | Where-Object { $_.Passed }).Count
$failed = ($results | Where-Object { -not $_.Passed }).Count

Write-Host "=========================================="
Write-Host "Regression Test Summary"
Write-Host "=========================================="
Write-Host "Total:  $($results.Count)" -ForegroundColor White
Write-Host "Passed: $passed" -ForegroundColor Green
Write-Host "Failed: $failed" -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "Green" })
Write-Host "Duration: $($duration.ToString('mm\:ss\.fff'))" -ForegroundColor White
Write-Host "=========================================="

if ($failed -gt 0) {
    Write-Host "`nFAILED TESTS:" -ForegroundColor Red
    $results | Where-Object { -not $_.Passed } | ForEach-Object {
        Write-Host "  - $($_.Test): $($_.Message)" -ForegroundColor Red
    }
    exit 1
}

Write-Host "`nAll tests passed!" -ForegroundColor Green
exit 0
