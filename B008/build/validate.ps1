# ============================================================================
# B008 Build Validation Script
# Validates: clean configure, full build, incremental rebuild, test execution
# ============================================================================
param(
    [string]$BuildDir = "d:\rawrxd\build-pmm-validate",
    [string]$SourceDir = "d:\rawrxd",
    [string]$ModelPath = "F:\Franken\BackwardsUnlock\1b\unlock-1B-Q4_K_M.gguf",
    [string]$OutputDir = "d:\rawrxd\B008"
)

$ErrorActionPreference = "Stop"
$script:ExitCode = 0

function Write-Step($msg) {
    Write-Host "`n[B008] $msg" -ForegroundColor Cyan
}

function Write-Pass($msg) {
    Write-Host "  [PASS] $msg" -ForegroundColor Green
}

function Write-Fail($msg) {
    Write-Host "  [FAIL] $msg" -ForegroundColor Red
    $script:ExitCode = 1
}

function Write-Info($msg) {
    Write-Host "  [INFO] $msg" -ForegroundColor Gray
}

# --- Step 1: Clean Configure ---
Write-Step "Step 1/5: Clean configure"
if (Test-Path $BuildDir) {
    Remove-Item -Recurse -Force $BuildDir
}
New-Item -ItemType Directory -Path $BuildDir | Out-Null

$configureStart = Get-Date
& cmake -B $BuildDir -S $SourceDir -G Ninja -DCMAKE_BUILD_TYPE=Release 2>&1 | Tee-Object -FilePath "$OutputDir/logs/configure.log" | Out-Null
$configureEnd = Get-Date
$configureMs = ($configureEnd - $configureStart).TotalMilliseconds

if ($LASTEXITCODE -eq 0) {
    Write-Pass "CMake configure succeeded (${[math]::Round($configureMs)}ms)"
} else {
    Write-Fail "CMake configure failed (exit=$LASTEXITCODE)"
    exit 1
}

# --- Step 2: Full Build ---
Write-Step "Step 2/5: Full build"
$buildStart = Get-Date
& ninja -C $BuildDir b004_transformer_router_streaming_integration_cpu.exe 2>&1 | Tee-Object -FilePath "$OutputDir/logs/build.log" | Out-Null
$buildEnd = Get-Date
$buildMs = ($buildEnd - $buildStart).TotalMilliseconds

if ($LASTEXITCODE -eq 0) {
    Write-Pass "Full build succeeded (${[math]::Round($buildMs)}ms)"
} else {
    Write-Fail "Full build failed (exit=$LASTEXITCODE)"
    exit 1
}

# --- Step 3: Incremental Rebuild ---
Write-Step "Step 3/5: Incremental rebuild (should be no-op)"
$incrStart = Get-Date
& ninja -C $BuildDir b004_transformer_router_streaming_integration_cpu.exe 2>&1 | Tee-Object -FilePath "$OutputDir/logs/incremental.log" | Out-Null
$incrEnd = Get-Date
$incrMs = ($incrEnd - $incrStart).TotalMilliseconds

if ($LASTEXITCODE -eq 0) {
    if ($incrMs -lt 1000) {
        Write-Pass "Incremental rebuild is no-op (${[math]::Round($incrMs)}ms)"
    } else {
        Write-Fail "Incremental rebuild took too long (${[math]::Round($incrMs)}ms) — something rebuilt unexpectedly"
    }
} else {
    Write-Fail "Incremental rebuild failed (exit=$LASTEXITCODE)"
}

# --- Step 4: Artifact Verification ---
Write-Step "Step 4/5: Artifact verification"
$exePath = Join-Path $BuildDir "bin\b004_transformer_router_streaming_integration_cpu.exe"
if (Test-Path $exePath) {
    $size = (Get-Item $exePath).Length
    Write-Pass "Test executable exists ($size bytes)"
    Copy-Item $exePath "$OutputDir/artifacts/"
} else {
    Write-Fail "Test executable not found: $exePath"
}

# --- Step 5: Test Execution ---
Write-Step "Step 5/5: Test execution"
$env:RAWRXD_TEST_MODEL = $ModelPath
$testStart = Get-Date
& $exePath 2>&1 | Tee-Object -FilePath "$OutputDir/logs/test_run.log" | Out-Null
$testEnd = Get-Date
$testMs = ($testEnd - $testStart).TotalMilliseconds
$testExit = $LASTEXITCODE

if ($testExit -eq 0) {
    Write-Pass "B004 test passed (exit=0, ${[math]::Round($testMs)}ms)"
} else {
    Write-Fail "B004 test failed (exit=$testExit)"
}

# --- Performance Baseline Capture ---
Write-Step "Performance baseline capture"
$logContent = Get-Content "$OutputDir/logs/test_run.log" -Raw
$forwardMatch = $logContent | Select-String "Forward\] complete: tokens=(\d+) layers=(\d+) execs=(\d+) elapsed_ms=([\d.]+)"
if ($forwardMatch) {
    $tokens = $forwardMatch.Matches[0].Groups[1].Value
    $layers = $forwardMatch.Matches[0].Groups[2].Value
    $execs = $forwardMatch.Matches[0].Groups[3].Value
    $elapsed = $forwardMatch.Matches[0].Groups[4].Value
    $baseline = @{
        tokens = [int]$tokens
        layers = [int]$layers
        execs = [int]$execs
        elapsed_ms = [double]$elapsed
        ms_per_layer_exec = [double]($elapsed / [Math]::Max(1, [int]$execs))
        timestamp = (Get-Date -Format "o")
    } | ConvertTo-Json -Depth 4
    $baseline | Out-File "$OutputDir/performance/b007_baseline.json" -Encoding UTF8
    Write-Pass "Captured B007 baseline: ${elapsed}ms for $execs layer executions"
} else {
    Write-Fail "Could not extract performance baseline from test output"
}

# --- Summary ---
Write-Step "B008 Validation Summary"
if ($script:ExitCode -eq 0) {
    Write-Host "`n  All B008 gates PASSED" -ForegroundColor Green
    Write-Host "  Build: ${[math]::Round($buildMs)}ms"
    Write-Host "  Test:  ${[math]::Round($testMs)}ms"
    Write-Host "  Artifacts: $OutputDir/artifacts/"
    Write-Host "  Logs: $OutputDir/logs/"
    Write-Host "  Performance: $OutputDir/performance/"
} else {
    Write-Host "`n  B008 validation FAILED — see logs in $OutputDir/logs/" -ForegroundColor Red
}

exit $script:ExitCode
