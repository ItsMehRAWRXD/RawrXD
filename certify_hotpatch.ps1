<#
.SYNOPSIS
    HP-REPRO-001 — One-command reproducibility for the RawrXD memory hotpatch certification.
.DESCRIPTION
    Performs a clean build of hotpatch_stress_test, runs all 187 assertions,
    captures the executable SHA-256, verifies exit code 0, and produces a
    certification evidence file.  Does NOT modify the golden baseline.
    Returns nonzero on ANY mismatch.
.PARAMETER BuildDir
    Build directory to use (default: build-hotpatch-repro).
.PARAMETER SkipClean
    Skip the clean step (reuse existing build directory).
.EXAMPLE
    .\certify_hotpatch.ps1
.EXAMPLE
    .\certify_hotpatch.ps1 -BuildDir build-hotpatch-repro
#>
[CmdletBinding()]
param(
    [string]$BuildDir = "build-hotpatch-repro",
    [switch]$SkipClean
)

$ErrorActionPreference = "Continue"
Set-StrictMode -Version 3.0

$RepoRoot = $PSScriptRoot
$ExpectedTests   = 187
$ExpectedPassed  = 187
$ExpectedFailed = 0
$ExpectedExit   = 0

Write-Host "=== HP-REPRO-001: Hotpatch Certification Reproducibility ===" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Record source commit ────────────────────────────────────────────
Push-Location $RepoRoot
$sourceCommit = git rev-parse HEAD
$sourceBranch = git rev-parse --abbrev-ref HEAD
Write-Host "[1/8] Source commit: $sourceCommit ($sourceBranch)"

# ── Step 2: Clean build directory ───────────────────────────────────────────
$buildPath = Join-Path $RepoRoot $BuildDir
if (-not $SkipClean) {
    Write-Host "[2/8] Cleaning build directory: $BuildDir"
    if (Test-Path $buildPath) {
        Remove-Item $buildPath -Recurse -Force
    }
} else {
    Write-Host "[2/8] Skipping clean (reuse existing $BuildDir)"
}

# ── Step 3: Configure CMake ─────────────────────────────────────────────────
Write-Host "[3/8] Configuring CMake (Ninja, Vulkan OFF)..."
New-Item -ItemType Directory -Path $buildPath -Force | Out-Null
Push-Location $buildPath
& cmake -G Ninja -DRAWR_ENABLE_VULKAN=OFF $RepoRoot 2>&1 | Out-Null
$configureExit = $LASTEXITCODE
Pop-Location
if ($configureExit -ne 0) {
    Write-Host "FAIL: CMake configure failed (exit $configureExit)" -ForegroundColor Red
    $configureResult | Select-Object -Last 20 | ForEach-Object { Write-Host $_ }
    exit 1
}
Write-Host "      Configure OK"

# ── Step 4: Build hotpatch_stress_test ──────────────────────────────────────
Write-Host "[4/8] Building hotpatch_stress_test..."
Push-Location $buildPath
& cmake --build . --target hotpatch_stress_test 2>&1 | Out-Null
$buildExit = $LASTEXITCODE
Pop-Location
if ($buildExit -ne 0) {
    Write-Host "FAIL: Build failed (exit $buildExit)" -ForegroundColor Red
    $buildResult | Select-Object -Last 20 | ForEach-Object { Write-Host $_ }
    exit 1
}
Write-Host "      Build OK"

# ── Step 5: Hash the executable ─────────────────────────────────────────────
$exePath = Join-Path $buildPath "bin\hotpatch_stress_test.exe"
if (-not (Test-Path $exePath)) {
    Write-Host "FAIL: Executable not found at $exePath" -ForegroundColor Red
    exit 1
}
$exeHash = (Get-FileHash $exePath -Algorithm SHA256).Hash
$exeInfo = Get-Item $exePath
Write-Host "[5/8] Executable SHA-256: $exeHash"
Write-Host "      Size: $($exeInfo.Length) bytes"

# ── Step 6: Run the stress test ─────────────────────────────────────────────
Write-Host "[6/8] Running 187-test stress suite..."
$testOutput = & $exePath 2>&1
$testExit = $LASTEXITCODE
$testOutputStr = $testOutput -join "`n"

# ── Step 7: Verify results ──────────────────────────────────────────────────
Write-Host "[7/8] Verifying results..."

# Extract test counts from output
$testsRunLine   = ($testOutput | Select-String "Tests run:\s*(\d+)").Matches.Groups[1].Value
$testsPassedLine = ($testOutput | Select-String "Tests passed:\s*(\d+)").Matches.Groups[1].Value
$testsFailedLine = ($testOutput | Select-String "Tests failed:\s*(\d+)").Matches.Groups[1].Value

$testsRun   = [int]$testsRunLine
$testsPassed = [int]$testsPassedLine
$testsFailed = [int]$testsFailedLine

$allOk = $true

if ($testExit -ne $ExpectedExit) {
    Write-Host "  FAIL: Exit code $testExit != expected $ExpectedExit" -ForegroundColor Red
    $allOk = $false
} else {
    Write-Host "  PASS: Exit code = $testExit"
}

if ($testsRun -ne $ExpectedTests) {
    Write-Host "  FAIL: Tests run $testsRun != expected $ExpectedTests" -ForegroundColor Red
    $allOk = $false
} else {
    Write-Host "  PASS: Tests run = $testsRun"
}

if ($testsPassed -ne $ExpectedPassed) {
    Write-Host "  FAIL: Tests passed $testsPassed != expected $ExpectedPassed" -ForegroundColor Red
    $allOk = $false
} else {
    Write-Host "  PASS: Tests passed = $testsPassed"
}

if ($testsFailed -ne $ExpectedFailed) {
    Write-Host "  FAIL: Tests failed $testsFailed != expected $ExpectedFailed" -ForegroundColor Red
    $allOk = $false
} else {
    Write-Host "  PASS: Tests failed = $testsFailed"
}

if ($testsPassed -ne $testsRun) {
    Write-Host "  FAIL: Tests passed ($testsPassed) != tests run ($testsRun)" -ForegroundColor Red
    $allOk = $false
} else {
    Write-Host "  PASS: Passed == Run"
}

# ── Step 8: Produce certification evidence ───────────────────────────────────
$timestamp = (Get-Date).ToUniversalTime().ToString("o")
$evidenceFile = Join-Path $RepoRoot "HP-REPRO-001_EVIDENCE.txt"

$evidence = @"
HP-REPRO-001 — Hotpatch Certification Reproducibility Evidence
==============================================================
Source commit:  $sourceCommit
Source branch:  $sourceBranch
Executable:     $exePath
SHA256:         $exeHash
Size:           $($exeInfo.Length) bytes
Timestamp:      $timestamp
Build dir:      $BuildDir
Generator:      Ninja
Vulkan:         OFF

Tests run:      $testsRun
Tests passed:   $testsPassed
Tests failed:   $testsFailed
Exit code:      $testExit

Expected:
  Tests run:    $ExpectedTests
  Tests passed: $ExpectedPassed
  Tests failed: $ExpectedFailed
  Exit code:    $ExpectedExit

Result:         $(if ($allOk) { 'REPRODUCED' } else { 'FAILED' })
"@

$evidence | Set-Content $evidenceFile -Encoding UTF8
Write-Host "[8/8] Evidence written to: $evidenceFile"
Pop-Location

Write-Host ""
if ($allOk) {
    Write-Host "=== HP-REPRO-001: REPRODUCED ===" -ForegroundColor Green
    Write-Host "  $testsPassed/$testsRun tests passed, exit code $testExit"
    Write-Host "  Executable SHA-256: $exeHash"
    exit 0
} else {
    Write-Host "=== HP-REPRO-001: FAILED ===" -ForegroundColor Red
    Write-Host "  See evidence file: $evidenceFile"
    exit 1
}