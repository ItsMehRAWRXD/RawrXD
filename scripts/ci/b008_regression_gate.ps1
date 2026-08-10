# ============================================================================
# B008 CI Gate — Regression Baseline Verification
# Run this script to confirm the B008 baseline is intact.
# ============================================================================
#Requires -Version 7.0
$ErrorActionPreference = "Stop"

$ManifestPath = "$PSScriptRoot\..\tests\b008_evidence_manifest.h"
$BuildDir     = "$PSScriptRoot\..\..\build"
$TargetExe    = "$BuildDir\bin\b005_canonical_model_certification.exe"
$ModelPath    = "F:\Franken\BackwardsUnlock\1b\unlock-1B-Q4_K_M.gguf"
$ExpectedHash = "DDE5AA3FC5FFC17176B5E8BDC82F587B24B2678C6C66101BF7DA77AF9F7CCDFF"

function Write-GateHeader($title) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  $title" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-GateResult($name, $passed, $detail = "") {
    if ($passed) {
        Write-Host "  [PASS] $name" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] $name" -ForegroundColor Red
        if ($detail) { Write-Host "         $detail" -ForegroundColor DarkGray }
    }
    return $passed
}

$allPassed = $true

# ---------------------------------------------------------------------------
# Gate 1: Source commit matches manifest
# ---------------------------------------------------------------------------
Write-GateHeader "Gate 1: Source Identity"
$actualCommit = git -C "$PSScriptRoot\..\.." rev-parse HEAD 2>$null
$expectedCommit = "29e76f01e632f0cc629967a161e7b537d18f4c08"
$allPassed = (Write-GateResult "Source commit matches manifest" ($actualCommit -eq $expectedCommit) "actual=$actualCommit expected=$expectedCommit") -and $allPassed

# ---------------------------------------------------------------------------
# Gate 2: Model file exists and hash matches
# ---------------------------------------------------------------------------
Write-GateHeader "Gate 2: Model Integrity"
$modelExists = Test-Path $ModelPath
$allPassed = (Write-GateResult "Model file exists" $modelExists "path=$ModelPath") -and $allPassed

if ($modelExists) {
    $actualHash = (Get-FileHash $ModelPath -Algorithm SHA256).Hash
    $allPassed = (Write-GateResult "Model SHA256 matches manifest" ($actualHash -eq $ExpectedHash) "actual=$actualHash") -and $allPassed
}

# ---------------------------------------------------------------------------
# Gate 3: Clean build
# ---------------------------------------------------------------------------
Write-GateHeader "Gate 3: Clean Build"
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir | Out-Null
}

$cmakeOutput = cmake -S "$PSScriptRoot\..\.." -B $BuildDir -G Ninja -DCMAKE_BUILD_TYPE=Release 2>&1
$cmakeOk = $LASTEXITCODE -eq 0
$allPassed = (Write-GateResult "CMake configuration" $cmakeOk) -and $allPassed

$buildOutput = cmake --build $BuildDir --target b005_canonical_model_certification --config Release 2>&1
$buildOk = $LASTEXITCODE -eq 0
$allPassed = (Write-GateResult "Build b005_canonical_model_certification" $buildOk) -and $allPassed

# ---------------------------------------------------------------------------
# Gate 4: B005 certification 12/12
# ---------------------------------------------------------------------------
Write-GateHeader "Gate 4: B005 Certification"
if (Test-Path $TargetExe) {
    $env:RAWRXD_TEST_MODEL = $ModelPath
    $certOutput = & $TargetExe 2>&1
    $certOk = $LASTEXITCODE -eq 0
    $allPassed = (Write-GateResult "B005 executable exit code 0" $certOk) -and $allPassed

    $passCount = ($certOutput | Select-String "PASS B005-").Count
    $failCount = ($certOutput | Select-String "FAIL B005-").Count
    $allPassed = (Write-GateResult "12/12 cases PASS" ($passCount -eq 12 -and $failCount -eq 0) "passed=$passCount failed=$failCount") -and $allPassed

    Write-Host "`n  Certification output:" -ForegroundColor DarkGray
    $certOutput | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
} else {
    $allPassed = (Write-GateResult "B005 executable exists" $false "path=$TargetExe") -and $allPassed
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-GateHeader "B008 CI Gate Summary"
if ($allPassed) {
    Write-Host "  ALL GATES PASSED — B008 baseline is intact." -ForegroundColor Green
    Write-Host "  Ready to proceed to B009 batched-prefill work." -ForegroundColor Green
    exit 0
} else {
    Write-Host "  SOME GATES FAILED — B008 baseline is BROKEN." -ForegroundColor Red
    Write-Host "  Do not proceed until all gates pass." -ForegroundColor Red
    exit 1
}
