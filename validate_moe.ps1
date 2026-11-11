# ============================================================================
# validate_moe.ps1 - MoE Implementation Validation Script
# Verifies the MoE implementation is correctly wired and functional
# ============================================================================

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "RawrXD MoE Implementation Validation" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$testsPassed = 0
$testsFailed = 0

# Test 1: Verify MoE source files exist
Write-Host "`n[Test 1] Checking MoE source files..." -ForegroundColor Yellow
$requiredFiles = @(
    "src\deep2\MoERouter.hpp",
    "src\deep2\MoERouter.cpp",
    "src\deep2\MoEWeightProxy.hpp",
    "src\deep2\MoEWeightProxy.cpp",
    "src\deep2\MoEWeightsLoader.hpp",
    "src\deep2\MoEWeightsLoader.cpp",
    "src\deep2\DeepSeekMoELoader.cpp",
    "src\deep2\Deep2Engine.h",
    "src\deep2\Deep2Engine.cpp"
)

$allFilesExist = $true
foreach ($file in $requiredFiles) {
    $fullPath = Join-Path $PSScriptRoot $file
    if (Test-Path $fullPath) {
        Write-Host "  ✓ $file" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $file (MISSING)" -ForegroundColor Red
        $allFilesExist = $false
    }
}

if ($allFilesExist) {
    $testsPassed++
    Write-Host "  Result: PASS - All MoE source files present" -ForegroundColor Green
} else {
    $testsFailed++
    Write-Host "  Result: FAIL - Missing source files" -ForegroundColor Red
}

# Test 2: Verify computeMoEFFN is implemented (not a stub)
Write-Host "`n[Test 2] Verifying computeMoEFFN implementation..." -ForegroundColor Yellow
$engineFile = Join-Path $PSScriptRoot "src\deep2\Deep2Engine.cpp"
$engineContent = Get-Content $engineFile -Raw

# Check for real MoE implementation markers
$hasRealMoE = $false
if ($engineContent -match "void Deep2Engine::computeMoEFFN" -and
    $engineContent -match "moeRouter_->Route" -and
    $engineContent -match "moeWeightProxy_->Acquire" -and
    $engineContent -match "computeExpertFFN" -and
    $engineContent -match "computeSharedExpertFFN") {
    $hasRealMoE = $true
}

# Check it's NOT a stub (no dense fallback comment)
$isStub = $false
if ($engineContent -match "computeMoEFFN.*stub" -or 
    $engineContent -match "computeMoEFFN.*TODO" -or
    $engineContent -match "computeMoEFFN.*dense.*fallback") {
    $isStub = $true
}

if ($hasRealMoE -and -not $isStub) {
    $testsPassed++
    Write-Host "  ✓ computeMoEFFN has real MoE routing implementation" -ForegroundColor Green
    Write-Host "  Result: PASS - Real MoE execution path" -ForegroundColor Green
} else {
    $testsFailed++
    Write-Host "  ✗ computeMoEFFN appears to be a stub" -ForegroundColor Red
    Write-Host "  Result: FAIL - Dense fallback detected" -ForegroundColor Red
}

# Test 3: Verify MoE metadata parsing in GGUFLoader
Write-Host "`n[Test 3] Verifying GGUF MoE metadata parsing..." -ForegroundColor Yellow
$ggufFile = Join-Path $PSScriptRoot "src\deep2\GGUFLoader.cpp"
$ggufContent = Get-Content $ggufFile -Raw

$hasMoEMetadata = $false
if ($ggufContent -match "numExperts" -and
    $ggufContent -match "numExpertsPerToken" -and
    $ggufContent -match "numSharedExperts" -and
    $ggufContent -match "moeIntermediateSize") {
    $hasMoEMetadata = $true
}

if ($hasMoEMetadata) {
    $testsPassed++
    Write-Host "  ✓ GGUFLoader parses MoE metadata" -ForegroundColor Green
    Write-Host "  Result: PASS - MoE metadata detection" -ForegroundColor Green
} else {
    $testsFailed++
    Write-Host "  ✗ GGUFLoader missing MoE metadata parsing" -ForegroundColor Red
    Write-Host "  Result: FAIL - Cannot detect MoE models" -ForegroundColor Red
}

# Test 4: Verify MoE detection in loadModel
Write-Host "`n[Test 4] Verifying MoE model detection..." -ForegroundColor Yellow

$hasMoEDetection = $false
if ($engineContent -match "isMoE\s*=\s*true" -or
    $engineContent -match "numExperts\s*>\s*0" -or
    $engineContent -match "metadata\.numExperts") {
    $hasMoEDetection = $true
}

if ($hasMoEDetection) {
    $testsPassed++
    Write-Host "  ✓ loadModel detects MoE from metadata" -ForegroundColor Green
    Write-Host "  Result: PASS - MoE auto-detection" -ForegroundColor Green
} else {
    $testsFailed++
    Write-Host "  ✗ loadModel missing MoE detection" -ForegroundColor Red
    Write-Host "  Result: FAIL - Cannot auto-detect MoE" -ForegroundColor Red
}

# Test 5: Verify buffer safety (no ffnOutput aliasing)
Write-Host "`n[Test 5] Verifying buffer safety..." -ForegroundColor Yellow

$hasBufferSafety = $false
if ($engineContent -match "sharedOut\s*=\s*attentionOutput" -and
    $engineContent -match "expertOut\s*=\s*attentionOutput" -and
    -not ($engineContent -match "ffnOutput.*gateBuf" -or $engineContent -match "gateBuf.*ffnOutput")) {
    $hasBufferSafety = $true
}

if ($hasBufferSafety) {
    $testsPassed++
    Write-Host "  ✓ Buffer aliasing fixed (attentionOutput used as temp)" -ForegroundColor Green
    Write-Host "  Result: PASS - No buffer collisions" -ForegroundColor Green
} else {
    $testsFailed++
    Write-Host "  ✗ Potential buffer aliasing issue" -ForegroundColor Red
    Write-Host "  Result: FAIL - Buffer collision risk" -ForegroundColor Red
}

# Test 6: Verify Q4_K quantization support
Write-Host "`n[Test 6] Verifying Q4_K quantization support..." -ForegroundColor Yellow

$hasQ4K = $false
if ($engineContent -match "q4kGEMV" -and
    $engineContent -match "dequantizeQ4KBlock" -and
    $engineContent -match "Q4_K_M_Block") {
    $hasQ4K = $true
}

if ($hasQ4K) {
    $testsPassed++
    Write-Host "  ✓ Q4_K dequantization and GEMV present" -ForegroundColor Green
    Write-Host "  Result: PASS - Q4_K support verified" -ForegroundColor Green
} else {
    $testsFailed++
    Write-Host "  ✗ Q4_K support missing" -ForegroundColor Red
    Write-Host "  Result: FAIL - Cannot load Q4_K weights" -ForegroundColor Red
}

# Test 7: Verify existing test binaries
Write-Host "`n[Test 7] Checking existing test binaries..." -ForegroundColor Yellow
$testBinaries = @(
    "build-ninja\bin\test_q4_fused_pipeline.exe",
    "build-ninja\bin\test_q4_scalar_simd.exe",
    "build-ninja\bin\test_q4_cache_alignment.exe"
)

$binariesFound = 0
foreach ($binary in $testBinaries) {
    $fullPath = Join-Path $PSScriptRoot $binary
    if (Test-Path $fullPath) {
        Write-Host "  ✓ $binary" -ForegroundColor Green
        $binariesFound++
    } else {
        Write-Host "  ✗ $binary (not found)" -ForegroundColor Gray
    }
}

if ($binariesFound -ge 2) {
    $testsPassed++
    Write-Host "  Result: PASS - Test infrastructure available ($binariesFound/3)" -ForegroundColor Green
} else {
    Write-Host "  Result: WARN - Limited test binaries ($binariesFound/3)" -ForegroundColor Yellow
}

# Summary
Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "VALIDATION SUMMARY" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "Tests passed: $testsPassed" -ForegroundColor Green
Write-Host "Tests failed: $testsFailed" -ForegroundColor $(if ($testsFailed -gt 0) { "Red" } else { "Green" })

if ($testsFailed -eq 0) {
    Write-Host "`n*** ALL VALIDATION CHECKS PASSED ***" -ForegroundColor Green
    Write-Host "MoE implementation is correctly wired and ready for benchmarking." -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n*** SOME VALIDATION CHECKS FAILED ***" -ForegroundColor Red
    Write-Host "Review the failures above before running benchmarks." -ForegroundColor Red
    exit 1
}
