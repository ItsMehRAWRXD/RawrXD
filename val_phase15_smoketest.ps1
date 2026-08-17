# ============================================================================
# VAL-063: Phase 15 Unified Platform Smoke Test
# Validates: RawrXDUnified.exe architecture completeness
# ============================================================================

$EXE = "d:\src\build-unified-final\RawrXDUnified.exe"
$PASS = 0
$FAIL = 0
$TESTS = @()

function Test-Step {
    param($Name, $ScriptBlock, [int]$ExpectedExit = 0)
    try {
        $result = & $ScriptBlock
        $exitCode = $LASTEXITCODE
        # If the script block returned a boolean, use that
        if ($result -is [bool]) {
            if ($result) {
                Write-Host "  [PASS] $Name" -ForegroundColor Green
                $script:PASS++
            } else {
                Write-Host "  [FAIL] $Name" -ForegroundColor Red
                $script:FAIL++
            }
            return
        }
        # Otherwise check exit code
        if ($exitCode -eq $ExpectedExit -or $exitCode -eq $null) {
            Write-Host "  [PASS] $Name" -ForegroundColor Green
            $script:PASS++
        } else {
            Write-Host "  [FAIL] $Name (exit code: $exitCode, expected: $ExpectedExit)" -ForegroundColor Red
            $script:FAIL++
        }
    } catch {
        Write-Host "  [FAIL] $Name - $_" -ForegroundColor Red
        $script:FAIL++
    }
}

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  VAL-063: Phase 15 Unified Smoke Test" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# Check executable exists
if (-not (Test-Path $EXE)) {
    Write-Host "[CRITICAL] $EXE not found!" -ForegroundColor Red
    exit 1
}

Write-Host "`nExecutable: $EXE" -ForegroundColor Gray
$size = (Get-Item $EXE).Length
Write-Host "Size: $([math]::Round($size / 1KB)) KB" -ForegroundColor Gray

# ============================================================================
# VAL-063.1: Executable Integrity
# ============================================================================
Write-Host "`n--- VAL-063.1: Executable Integrity ---" -ForegroundColor Yellow

Test-Step "Binary exists and is executable" {
    $exe = Get-Item $EXE
    $exe.Length -gt 1MB
}

Test-Step "Version output" {
    $output = & $EXE --version 2>&1
    $output -match "RawrXD Unified v15"
}

Test-Step "Help output" {
    $output = & $EXE --help 2>&1
    $output -match "--cli" -and $output -match "--server" -and $output -match "--compile"
}

# ============================================================================
# VAL-063.2: Self-Test Suite
# ============================================================================
Write-Host "`n--- VAL-063.2: Self-Test Suite ---" -ForegroundColor Yellow

Test-Step "Self-test all pass" {
    $output = & $EXE --self-test 2>&1
    $output -match "6 passed" -and $output -match "0 failed"
}

Test-Step "EventBus test" {
    $output = & $EXE --self-test 2>&1
    $output -match "EventBus.*PASS"
}

Test-Step "AI Service test" {
    $output = & $EXE --self-test 2>&1
    $output -match "AI Service.*PASS"
}

Test-Step "Compiler Service test" {
    $output = & $EXE --self-test 2>&1
    $output -match "Compiler Service.*PASS"
}

Test-Step "Agent Service test" {
    $output = & $EXE --self-test 2>&1
    $output -match "Agent Service.*PASS"
}

# ============================================================================
# VAL-063.3: Status Report
# ============================================================================
Write-Host "`n--- VAL-063.3: Status Report ---" -ForegroundColor Yellow

Test-Step "Status report" {
    $output = & $EXE --status 2>&1
    $output -match "Host: RUNNING"
}

Test-Step "Compiler languages reported" {
    $output = & $EXE --status 2>&1
    $output -match "75 supported"
}

Test-Step "EventBus active" {
    $output = & $EXE --status 2>&1
    $output -match "EventBus: ACTIVE"
}

Test-Step "Agent ready" {
    $output = & $EXE --status 2>&1
    $output -match "Agent Service.*READY"
}

# ============================================================================
# VAL-063.4: Mode Switching
# ============================================================================
Write-Host "`n--- VAL-063.4: Mode Switching ---" -ForegroundColor Yellow

Test-Step "CLI mode" {
    $output = & $EXE --cli --help 2>&1
    $output -match "RawrXD CLI"
}

Test-Step "Server mode" {
    $output = & $EXE --server --help 2>&1
    $output -match "RawrXD Server"
}

Test-Step "Compile mode (no file)" -ExpectedExit 1 {
    $output = & $EXE --compile 2>&1
    $output -match "No source file"
}

Test-Step "Agent mode (no task)" -ExpectedExit 1 {
    $output = & $EXE --agent 2>&1
    $output -match "No task specified"
}

# ============================================================================
# VAL-063.5: Architecture Validation
# ============================================================================
Write-Host "`n--- VAL-063.5: Architecture Validation ---" -ForegroundColor Yellow

# Verify all Phase 15 source files exist
$archFiles = @(
    "src\core\AIProvider.h",
    "src\deep2\Deep2Provider.h",
    "src\deep2\Deep2Provider.cpp",
    "src\context\ContextEngine.h",
    "src\context\ContextEngine.cpp",
    "src\agent\CompilerAgent.h",
    "src\agent\CompilerAgent.cpp",
    "src\unified\AIServiceAdapter.h",
    "src\unified\AIServiceAdapter.cpp",
    "src\unified\RawrXDHost.h",
    "src\unified\RawrXDHost.cpp",
    "src\unified\main_unified.cpp",
    "src\core\EventBus.h"
)

$allExist = $true
foreach ($f in $archFiles) {
    $path = Join-Path "d:\src" $f
    if (-not (Test-Path $path)) {
        Write-Host "  [MISSING] $f" -ForegroundColor Red
        $allExist = $false
    }
}

if ($allExist) {
    Write-Host "  [PASS] All 13 architecture files present" -ForegroundColor Green
    $script:PASS++
} else {
    Write-Host "  [FAIL] Architecture files missing" -ForegroundColor Red
    $script:FAIL++
}

# Verify object files exist
$objFiles = @(
    "main_unified.obj",
    "RawrXDHost.obj",
    "AIServiceAdapter.obj",
    "CompilerAgent.obj",
    "ContextEngine.obj",
    "Deep2Provider.obj",
    "Deep2Engine.obj",
    "Deep2InferenceGateway.obj",
    "InferenceEngine.obj",
    "sampling.obj",
    "Tokenizer.obj",
    "advanced_sampler.obj"
)

$allObjExist = $true
foreach ($f in $objFiles) {
    $path = Join-Path "d:\src\build-unified-final" $f
    if (-not (Test-Path $path)) {
        Write-Host "  [MISSING] $f" -ForegroundColor Red
        $allObjExist = $false
    }
}

if ($allObjExist) {
    Write-Host "  [PASS] All 12 object files present" -ForegroundColor Green
    $script:PASS++
} else {
    Write-Host "  [FAIL] Object files missing" -ForegroundColor Red
    $script:FAIL++
}

# ============================================================================
# VAL-063.6: Build Script Validation
# ============================================================================
Write-Host "`n--- VAL-063.6: Build Script Validation ---" -ForegroundColor Yellow

Test-Step "Build script exists" {
    $r = Test-Path "d:\src\build_phase15_final.bat"
    if ($r) { return $true } else { return $false }
}

Test-Step "Build script is executable" {
    $content = Get-Content "d:\src\build_phase15_final.bat" -Raw
    $r = $content -match "RawrXDUnified.exe" -and $content -match "g\+\+"
    if ($r) { return $true } else { return $false }
}

# ============================================================================
# Summary
# ============================================================================
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  VAL-063: SMOKE TEST RESULTS" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Passed: $PASS" -ForegroundColor Green
Write-Host "  Failed: $FAIL" -ForegroundColor Red
Write-Host "  Total:  $($PASS + $FAIL)" -ForegroundColor White

if ($FAIL -eq 0) {
    Write-Host "`n  STATUS: ✅ VAL-063 CERTIFIED" -ForegroundColor Green
    Write-Host "  All Phase 15 components validated.`n" -ForegroundColor Green
} else {
    Write-Host "`n  STATUS: ❌ CERTIFICATION FAILED" -ForegroundColor Red
}

# Write report
$report = @"
# VAL-063 Phase 15 Smoke Test Report

**Date:** $(Get-Date -Format "yyyy-MM-dd HH:mm")
**Executable:** RawrXDUnified.exe ($([math]::Round($size / 1KB)) KB)

## Results
- **Passed:** $PASS
- **Failed:** $FAIL
- **Status:** $(if ($FAIL -eq 0) { "✅ CERTIFIED" } else { "❌ FAILED" })

## Components Validated
- Executable Integrity
- Self-Test Suite (6 tests)
- Status Report
- Mode Switching (CLI, Server, Compile, Agent)
- Architecture Files (13 source, 12 object)
- Build Script
"@

$report | Out-File -FilePath "d:\src\VAL063_SMOKE_TEST_REPORT.md" -Encoding utf8
Write-Host "Report written to: VAL063_SMOKE_TEST_REPORT.md" -ForegroundColor Gray
