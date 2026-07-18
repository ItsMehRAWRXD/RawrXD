#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Reproducible Build Verification
.DESCRIPTION
    Verifies that the repository builds and tests pass from a clean state.
    This simulates what happens when someone clones the repo fresh.
.NOTES
    Run this AFTER cleanup but BEFORE creating the freeze tag.
#>

param(
    [string]$TestDir = "$env:TEMP\RawrXD_ReproTest",
    [string]$SourceDir = (Get-Location).Path
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Reproducible Build Verification" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Source: $SourceDir" -ForegroundColor Gray
Write-Host "Test Directory: $TestDir" -ForegroundColor Gray
Write-Host ""

$Report = @{
    timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    source_dir = $SourceDir
    test_dir = $TestDir
    steps = @()
    overall_status = "PENDING"
}

# Step 1: Clean test directory
Write-Host "[STEP 1] Preparing clean test directory..." -ForegroundColor Yellow
$step1 = @{ name = "Clean Test Directory"; status = "PENDING"; details = "" }
try {
    if (Test-Path $TestDir) {
        Remove-Item -Recurse -Force $TestDir
    }
    New-Item -ItemType Directory -Path $TestDir | Out-Null
    $step1.status = "PASS"
    $step1.details = "Created $TestDir"
    Write-Host "  ✓ PASS" -ForegroundColor Green
} catch {
    $step1.status = "FAIL"
    $step1.details = $_.Exception.Message
    Write-Host "  ✗ FAIL: $($_.Exception.Message)" -ForegroundColor Red
}
$Report.steps += $step1

# Step 2: Copy source (simulating clone without git history)
Write-Host "`n[STEP 2] Copying source files..." -ForegroundColor Yellow
$step2 = @{ name = "Copy Source"; status = "PENDING"; details = "" }
try {
    # Use robocopy for better performance with many files
    $excludeDirs = @("build*", ".git", "RawrXD-ModelLoader", "release", "*.exe.WebView2")
    $excludeFiles = @("*.exe", "*.obj", "*.dll", "*.pdb", "*.ilk", "__*.txt")
    
    # Simple copy for now
    Copy-Item -Path "$SourceDir\*" -Destination $TestDir -Recurse -Force -ErrorAction SilentlyContinue
    
    # Remove excluded items
    foreach ($pattern in $excludeDirs) {
        Get-ChildItem -Path $TestDir -Filter $pattern -Recurse -Directory -ErrorAction SilentlyContinue | 
            Remove-Item -Recurse -Force
    }
    
    $step2.status = "PASS"
    $step2.details = "Copied source to $TestDir"
    Write-Host "  ✓ PASS" -ForegroundColor Green
} catch {
    $step2.status = "FAIL"
    $step2.details = $_.Exception.Message
    Write-Host "  ✗ FAIL: $($_.Exception.Message)" -ForegroundColor Red
}
$Report.steps += $step2

# Step 3: Configure build
Write-Host "`n[STEP 3] Configuring build..." -ForegroundColor Yellow
$step3 = @{ name = "CMake Configure"; status = "PENDING"; details = "" }
try {
    Set-Location $TestDir
    
    # Check for CMakeLists.txt
    if (-not (Test-Path "CMakeLists.txt")) {
        throw "CMakeLists.txt not found"
    }
    
    # Configure
    $cmakeOutput = cmake -B build -G Ninja 2&1
    if ($LASTEXITCODE -ne 0) {
        throw "CMake configuration failed: $cmakeOutput"
    }
    
    $step3.status = "PASS"
    $step3.details = "Configured with Ninja generator"
    Write-Host "  ✓ PASS" -ForegroundColor Green
} catch {
    $step3.status = "FAIL"
    $step3.details = $_.Exception.Message
    Write-Host "  ✗ FAIL: $($_.Exception.Message)" -ForegroundColor Red
}
$Report.steps += $step3

# Step 4: Build
Write-Host "`n[STEP 4] Building..." -ForegroundColor Yellow
$step4 = @{ name = "Build"; status = "PENDING"; details = "" }
try {
    $buildOutput = cmake --build build 2&1
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed"
    }
    
    # Count built executables
    $executables = Get-ChildItem -Path "build" -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue
    $step4.status = "PASS"
    $step4.details = "Built $($executables.Count) executables"
    Write-Host "  ✓ PASS - Built $($executables.Count) executables" -ForegroundColor Green
} catch {
    $step4.status = "FAIL"
    $step4.details = $_.Exception.Message
    Write-Host "  ✗ FAIL: $($_.Exception.Message)" -ForegroundColor Red
}
$Report.steps += $step4

# Step 5: Run tests
Write-Host "`n[STEP 5] Running tests..." -ForegroundColor Yellow
$step5 = @{ name = "Run Tests"; status = "PENDING"; details = "" }
try {
    $testOutput = ctest --test-dir build --output-on-failure 2&1
    $exitCode = $LASTEXITCODE
    
    if ($exitCode -eq 0) {
        $step5.status = "PASS"
        $step5.details = "All tests passed"
        Write-Host "  ✓ PASS - All tests passed" -ForegroundColor Green
    } else {
        $step5.status = "FAIL"
        $step5.details = "Tests failed with exit code $exitCode"
        Write-Host "  ✗ FAIL - Exit code: $exitCode" -ForegroundColor Red
    }
} catch {
    $step5.status = "FAIL"
    $step5.details = $_.Exception.Message
    Write-Host "  ✗ FAIL: $($_.Exception.Message)" -ForegroundColor Red
}
$Report.steps += $step5

# Step 6: Verify Gate D artifacts exist
Write-Host "`n[STEP 6] Verifying Gate D artifacts..." -ForegroundColor Yellow
$step6 = @{ name = "Gate D Artifacts"; status = "PENDING"; details = "" }
try {
    $gateDExe = "build/tests/test_gate_d_intrinsics.exe"
    if (Test-Path $gateDExe) {
        $step6.status = "PASS"
        $step6.details = "test_gate_d_intrinsics.exe exists"
        Write-Host "  ✓ PASS - Gate D executable found" -ForegroundColor Green
    } else {
        $step6.status = "WARN"
        $step6.details = "Gate D executable not found at expected path"
        Write-Host "  ⚠ WARN - Gate D executable not found" -ForegroundColor Yellow
    }
} catch {
    $step6.status = "FAIL"
    $step6.details = $_.Exception.Message
    Write-Host "  ✗ FAIL: $($_.Exception.Message)" -ForegroundColor Red
}
$Report.steps += $step6

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Verification Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$passCount = ($Report.steps | Where-Object { $_.status -eq "PASS" }).Count
$failCount = ($Report.steps | Where-Object { $_.status -eq "FAIL" }).Count
$warnCount = ($Report.steps | Where-Object { $_.status -eq "WARN" }).Count

foreach ($step in $Report.steps) {
    $color = switch ($step.status) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "WARN" { "Yellow" }
        default { "Gray" }
    }
    Write-Host "[$($step.status)] $($step.name): $($step.details)" -ForegroundColor $color
}

Write-Host "`nResults: $passCount PASS, $failCount FAIL, $warnCount WARN" -ForegroundColor White

if ($failCount -eq 0) {
    $Report.overall_status = "READY"
    Write-Host "`n✅ Repository is READY for foundation freeze tag" -ForegroundColor Green
    Write-Host "   Create tag with: git tag -a v1.0-foundation-freeze -m 'Foundation freeze: Gates A-E PASS'" -ForegroundColor Gray
} else {
    $Report.overall_status = "NOT_READY"
    Write-Host "`n❌ Repository is NOT READY for foundation freeze" -ForegroundColor Red
    Write-Host "   Fix the failures above before creating the tag" -ForegroundColor Gray
}

# Save report
$ReportPath = "$SourceDir\reproducible_build_report.json"
$Report | ConvertTo-Json -Depth 3 | Set-Content $ReportPath
Write-Host "`nReport saved to: $ReportPath" -ForegroundColor Gray

# Cleanup
Write-Host "`nCleaning up test directory..." -ForegroundColor Gray
Set-Location $SourceDir
Remove-Item -Recurse -Force $TestDir -ErrorAction SilentlyContinue
