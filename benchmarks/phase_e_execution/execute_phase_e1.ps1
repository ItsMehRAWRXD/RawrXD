# RawrXD Phase E.1 — Master Execution Script
# Follows VALIDATION_PROTOCOL.md exactly
# Generates publication-ready evidence

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("quick", "full", "matrix")]
    [string]$Mode,
    
    [string]$Model = "models\phi-3-mini-Q4_K_M.gguf",
    [string]$Patch = "gemm",
    [switch]$SkipFreeze,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$Banner = @"
╔════════════════════════════════════════════════════════════════╗
║  RawrXD Phase E.1 — Sovereign Validation Execution               ║
║  =================================================               ║
║  From Architecture → Empirical Evidence                          ║
╚════════════════════════════════════════════════════════════════╝
"@

Write-Host $Banner -ForegroundColor Cyan
Write-Host ""

# ============================================================================
# Phase 0: Environment Freeze (Required)
# ============================================================================

if (-not $SkipFreeze) {
    Write-Host "[PHASE 0] Environment Freeze" -ForegroundColor Yellow
    Write-Host "--------------------------------" -ForegroundColor Yellow
    
    if (-not (Test-Path "environment_lock.json") -or $Force) {
        Write-Host "Creating environment lock..." -ForegroundColor Gray
        & .\freeze_environment.ps1
        
        if ($LASTEXITCODE -ne 0) {
            throw "Environment freeze failed. Commit all changes before running."
        }
    } else {
        Write-Host "Using existing environment lock" -ForegroundColor Gray
    }
    
    $lock = Get-Content "environment_lock.json" | ConvertFrom-Json
    Write-Host "  ✓ Locked commit: $($lock.git.commit_short)" -ForegroundColor Green
    Write-Host "  ✓ Locked model: $($lock.model.filename)" -ForegroundColor Green
    Write-Host "  ✓ Fingerprint: $($lock.fingerprint.Substring(0, 16))..." -ForegroundColor Green
    
    if ($lock.git.dirty) {
        throw "Working directory is dirty. Commit all changes before benchmark execution."
    }
} else {
    Write-Host "[PHASE 0] SKIPPED (using --SkipFreeze)" -ForegroundColor Yellow
}

# ============================================================================
# Phase 1: Build Runner
# ============================================================================

Write-Host "`n[PHASE 1] Building Phase E.1 Runner" -ForegroundColor Yellow
Write-Host "-------------------------------------" -ForegroundColor Yellow

$BuildDir = "build_phase_e1"
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
}

Push-Location $BuildDir

try {
    Write-Host "Configuring with CMake..." -ForegroundColor Gray
    & cmake .. -G "Ninja" -DCMAKE_BUILD_TYPE=Release 2>! | Tee-Object -FilePath "cmake.log"
    
    if ($LASTEXITCODE -ne 0) {
        throw "CMake configuration failed. Check cmake.log"
    }
    
    Write-Host "Building..." -ForegroundColor Gray
    & cmake --build . --target phase_e1_runner -j8 2>! | Tee-Object -FilePath "build.log"
    
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed. Check build.log"
    }
    
    Write-Host "  ✓ Build complete" -ForegroundColor Green
    
} finally {
    Pop-Location
}

# ============================================================================
# Phase 2: Execute Benchmarks
# ============================================================================

Write-Host "`n[PHASE 2] Executing Benchmarks" -ForegroundColor Yellow
Write-Host "--------------------------------" -ForegroundColor Yellow

$Runner = "$BuildDir\phase_e1_runner.exe"
if (-not (Test-Path $Runner)) {
    $Runner = "$BuildDir\Release\phase_e1_runner.exe"
}

if (-not (Test-Path $Runner)) {
    throw "Runner executable not found"
}

Write-Host "Mode: $Mode" -ForegroundColor Cyan
Write-Host "Model: $Model" -ForegroundColor Cyan
Write-Host "Patch: $Patch" -ForegroundColor Cyan
Write-Host ""

$RunArgs = @()

switch ($Mode) {
    "quick" {
        $RunArgs += "--model", $Model
        $RunArgs += "--patch", $Patch
        $RunArgs += "--warmup", "10"
        $RunArgs += "--runs", "30"
        Write-Host "Estimated time: 5-10 minutes" -ForegroundColor Gray
    }
    "full" {
        $RunArgs += "--model", $Model
        $RunArgs += "--patch", $Patch
        $RunArgs += "--warmup", "10"
        $RunArgs += "--runs", "50"
        $RunArgs += "--strict"
        Write-Host "Estimated time: 15-25 minutes" -ForegroundColor Gray
    }
    "matrix" {
        $RunArgs += "--matrix"
        $RunArgs += "--strict"
        Write-Host "Estimated time: 45-90 minutes" -ForegroundColor Gray
    }
}

Write-Host "Executing: $Runner $RunArgs" -ForegroundColor Gray
Write-Host ""

$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

& $Runner @RunArgs 2>! | Tee-Object -FilePath "$BuildDir\benchmark.log"

$Stopwatch.Stop()

if ($LASTEXITCODE -ne 0) {
    throw "Benchmark execution failed with exit code $LASTEXITCODE"
}

Write-Host ""
Write-Host "  ✓ Benchmark complete in $($Stopwatch.Elapsed.ToString('mm\:ss'))" -ForegroundColor Green

# ============================================================================
# Phase 3: Validate Results
# ============================================================================

Write-Host "`n[PHASE 3] Validating Results" -ForegroundColor Yellow
Write-Host "------------------------------" -ForegroundColor Yellow

$ReportPath = "$BuildDir\validation_report.json"
if (-not (Test-Path $ReportPath)) {
    throw "Validation report not generated"
}

$Report = Get-Content $ReportPath | ConvertFrom-Json

Write-Host "Results:" -ForegroundColor Cyan
Write-Host "  SIS Score: $($Report.sis_score) (Grade $($Report.grade))" -ForegroundColor White
Write-Host "  SAI Index: $($Report.sai_index)" -ForegroundColor White
Write-Host "  Baseline TPS: $($Report.baseline_tps)" -ForegroundColor White
Write-Host "  Hotpatched TPS: $($Report.hotpatched_tps)" -ForegroundColor White
Write-Host "  Improvement: +$($Report.improvement_percent)%" -ForegroundColor White
Write-Host "  Effect Size: d = $($Report.effect_size)" -ForegroundColor White
Write-Host "  Significant: $($Report.statistically_significant)" -ForegroundColor White

# Check success criteria
$Success = $true
$Failures = @()

if ($Report.improvement_percent -lt 5) {
    $Success = $false
    $Failures += "TPS improvement < 5%"
}

if (-not $Report.statistically_significant) {
    $Success = $false
    $Failures += "Not statistically significant"
}

if ($Report.effect_size -lt 0.8) {
    $Success = $false
    $Failures += "Effect size < 0.8"
}

Write-Host ""
if ($Success) {
    Write-Host "  ✅ ALL SUCCESS CRITERIA MET" -ForegroundColor Green
} else {
    Write-Host "  ❌ VALIDATION FAILED" -ForegroundColor Red
    foreach ($f in $Failures) {
        Write-Host "     - $f" -ForegroundColor Red
    }
}

# ============================================================================
# Phase 4: Generate Evidence Package
# ============================================================================

Write-Host "`n[PHASE 4] Generating Evidence Package" -ForegroundColor Yellow
Write-Host "--------------------------------------" -ForegroundColor Yellow

$EvidenceDir = "evidence_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null

# Copy artifacts
Copy-Item "environment_lock.json" "$EvidenceDir\"
Copy-Item $ReportPath "$EvidenceDir\"
Copy-Item "$BuildDir\benchmark.log" "$EvidenceDir\"

if (Test-Path "$BuildDir\validation_dashboard.html") {
    Copy-Item "$BuildDir\validation_dashboard.html" "$EvidenceDir\"
}

if (Test-Path "$BuildDir\raw_data") {
    Copy-Item "$BuildDir\raw_data" "$EvidenceDir\" -Recurse
}

# Generate summary
$Summary = @"
# Phase E.1 Validation Report

**Date:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")  
**Mode:** $Mode  
**Duration:** $($Stopwatch.Elapsed.ToString('mm\:ss'))

## Environment
- **Commit:** $($lock.git.commit_short)
- **Model:** $($lock.model.filename)
- **GPU:** $($lock.drivers.gpu.name)

## Results

| Metric | Value | Status |
|--------|-------|--------|
| SIS Score | $($Report.sis_score) | $(if ($Report.sis_score -ge 85) { "✅ PASS" } else { "❌ FAIL" }) |
| SAI Index | $($Report.sai_index) | $(if ($Report.sai_index -ge 1.3) { "✅ PASS" } else { "❌ FAIL" }) |
| TPS Improvement | +$($Report.improvement_percent)% | $(if ($Report.improvement_percent -ge 5) { "✅ PASS" } else { "❌ FAIL" }) |
| Effect Size | d = $($Report.effect_size) | $(if ($Report.effect_size -ge 0.8) { "✅ PASS" } else { "❌ FAIL" }) |
| Significant | $($Report.statistically_significant) | $(if ($Report.statistically_significant) { "✅ PASS" } else { "❌ FAIL" }) |

## Verdict

$(if ($Success) { "**VALIDATION SUCCESSFUL** — Phase E.1 evidence meets all criteria." } else { "**VALIDATION FAILED** — Review failures above." })

---
*RawrXD Sovereign Validation Protocol v1.0*
"@

$Summary | Set-Content "$EvidenceDir\SUMMARY.md"

Write-Host "  ✓ Evidence package: $EvidenceDir" -ForegroundColor Green
Write-Host "    - environment_lock.json" -ForegroundColor Gray
Write-Host "    - validation_report.json" -ForegroundColor Gray
Write-Host "    - benchmark.log" -ForegroundColor Gray
Write-Host "    - SUMMARY.md" -ForegroundColor Gray

# ============================================================================
# Final Summary
# ============================================================================

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor $(if ($Success) { "Green" } else { "Red" })
Write-Host "║  Phase E.1 Execution $(if ($Success) { "COMPLETE ✅" } else { "FAILED ❌" })" -ForegroundColor $(if ($Success) { "Green" } else { "Red" })
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor $(if ($Success) { "Green" } else { "Red" })
Write-Host ""

if ($Success) {
    Write-Host "RawrXD has been empirically validated:" -ForegroundColor White
    Write-Host "  • Hotpatching produces measurable TPS improvement" -ForegroundColor Gray
    Write-Host "  • Improvement is statistically significant" -ForegroundColor Gray
    Write-Host "  • Effect size is large (d > 0.8)" -ForegroundColor Gray
    Write-Host "  • All success criteria met" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Evidence package ready for publication:" -ForegroundColor Yellow
    Write-Host "  $EvidenceDir" -ForegroundColor White
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "  1. Review $EvidenceDir\SUMMARY.md" -ForegroundColor White
    Write-Host "  2. Commit evidence: git add $EvidenceDir" -ForegroundColor White
    Write-Host "  3. Compare with Ollama baseline for SAI calculation" -ForegroundColor White
} else {
    Write-Host "Validation failed. Review:" -ForegroundColor Yellow
    Write-Host "  - $EvidenceDir\benchmark.log" -ForegroundColor White
    Write-Host "  - $BuildDir\build.log" -ForegroundColor White
}

Write-Host ""
