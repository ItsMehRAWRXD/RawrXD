# RawrXD Phase E.1 Execution Script
# Builds and runs the hotpatch validation pipeline
# Generates real evidence on RX 7800 XT

param(
    [string]$BuildDir = "build_phase_e1",
    [string]$Model = "phi-3-mini",
    [string]$Patch = "gemm",
    [switch]$Matrix,
    [switch]$Strict,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

Write-Host @"
╔════════════════════════════════════════════════════════════════╗
║  RawrXD Phase E.1 — Hotpatch Validation Execution              ║
║  ===================================================          ║
║  From Architecture → Evidence                                  ║
╚════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Check prerequisites
Write-Host "`n[1/5] Checking prerequisites..." -ForegroundColor Yellow

$cmake = Get-Command cmake -ErrorAction SilentlyContinue
if (-not $cmake) {
    throw "CMake not found. Please install CMake 3.20+"
}
Write-Host "  ✓ CMake found: $(cmake --version | Select-Object -First 1)" -ForegroundColor Green

$vsPath = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath 2>$null
if (-not $vsPath) {
    throw "Visual Studio not found. Please install VS2022 with C++ tools"
}
Write-Host "  ✓ Visual Studio found: $vsPath" -ForegroundColor Green

# Check for RX 7800 XT
Write-Host "`n[2/5] Detecting RX 7800 XT..." -ForegroundColor Yellow
try {
    $gpu = Get-WmiObject Win32_VideoController | Where-Object { $_.Name -match "7800 XT|RX 7800" } | Select-Object -First 1
    if ($gpu) {
        Write-Host "  ✓ GPU detected: $($gpu.Name)" -ForegroundColor Green
        Write-Host "    VRAM: $([math]::Round($gpu.AdapterRAM / 1GB, 1)) GB" -ForegroundColor Gray
    } else {
        Write-Host "  ⚠ RX 7800 XT not detected - will use generic AMD GPU profile" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  ⚠ Could not detect GPU - continuing anyway" -ForegroundColor Yellow
}

# Create build directory
Write-Host "`n[3/5] Configuring build..." -ForegroundColor Yellow
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
}

Push-Location $BuildDir

try {
    # Configure with CMake
    $cmakeArgs = @(
        ".."
        "-G", "Ninja"
        "-DCMAKE_BUILD_TYPE=Release"
        "-DCMAKE_CXX_STANDARD=20"
        "-DRAWRXD_ENABLE_BENCHMARKS=ON"
        "-DRAWRXD_BACKEND_VULKAN=ON"
    )
    
    if ($Verbose) {
        $cmakeArgs += "-DCMAKE_VERBOSE_MAKEFILE=ON"
    }
    
    Write-Host "  Running: cmake $cmakeArgs" -ForegroundColor Gray
    & cmake @cmakeArgs 2>&1 | Tee-Object -FilePath "cmake_configure.log"
    
    if ($LASTEXITCODE -ne 0) {
        throw "CMake configuration failed"
    }
    Write-Host "  ✓ Configuration complete" -ForegroundColor Green
    
    # Build
    Write-Host "`n[4/5] Building Phase E.1 runner..." -ForegroundColor Yellow
    $buildArgs = @("--build", ".", "--target", "phase_e1_runner", "-j", "8")
    
    if ($Verbose) {
        $buildArgs += "--verbose"
    }
    
    & cmake @buildArgs 2>&1 | Tee-Object -FilePath "build.log"
    
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed - check build.log"
    }
    Write-Host "  ✓ Build complete" -ForegroundColor Green
    
    # Check executable
    $exePath = "phase_e1_runner.exe"
    if (-not (Test-Path $exePath)) {
        $exePath = "Release\phase_e1_runner.exe"
    }
    
    if (-not (Test-Path $exePath)) {
        throw "Executable not found after build"
    }
    
    Write-Host "  ✓ Executable: $exePath" -ForegroundColor Green
    
    # Run benchmarks
    Write-Host "`n[5/5] Executing benchmarks..." -ForegroundColor Yellow
    Write-Host "  This will take 10-30 minutes depending on configuration" -ForegroundColor Gray
    Write-Host ""
    
    $runArgs = @()
    
    if ($Matrix) {
        $runArgs += "--matrix"
        Write-Host "  Mode: FULL MATRIX (all models, all patches)" -ForegroundColor Cyan
    } else {
        $runArgs += "--model", $Model
        $runArgs += "--patch", $Patch
        Write-Host "  Model: $Model" -ForegroundColor Cyan
        Write-Host "  Patch: $Patch" -ForegroundColor Cyan
    }
    
    if ($Strict) {
        $runArgs += "--strict"
        Write-Host "  Mode: STRICT (maximum reproducibility)" -ForegroundColor Cyan
    }
    
    Write-Host ""
    
    # Execute with real-time output
    & "./$exePath" @runArgs 2>&1 | Tee-Object -FilePath "benchmark_run.log"
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║  ✅ Phase E.1 Execution COMPLETE                              ║" -ForegroundColor Green
        Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host ""
        
        # Display results if report exists
        $reportPath = "validation_report.json"
        if (Test-Path $reportPath) {
            $report = Get-Content $reportPath | ConvertFrom-Json
            Write-Host "Results Summary:" -ForegroundColor Cyan
            Write-Host "  SIS Score: $($report.sis_score) (Grade $($report.grade))" -ForegroundColor White
            Write-Host "  SAI Index: $($report.sai_index)" -ForegroundColor White
            Write-Host "  Baseline TPS: $($report.baseline_tps)" -ForegroundColor White
            Write-Host "  Hotpatched TPS: $($report.hotpatched_tps)" -ForegroundColor White
            Write-Host "  Improvement: +$($report.improvement_percent)%" -ForegroundColor White
            Write-Host "  Effect Size: d = $($report.effect_size)" -ForegroundColor White
            Write-Host "  Significant: $($report.statistically_significant)" -ForegroundColor White
            Write-Host ""
            Write-Host "Report: $reportPath" -ForegroundColor Yellow
        }
        
        Write-Host "Logs:" -ForegroundColor Yellow
        Write-Host "  Configure: cmake_configure.log" -ForegroundColor Gray
        Write-Host "  Build: build.log" -ForegroundColor Gray
        Write-Host "  Run: benchmark_run.log" -ForegroundColor Gray
        
    } else {
        throw "Benchmark execution failed with exit code $LASTEXITCODE"
    }
    
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Review validation_report.json for detailed results" -ForegroundColor White
Write-Host "  2. Check benchmark_run.log for execution details" -ForegroundColor White
Write-Host "  3. Commit evidence to git: git add $BuildDir/validation_report.json" -ForegroundColor White
Write-Host ""
