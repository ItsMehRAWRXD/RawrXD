# RawrXD Production Validation Runner
# Generates runtime witness artifacts for production readiness claims

param(
    [string]$TargetUrl = "http://127.0.0.1:8080",
    [string]$OutputDir = "validation_output",
    [int]$Iterations = 100,
    [switch]$SkipBuild,
    [switch]$HardwareValidation
)

$ErrorActionPreference = "Stop"

Write-Host "RawrXD Production Validation Runner" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
    Write-Host "Created output directory: $OutputDir" -ForegroundColor Green
}

# Build harness if needed
if (-not $SkipBuild) {
    Write-Host "[1/6] Building validation harness..." -ForegroundColor Yellow
    Push-Location harness
    try {
        $buildOutput = cmd /c build.bat 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Build failed: $buildOutput"
        }
        Write-Host "    Build successful" -ForegroundColor Green
    } finally {
        Pop-Location
    }
} else {
    Write-Host "[1/6] Skipping build (--SkipBuild specified)" -ForegroundColor Yellow
}

# Run validation harness
Write-Host "[2/6] Running validation harness..." -ForegroundColor Yellow
$harnessArgs = @(
    "--output-dir", $OutputDir,
    "--target", $TargetUrl,
    "--iterations", $Iterations
)

$process = Start-Process -FilePath "harness\ValidationHarness.exe" -ArgumentList $harnessArgs -Wait -PassThru -NoNewWindow
if ($process.ExitCode -ne 0) {
    throw "Validation harness failed with exit code $($process.ExitCode)"
}
Write-Host "    Validation complete" -ForegroundColor Green

# Check output files
Write-Host "[3/6] Verifying output artifacts..." -ForegroundColor Yellow
$requiredFiles = @(
    "boot.log",
    "boot_report.json",
    "gateway.log",
    "inference_trace.json",
    "gpu_metrics.json",
    "validation_summary.json"
)

$missingFiles = @()
foreach ($file in $requiredFiles) {
    $path = Join-Path $OutputDir $file
    if (Test-Path $path) {
        $size = (Get-Item $path).Length
        Write-Host "    ✓ $file ($size bytes)" -ForegroundColor Green
    } else {
        Write-Host "    ✗ $file (MISSING)" -ForegroundColor Red
        $missingFiles += $file
    }
}

if ($missingFiles.Count -gt 0) {
    throw "Missing required output files: $($missingFiles -join ', ')"
}

# Parse and validate results
Write-Host "[4/6] Analyzing validation results..." -ForegroundColor Yellow
$summaryPath = Join-Path $OutputDir "validation_summary.json"
$summary = Get-Content $summaryPath | ConvertFrom-Json

Write-Host "    Boot time: $($summary.boot_time_ms)ms (target: <5000ms)" -ForegroundColor $(if ($summary.boot_passed) { "Green" } else { "Red" })
Write-Host "    Health endpoint: $(if ($summary.health_passed) { "PASS" } else { "FAIL" })" -ForegroundColor $(if ($summary.health_passed) { "Green" } else { "Red" })
Write-Host "    Inference endpoint: $(if ($summary.inference_passed) { "PASS" } else { "FAIL" })" -ForegroundColor $(if ($summary.inference_passed) { "Green" } else { "Red" })
Write-Host "    Streaming endpoint: $(if ($summary.streaming_passed) { "PASS" } else { "FAIL" })" -ForegroundColor $(if ($summary.streaming_passed) { "Green" } else { "Red" })

# Analyze inference trace
$tracePath = Join-Path $OutputDir "inference_trace.json"
$trace = Get-Content $tracePath | ConvertFrom-Json

if ($trace.statistics) {
    Write-Host "    Average TPS: $([math]::Round($trace.statistics.avg_tps, 2))" -ForegroundColor Cyan
    Write-Host "    Average latency: $([math]::Round($trace.statistics.avg_latency_ms, 2))ms" -ForegroundColor Cyan
    Write-Host "    Average TTFT: $([math]::Round($trace.statistics.avg_ttft_ms, 2))ms" -ForegroundColor Cyan
    
    # Performance certification
    $tpsPass = $trace.statistics.avg_tps -gt 100
    $latencyPass = $trace.statistics.avg_latency_ms -lt 5000
    
    Write-Host "    TPS > 100: $(if ($tpsPass) { "PASS" } else { "FAIL" })" -ForegroundColor $(if ($tpsPass) { "Green" } else { "Red" })
    Write-Host "    Latency < 5000ms: $(if ($latencyPass) { "PASS" } else { "FAIL" })" -ForegroundColor $(if ($latencyPass) { "Green" } else { "Red" })
}

# Hardware validation (if requested)
if ($HardwareValidation) {
    Write-Host "[5/6] Running hardware validation..." -ForegroundColor Yellow
    
    # Check for GPU presence
    $gpus = Get-WmiObject -Class Win32_VideoController | Where-Object { $_.Name -match "AMD|NVIDIA" }
    Write-Host "    Detected GPUs:" -ForegroundColor Cyan
    foreach ($gpu in $gpus) {
        Write-Host "      - $($gpu.Name)" -ForegroundColor Gray
    }
    
    # Check for R9700 and 7800 XT specifically
    $r9700 = $gpus | Where-Object { $_.Name -match "R9700|AI PRO" }
    $rx7800 = $gpus | Where-Object { $_.Name -match "7800 XT" }
    
    if ($r9700) {
        Write-Host "    ✓ Radeon AI PRO R9700 detected" -ForegroundColor Green
    } else {
        Write-Host "    ✗ Radeon AI PRO R9700 NOT detected" -ForegroundColor Red
    }
    
    if ($rx7800) {
        Write-Host "    ✓ RX 7800 XT detected" -ForegroundColor Green
    } else {
        Write-Host "    ✗ RX 7800 XT NOT detected" -ForegroundColor Red
    }
    
    # Export hardware report
    $hardwareReport = @{
        timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        gpus = @()
        r9700_present = [bool]$r9700
        rx7800_present = [bool]$rx7800
        multi_gpu_ready = ($r9700 -and $rx7800)
    }
    
    foreach ($gpu in $gpus) {
        $hardwareReport.gpus += @{
            name = $gpu.Name
            adapter_ram_gb = [math]::Round($gpu.AdapterRAM / 1GB, 2)
            driver_version = $gpu.DriverVersion
            video_mode = $gpu.VideoModeDescription
        }
    }
    
    $hardwareReport | ConvertTo-Json -Depth 10 | Out-File (Join-Path $OutputDir "hardware_report.json")
    Write-Host "    hardware_report.json exported" -ForegroundColor Green
} else {
    Write-Host "[5/6] Skipping hardware validation (--HardwareValidation not specified)" -ForegroundColor Yellow
}

# Generate final report
Write-Host "[6/6] Generating final validation report..." -ForegroundColor Yellow

$finalReport = @{
    validation_timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    target_url = $TargetUrl
    iterations = $Iterations
    
    boot_validation = @{
        passed = $summary.boot_passed
        time_ms = $summary.boot_time_ms
        target_ms = 5000
    }
    
    gateway_validation = @{
        health_passed = $summary.health_passed
        inference_passed = $summary.inference_passed
        streaming_passed = $summary.streaming_passed
    }
    
    performance_metrics = @{
        avg_tps = $trace.statistics.avg_tps
        min_tps = $trace.statistics.min_tps
        max_tps = $trace.statistics.max_tps
        avg_latency_ms = $trace.statistics.avg_latency_ms
        avg_ttft_ms = $trace.statistics.avg_ttft_ms
    }
    
    artifacts_generated = @(
        "boot.log"
        "boot_report.json"
        "gateway.log"
        "inference_trace.json"
        "gpu_metrics.json"
        "validation_summary.json"
    )
    
    overall_status = if ($summary.boot_passed -and $summary.health_passed -and $summary.inference_passed -and $summary.streaming_passed) { "PASS" } else { "FAIL" }
}

$finalReport | ConvertTo-Json -Depth 10 | Out-File (Join-Path $OutputDir "final_validation_report.json")
Write-Host "    final_validation_report.json exported" -ForegroundColor Green

# Summary
Write-Host ""
Write-Host "Validation Complete!" -ForegroundColor Cyan
Write-Host "====================" -ForegroundColor Cyan
Write-Host "Output directory: $((Resolve-Path $OutputDir).Path)" -ForegroundColor White
Write-Host "Overall status: $($finalReport.overall_status)" -ForegroundColor $(if ($finalReport.overall_status -eq "PASS") { "Green" } else { "Red" })
Write-Host ""
Write-Host "Generated artifacts:" -ForegroundColor White
Get-ChildItem $OutputDir | ForEach-Object {
    Write-Host "  - $($_.Name) ($($_.Length) bytes)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Review validation_output/final_validation_report.json" -ForegroundColor Gray
Write-Host "  2. Check validation_output/inference_trace.json for detailed metrics" -ForegroundColor Gray
Write-Host "  3. Verify validation_output/gpu_metrics.json for GPU utilization" -ForegroundColor Gray
Write-Host "  4. Run with -HardwareValidation flag for GPU detection verification" -ForegroundColor Gray
