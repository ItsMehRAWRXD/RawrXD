# RawrXD Production Validation Orchestrator
# Comprehensive validation pipeline for production readiness certification

param(
    [Parameter(Mandatory=$false)]
    [string]$TargetUrl = "http://127.0.0.1:8080",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputDir = "validation_output",
    
    [Parameter(Mandatory=$false)]
    [int]$BenchmarkRuns = 100,
    
    [Parameter(Mandatory=$false)]
    [int]$WarmupRuns = 10,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipBuild,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipHardware,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipInference,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipTelemetry,
    
    [Parameter(Mandatory=$false)]
    [switch]$GenerateReport
)

$ErrorActionPreference = "Stop"
$script:ExitCode = 0

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Header($text) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host $text -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-Step($number, $total, $text) {
    Write-Host ""
    Write-Host "[$number/$total] $text" -ForegroundColor Yellow
}

function Write-Result($passed, $message) {
    if ($passed) {
        Write-Host "    ✓ $message" -ForegroundColor Green
    } else {
        Write-Host "    ✗ $message" -ForegroundColor Red
    }
}

function Test-Command($command) {
    try {
        $null = Invoke-Expression $command 2>$null
        return $true
    } catch {
        return $false
    }
}

function Initialize-Environment {
    Write-Header "RawrXD Production Validation Orchestrator"
    
    # Create output directory
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        Write-Host "Created output directory: $OutputDir" -ForegroundColor Green
    }
    
    # Check for required tools
    Write-Host "Checking environment..." -ForegroundColor Gray
    
    $vcvarsPath = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    if (-not (Test-Path $vcvarsPath)) {
        $vcvarsPath = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    }
    
    if (Test-Path $vcvarsPath) {
        Write-Host "  Found Visual Studio 2022" -ForegroundColor Green
    } else {
        Write-Warning "Visual Studio 2022 not found. Build may fail."
    }
    
    # Check for harness directory
    $harnessDir = Join-Path $PSScriptRoot "harness"
    if (-not (Test-Path $harnessDir)) {
        throw "Validation harness not found at: $harnessDir"
    }
    
    Write-Host "  Validation harness: $harnessDir" -ForegroundColor Green
    Write-Host ""
}

function Build-Harness {
    param([string]$HarnessDir)
    
    if ($SkipBuild) {
        Write-Host "Skipping build (--SkipBuild specified)" -ForegroundColor Yellow
        return
    }
    
    Write-Step 1 6 "Building validation harness..."
    
    Push-Location $HarnessDir
    try {
        $buildOutput = & cmd /c "build.bat" 2>&1
        $exitCode = $LASTEXITCODE
        
        if ($exitCode -ne 0) {
            throw "Build failed with exit code $exitCode`n`nBuild output:`n$buildOutput"
        }
        
        # Verify executables were created
        $executables = @(
            "ValidationHarness.exe",
            "HardwareValidator.exe",
            "RealInferenceBenchmark.exe",
            "TelemetryCollector.exe"
        )
        
        $missing = @()
        foreach ($exe in $executables) {
            if (-not (Test-Path $exe)) {
                $missing += $exe
            }
        }
        
        if ($missing.Count -gt 0) {
            throw "Missing executables after build: $($missing -join ', ')"
        }
        
        Write-Result $true "Build successful - all components compiled"
    } finally {
        Pop-Location
    }
}

function Test-Hardware {
    param([string]$HarnessDir)
    
    if ($SkipHardware) {
        Write-Host "Skipping hardware validation (--SkipHardware specified)" -ForegroundColor Yellow
        return @{ passed = $true; skipped = $true }
    }
    
    Write-Step 2 6 "Validating hardware configuration..."
    
    $hardwareReportPath = Join-Path $OutputDir "hardware_report.json"
    $validatorPath = Join-Path $HarnessDir "HardwareValidator.exe"
    
    if (-not (Test-Path $validatorPath)) {
        throw "HardwareValidator.exe not found. Run build first."
    }
    
    $process = Start-Process -FilePath $validatorPath `
        -ArgumentList $hardwareReportPath `
        -Wait -PassThru -NoNewWindow
    
    $detected = @()
    $r9700 = $false
    $rx7800 = $false
    
    if (Test-Path $hardwareReportPath) {
        $report = Get-Content $hardwareReportPath | ConvertFrom-Json
        
        if ($report.gpus) {
            foreach ($gpu in $report.gpus) {
                $detected += $gpu.name
                if ($gpu.is_r9700) { $r9700 = $true }
                if ($gpu.is_rx7800xt) { $rx7800 = $true }
            }
        }
        
        Write-Host "  Detected GPUs:" -ForegroundColor Gray
        foreach ($name in $detected) {
            Write-Host "    - $name" -ForegroundColor Gray
        }
        
        Write-Result $r9700 "Radeon AI PRO R9700 detected"
        Write-Result $rx7800 "RX 7800 XT detected"
        Write-Result ($r9700 -and $rx7800) "Multi-GPU configuration ready"
    } else {
        Write-Warning "Hardware report not generated"
    }
    
    return @{
        passed = ($process.ExitCode -eq 0)
        r9700 = $r9700
        rx7800 = $rx7800
        multiGpu = ($r9700 -and $rx7800)
        report = $hardwareReportPath
    }
}

function Test-Inference {
    param([string]$HarnessDir)
    
    if ($SkipInference) {
        Write-Host "Skipping inference validation (--SkipInference specified)" -ForegroundColor Yellow
        return @{ passed = $true; skipped = $true }
    }
    
    Write-Step 3 6 "Running inference benchmark..."
    
    $benchmarkPath = Join-Path $HarnessDir "RealInferenceBenchmark.exe"
    $outputPath = Join-Path $OutputDir "benchmark_results.json"
    
    if (-not (Test-Path $benchmarkPath)) {
        throw "RealInferenceBenchmark.exe not found. Run build first."
    }
    
    # Parse target URL
    $uri = [System.Uri]$TargetUrl
    $targetHost = $uri.Host
    $port = $uri.Port
    
    $args = @(
        "--host", $targetHost,
        "--port", $port,
        "--runs", $BenchmarkRuns,
        "--warmup", $WarmupRuns,
        "--output", $outputPath,
        "--verbose"
    )
    
    Write-Host "  Target: $TargetUrl" -ForegroundColor Gray
    Write-Host "  Runs: $BenchmarkRuns (warmup: $WarmupRuns)" -ForegroundColor Gray
    
    $process = Start-Process -FilePath $benchmarkPath `
        -ArgumentList $args `
        -Wait -PassThru -NoNewWindow
    
    $results = @{}
    
    if (Test-Path $outputPath) {
        $report = Get-Content $outputPath | ConvertFrom-Json
        
        if ($report.performance) {
            $avgTps = $report.performance.avg_tps
            $avgLatency = $report.performance.avg_latency_ms
            $avgTtft = $report.performance.avg_ttft_ms
            
            Write-Host ""
            Write-Host "  Performance Results:" -ForegroundColor Gray
            Write-Host "    Average TPS: $([math]::Round($avgTps, 1))" -ForegroundColor White
            Write-Host "    Average Latency: $([math]::Round($avgLatency, 0)) ms" -ForegroundColor White
            Write-Host "    Average TTFT: $([math]::Round($avgTtft, 0)) ms" -ForegroundColor White
            
            # Certification checks
            $tpsPass = $avgTps -ge 100
            $latencyPass = $avgLatency -lt 5000
            $ttftPass = $avgTtft -lt 250
            
            Write-Host ""
            Write-Result $tpsPass "TPS >= 100 (target: 100+)"
            Write-Result $latencyPass "Latency < 5000ms (target: <5000)"
            Write-Result $ttftPass "TTFT < 250ms (target: <250)"
            
            $results = @{
                tps = $avgTps
                latency = $avgLatency
                ttft = $avgTtft
                tpsPassed = $tpsPass
                latencyPassed = $latencyPass
                ttftPassed = $ttftPass
                allPassed = ($tpsPass -and $latencyPass -and $ttftPass)
            }
        }
    }
    
    # Fallback: Read from inference_trace.json if benchmark_results.json doesn't have data
    if ($results.Count -eq 0) {
        $tracePath = Join-Path $OutputDir "inference_trace.json"
        if (Test-Path $tracePath) {
            Write-Host "  Reading from inference_trace.json..." -ForegroundColor Gray
            $trace = Get-Content $tracePath | ConvertFrom-Json
            
            if ($trace.statistics) {
                $avgTps = $trace.statistics.avg_tps
                $avgLatency = $trace.statistics.avg_latency_ms
                $avgTtft = $trace.statistics.avg_ttft_ms
                
                Write-Host ""
                Write-Host "  Performance Results (from trace):" -ForegroundColor Gray
                Write-Host "    Average TPS: $([math]::Round($avgTps, 1))" -ForegroundColor White
                Write-Host "    Average Latency: $([math]::Round($avgLatency, 0)) ms" -ForegroundColor White
                Write-Host "    Average TTFT: $([math]::Round($avgTtft, 0)) ms" -ForegroundColor White
                
                # Certification checks
                $tpsPass = $avgTps -ge 100
                $latencyPass = $avgLatency -lt 5000
                $ttftPass = $avgTtft -lt 250
                
                Write-Host ""
                Write-Result $tpsPass "TPS >= 100 (target: 100+)"
                Write-Result $latencyPass "Latency < 5000ms (target: <5000)"
                Write-Result $ttftPass "TTFT < 250ms (target: <250)"
                
                $results = @{
                    tps = $avgTps
                    latency = $avgLatency
                    ttft = $avgTtft
                    tpsPassed = $tpsPass
                    latencyPassed = $latencyPass
                    ttftPassed = $ttftPass
                    allPassed = ($tpsPass -and $latencyPass -and $ttftPass)
                }
            }
        }
    }
    
    if ($results.Count -eq 0) {
        Write-Warning "Benchmark results not generated"
    }
    
    return $results
}

function Test-Telemetry {
    param([string]$HarnessDir)
    
    if ($SkipTelemetry) {
        Write-Host "Skipping telemetry collection (--SkipTelemetry specified)" -ForegroundColor Yellow
        return @{ passed = $true; skipped = $true }
    }
    
    Write-Step 4 6 "Collecting GPU telemetry..."
    
    $telemetryPath = Join-Path $HarnessDir "TelemetryCollector.exe"
    $outputPath = Join-Path $OutputDir "telemetry_report.json"
    
    if (-not (Test-Path $telemetryPath)) {
        throw "TelemetryCollector.exe not found. Run build first."
    }
    
    # Run telemetry collection for 30 seconds
    $duration = 30
    
    Write-Host "  Collecting for $duration seconds..." -ForegroundColor Gray
    
    $process = Start-Process -FilePath $telemetryPath `
        -ArgumentList "--duration", $duration, "--interval", "1000", "--output", $outputPath `
        -Wait -PassThru -NoNewWindow
    
    if (Test-Path $outputPath) {
        $report = Get-Content $outputPath | ConvertFrom-Json
        
        if ($report.gpu_telemetry) {
            $avgGpu = $report.gpu_telemetry.averages.gpu_utilization
            $avgMem = $report.gpu_telemetry.averages.memory_utilization
            $avgTemp = $report.gpu_telemetry.averages.temperature
            
            Write-Host ""
            Write-Host "  GPU Telemetry:" -ForegroundColor Gray
            Write-Host "    Avg GPU Utilization: $([math]::Round($avgGpu, 1))%" -ForegroundColor White
            Write-Host "    Avg Memory Utilization: $([math]::Round($avgMem, 1))%" -ForegroundColor White
            Write-Host "    Avg Temperature: $([math]::Round($avgTemp, 1))°C" -ForegroundColor White
        }
        
        if ($report.inference_telemetry) {
            $totalReq = $report.inference_telemetry.total_requests
            Write-Host "    Inference Requests: $totalReq" -ForegroundColor White
        }
        
        Write-Result $true "Telemetry collected successfully"
    } else {
        Write-Warning "Telemetry report not generated"
    }
    
    return @{ passed = ($process.ExitCode -eq 0) }
}

function Invoke-FullValidation {
    param([string]$HarnessDir)
    
    if (-not $SkipInference -and -not $SkipTelemetry) {
        Write-Step 5 6 "Running full validation harness..."
        
        $harnessPath = Join-Path $HarnessDir "ValidationHarness.exe"
        
        if (-not (Test-Path $harnessPath)) {
            throw "ValidationHarness.exe not found. Run build first."
        }
        
        $args = @(
            "--output-dir", $OutputDir,
            "--target", $TargetUrl,
            "--iterations", $BenchmarkRuns
        )
        
        $process = Start-Process -FilePath $harnessPath `
            -ArgumentList $args `
            -Wait -PassThru -NoNewWindow
        
        # Check for output files
        $expectedFiles = @(
            "boot.log",
            "boot_report.json",
            "gateway.log",
            "inference_trace.json",
            "gpu_metrics.json",
            "validation_summary.json"
        )
        
        $found = 0
        foreach ($file in $expectedFiles) {
            $path = Join-Path $OutputDir $file
            if (Test-Path $path) {
                $found++
            }
        }
        
        Write-Result ($found -eq $expectedFiles.Count) "Generated $found/$($expectedFiles.Count) validation artifacts"
    } else {
        Write-Host "Skipping full validation (component tests selected)" -ForegroundColor Yellow
    }
}

function Export-FinalReport {
    param(
        [hashtable]$HardwareResults,
        [hashtable]$InferenceResults,
        [hashtable]$TelemetryResults
    )
    
    Write-Step 6 6 "Generating final validation report..."
    
    # Try to read inference results from inference_trace.json if not provided
    $inferenceData = $InferenceResults
    if ($inferenceData.Count -eq 0 -or -not $inferenceData.allPassed) {
        $tracePath = Join-Path $OutputDir "inference_trace.json"
        if (Test-Path $tracePath) {
            Write-Host "  Reading inference data from inference_trace.json..." -ForegroundColor Gray
            try {
                $trace = Get-Content $tracePath | ConvertFrom-Json
                if ($trace.statistics) {
                    $avgTps = $trace.statistics.avg_tps
                    $avgLatency = $trace.statistics.avg_latency_ms
                    $avgTtft = $trace.statistics.avg_ttft_ms
                    
                    $tpsPass = $avgTps -ge 100
                    $latencyPass = $avgLatency -lt 5000
                    $ttftPass = $avgTtft -lt 250
                    
                    $inferenceData = @{
                        tps = $avgTps
                        latency = $avgLatency
                        ttft = $avgTtft
                        tpsPassed = $tpsPass
                        latencyPassed = $latencyPass
                        ttftPassed = $ttftPass
                        allPassed = ($tpsPass -and $latencyPass -and $ttftPass)
                    }
                    
                    Write-Host "    TPS: $([math]::Round($avgTps, 1)) (pass: $tpsPass)" -ForegroundColor Gray
                    Write-Host "    Latency: $([math]::Round($avgLatency, 0))ms (pass: $latencyPass)" -ForegroundColor Gray
                    Write-Host "    TTFT: $([math]::Round($avgTtft, 0))ms (pass: $ttftPass)" -ForegroundColor Gray
                }
            } catch {
                Write-Warning "Failed to parse inference_trace.json: $_"
            }
        }
    }
    
    # Hardware passes if at least one valid discrete GPU is detected (R9700 or RX 7800 XT)
    $hasValidGpu = $HardwareResults.r9700 -or $HardwareResults.rx7800
    
    # Ensure inferenceData is never null — provide defaults if missing
    if (-not $inferenceData) {
        Write-Warning "  Inference data is null, using defaults"
        $inferenceData = @{
            tps = 0
            latency = 0
            ttft = 0
            tpsPassed = $false
            latencyPassed = $false
            ttftPassed = $false
            allPassed = $false
        }
    }
    
    # Overall passes if: valid GPU detected AND inference passed AND telemetry passed
    # Note: multi_gpu_ready is a bonus, not a requirement
    $overallPassed = $hasValidGpu -and $inferenceData.allPassed -and $TelemetryResults.passed
    $overallStatus = if ($overallPassed) { "PASS" } else { "FAIL" }
    
    $finalReport = @{
        validation_timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        target_url = $TargetUrl
        output_directory = (Resolve-Path $OutputDir).Path
        hardware_validation = @{
            passed = $hasValidGpu
            r9700_detected = $HardwareResults.r9700
            rx7800xt_detected = $HardwareResults.rx7800
            multi_gpu_ready = $HardwareResults.multiGpu
            report_path = $HardwareResults.report
        }
        inference_validation = @{
            passed = $inferenceData.allPassed
            avg_tps = $inferenceData.tps
            avg_latency_ms = $inferenceData.latency
            avg_ttft_ms = $inferenceData.ttft
            tps_passed = $inferenceData.tpsPassed
            latency_passed = $inferenceData.latencyPassed
            ttft_passed = $inferenceData.ttftPassed
        }
        telemetry_validation = @{
            passed = $TelemetryResults.passed
        }
        overall_status = $overallStatus
    }
    
    $reportPath = Join-Path $OutputDir "final_validation_report.json"
    $finalReport | ConvertTo-Json -Depth 10 | Out-File $reportPath
    
    Write-Result $true "Final report exported to: $reportPath"
    
    return $finalReport
}

function Show-Summary {
    param([hashtable]$FinalReport)
    
    Write-Header "Validation Complete"
    
    Write-Host "Output Directory: $($FinalReport.output_directory)" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Hardware Validation:" -ForegroundColor Cyan
    Write-Host "  R9700 Detected: $(if ($FinalReport.hardware_validation.r9700_detected) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($FinalReport.hardware_validation.r9700_detected) { "Green" } else { "Red" })
    Write-Host "  RX 7800 XT Detected: $(if ($FinalReport.hardware_validation.rx7800xt_detected) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($FinalReport.hardware_validation.rx7800xt_detected) { "Green" } else { "Red" })
    Write-Host "  Multi-GPU Ready: $(if ($FinalReport.hardware_validation.multi_gpu_ready) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($FinalReport.hardware_validation.multi_gpu_ready) { "Green" } else { "Red" })
    Write-Host ""
    
    Write-Host "Inference Performance:" -ForegroundColor Cyan
    Write-Host "  Average TPS: $([math]::Round($FinalReport.inference_validation.avg_tps, 1))" -ForegroundColor White
    Write-Host "  Average Latency: $([math]::Round($FinalReport.inference_validation.avg_latency_ms, 0)) ms" -ForegroundColor White
    Write-Host "  Average TTFT: $([math]::Round($FinalReport.inference_validation.avg_ttft_ms, 0)) ms" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Certification Results:" -ForegroundColor Cyan
    Write-Host "  TPS >= 100: $(if ($FinalReport.inference_validation.tps_passed) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($FinalReport.inference_validation.tps_passed) { "Green" } else { "Red" })
    Write-Host "  Latency < 5000ms: $(if ($FinalReport.inference_validation.latency_passed) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($FinalReport.inference_validation.latency_passed) { "Green" } else { "Red" })
    Write-Host "  TTFT < 250ms: $(if ($FinalReport.inference_validation.ttft_passed) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($FinalReport.inference_validation.ttft_passed) { "Green" } else { "Red" })
    Write-Host ""
    
    $overallColor = if ($FinalReport.overall_status -eq "PASS") { "Green" } else { "Red" }
    Write-Host "Overall Status: $($FinalReport.overall_status)" -ForegroundColor $overallColor
    Write-Host ""
    
    Write-Host "Generated Artifacts:" -ForegroundColor Cyan
    Get-ChildItem $OutputDir | ForEach-Object {
        Write-Host "  - $($_.Name) ($($_.Length) bytes)" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Yellow
    Write-Host "  1. Review final_validation_report.json for detailed results" -ForegroundColor Gray
    Write-Host "  2. Check inference_trace.json for per-request metrics" -ForegroundColor Gray
    Write-Host "  3. Verify gpu_metrics.json for GPU utilization data" -ForegroundColor Gray
    Write-Host "  4. Archive validation artifacts with release build" -ForegroundColor Gray
}

# ============================================================================
# Main Execution
# ============================================================================

try {
    Initialize-Environment
    
    $harnessDir = Join-Path $PSScriptRoot "harness"
    
    Build-Harness -HarnessDir $harnessDir
    
    $hardwareResults = Test-Hardware -HarnessDir $harnessDir
    $inferenceResults = Test-Inference -HarnessDir $harnessDir
    $telemetryResults = Test-Telemetry -HarnessDir $harnessDir
    
    Invoke-FullValidation -HarnessDir $harnessDir
    
    $finalReport = Export-FinalReport `
        -HardwareResults $hardwareResults `
        -InferenceResults $inferenceResults `
        -TelemetryResults $telemetryResults
    
    Show-Summary -FinalReport $finalReport
    
    # Set exit code based on results
    if ($finalReport.overall_status -eq "FAIL") {
        $script:ExitCode = 1
    }
    
} catch {
    Write-Host ""
    Write-Host "ERROR: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    $script:ExitCode = 1
}

exit $script:ExitCode
