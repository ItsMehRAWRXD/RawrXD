# RawrXD CI/CD Validation Script
# Intended for use in GitHub Actions, Azure DevOps, Jenkins, etc.

param(
    [Parameter(Mandatory=$true)]
    [string]$TargetUrl,
    
    [Parameter(Mandatory=$false)]
    [int]$BenchmarkRuns = 50,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputDir = "ci_validation_output",
    
    [Parameter(Mandatory=$false)]
    [switch]$FailOnCertification,
    
    [Parameter(Mandatory=$false)]
    [switch]$UploadArtifacts
)

$ErrorActionPreference = "Stop"
$script:ExitCode = 0

# ============================================================================
# CI/CD Logging Helpers
# ============================================================================

function Write-CILog($message, $level = "INFO") {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    switch ($level) {
        "INFO" { Write-Host "[$timestamp] [INFO] $message" }
        "WARN" { Write-Warning "[$timestamp] $message" }
        "ERROR" { Write-Error "[$timestamp] $message" }
        "SUCCESS" { Write-Host "[$timestamp] [SUCCESS] $message" -ForegroundColor Green }
        "FAILURE" { Write-Host "[$timestamp] [FAILURE] $message" -ForegroundColor Red }
    }
}

function Set-GitHubOutput($name, $value) {
    # GitHub Actions output
    if ($env:GITHUB_OUTPUT) {
        "$name=$value" | Out-File -FilePath $env:GITHUB_OUTPUT -Append
    }
    
    # Azure DevOps variable
    if ($env:TF_BUILD) {
        Write-Host "##vso[task.setvariable variable=$name]$value"
    }
}

function Set-GitHubStepSummary($markdown) {
    if ($env:GITHUB_STEP_SUMMARY) {
        $markdown | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append
    }
}

# ============================================================================
# Validation Execution
# ============================================================================

function Invoke-Validation {
    Write-CILog "Starting RawrXD CI Validation"
    Write-CILog "Target URL: $TargetUrl"
    Write-CILog "Benchmark runs: $BenchmarkRuns"
    Write-CILog "Output directory: $OutputDir"
    
    # Create output directory
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
    
    # Determine harness path
    $harnessDir = Join-Path $PSScriptRoot "..\harness"
    if (-not (Test-Path $harnessDir)) {
        throw "Validation harness not found at: $harnessDir"
    }
    
    # Build if needed
    $executables = @(
        "ValidationHarness.exe",
        "HardwareValidator.exe",
        "RealInferenceBenchmark.exe"
    )
    
    $needsBuild = $false
    foreach ($exe in $executables) {
        if (-not (Test-Path (Join-Path $harnessDir $exe))) {
            $needsBuild = $true
            break
        }
    }
    
    if ($needsBuild) {
        Write-CILog "Building validation harness..."
        Push-Location $harnessDir
        try {
            $buildOutput = & cmd /c "build.bat" 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "Build failed: $buildOutput"
            }
            Write-CILog "Build successful" "SUCCESS"
        } finally {
            Pop-Location
        }
    }
    
    # Run hardware validation
    Write-CILog "Running hardware validation..."
    $hardwareOutput = Join-Path $OutputDir "hardware_report.json"
    $hwProcess = Start-Process -FilePath (Join-Path $harnessDir "HardwareValidator.exe") `
        -ArgumentList $hardwareOutput `
        -Wait -PassThru -NoNewWindow
    
    $hwResults = @{}
    if (Test-Path $hardwareOutput) {
        $hwReport = Get-Content $hardwareOutput | ConvertFrom-Json
        $hwResults = @{
            r9700 = $hwReport.r9700_detected
            rx7800 = $hwReport.rx7800xt_detected
            multiGpu = $hwReport.multi_gpu_ready
            gpuCount = $hwReport.gpu_count
        }
        
        Write-CILog "Hardware validation complete:"
        Write-CILog "  GPUs found: $($hwResults.gpuCount)"
        Write-CILog "  R9700: $(if ($hwResults.r9700) { 'YES' } else { 'NO' })"
        Write-CILog "  RX 7800 XT: $(if ($hwResults.rx7800) { 'YES' } else { 'NO' })"
        Write-CILog "  Multi-GPU ready: $(if ($hwResults.multiGpu) { 'YES' } else { 'NO' })"
    } else {
        Write-CILog "Hardware report not generated" "WARN"
    }
    
    # Run inference benchmark
    Write-CILog "Running inference benchmark ($BenchmarkRuns runs)..."
    $benchmarkOutput = Join-Path $OutputDir "benchmark_results.json"
    
    $uri = [System.Uri]$TargetUrl
    $bmArgs = @(
        "--host", $uri.Host,
        "--port", $uri.Port,
        "--runs", $BenchmarkRuns,
        "--warmup", ([Math]::Max(5, [Math]::Floor($BenchmarkRuns / 10))),
        "--output", $benchmarkOutput
    )
    
    $bmProcess = Start-Process -FilePath (Join-Path $harnessDir "RealInferenceBenchmark.exe") `
        -ArgumentList $bmArgs `
        -Wait -PassThru -NoNewWindow
    
    $bmResults = @{}
    if (Test-Path $benchmarkOutput) {
        $bmReport = Get-Content $benchmarkOutput | ConvertFrom-Json
        
        if ($bmReport.performance) {
            $bmResults = @{
                avgTps = $bmReport.performance.avg_tps
                avgLatency = $bmReport.performance.avg_latency_ms
                avgTtft = $bmReport.performance.avg_ttft_ms
                minTps = $bmReport.performance.min_tps
                maxTps = $bmReport.performance.max_tps
                tpsPassed = $bmReport.certification.tps_passed
                latencyPassed = $bmReport.certification.latency_passed
                ttftPassed = $bmReport.certification.ttft_passed
                successRate = $bmReport.summary.success_rate
            }
            
            Write-CILog "Inference benchmark complete:"
            Write-CILog "  Avg TPS: $([math]::Round($bmResults.avgTps, 1))"
            Write-CILog "  Avg Latency: $([math]::Round($bmResults.avgLatency, 0)) ms"
            Write-CILog "  Avg TTFT: $([math]::Round($bmResults.avgTtft, 0)) ms"
            Write-CILog "  Success rate: $([math]::Round($bmResults.successRate * 100, 1))%"
        }
    } else {
        Write-CILog "Benchmark results not generated" "WARN"
    }
    
    # Generate final report
    Write-CILog "Generating final validation report..."
    $finalReport = @{
        validation_timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ci_system = if ($env:GITHUB_ACTIONS) { "GitHub Actions" } 
                    elseif ($env:TF_BUILD) { "Azure DevOps" }
                    elseif ($env:JENKINS_URL) { "Jenkins" }
                    else { "Unknown" }
        target_url = $TargetUrl
        benchmark_runs = $BenchmarkRuns
        
        hardware = $hwResults
        inference = $bmResults
        
        certification = @{
            all_passed = ($hwResults.multiGpu -and $bmResults.tpsPassed -and 
                         $bmResults.latencyPassed -and $bmResults.ttftPassed)
            boot_passed = $true  # Assumed in CI
            tps_passed = $bmResults.tpsPassed
            latency_passed = $bmResults.latencyPassed
            ttft_passed = $bmResults.ttftPassed
            multi_gpu_passed = $hwResults.multiGpu
        }
    }
    
    $finalReportPath = Join-Path $OutputDir "final_validation_report.json"
    $finalReport | ConvertTo-Json -Depth 10 | Out-File $finalReportPath
    
    Write-CILog "Final report exported to: $finalReportPath"
    
    # Set CI outputs
    Set-GitHubOutput "validation_status" $(if ($finalReport.certification.all_passed) { "PASS" } else { "FAIL" })
    Set-GitHubOutput "avg_tps" $bmResults.avgTps
    Set-GitHubOutput "avg_latency_ms" $bmResults.avgLatency
    Set-GitHubOutput "avg_ttft_ms" $bmResults.avgTtft
    Set-GitHubOutput "r9700_detected" $hwResults.r9700
    Set-GitHubOutput "rx7800xt_detected" $hwResults.rx7800
    Set-GitHubOutput "multi_gpu_ready" $hwResults.multiGpu
    
    # Generate step summary
    $summary = @"
## RawrXD Validation Results

### Certification Status

| Criteria | Target | Actual | Status |
|----------|--------|--------|--------|
| TPS | ≥ 100 | $([math]::Round($bmResults.avgTps, 1)) | $(if ($bmResults.tpsPassed) { "✅ PASS" } else { "❌ FAIL" }) |
| Latency | < 5000ms | $([math]::Round($bmResults.avgLatency, 0)) ms | $(if ($bmResults.latencyPassed) { "✅ PASS" } else { "❌ FAIL" }) |
| TTFT | < 250ms | $([math]::Round($bmResults.avgTtft, 0)) ms | $(if ($bmResults.ttftPassed) { "✅ PASS" } else { "❌ FAIL" }) |
| Multi-GPU | Both GPUs | $(if ($hwResults.multiGpu) { "Yes" } else { "No" }) | $(if ($hwResults.multiGpu) { "✅ PASS" } else { "❌ FAIL" }) |

### Hardware Configuration

- **Radeon AI PRO R9700**: $(if ($hwResults.r9700) { "✅ Detected" } else { "❌ Not detected" })
- **RX 7800 XT**: $(if ($hwResults.rx7800) { "✅ Detected" } else { "❌ Not detected" })
- **Total GPUs**: $($hwResults.gpuCount)

### Performance Metrics

- **Average TPS**: $([math]::Round($bmResults.avgTps, 1)) (min: $([math]::Round($bmResults.minTps, 1)), max: $([math]::Round($bmResults.maxTps, 1)))
- **Average Latency**: $([math]::Round($bmResults.avgLatency, 0)) ms
- **Average TTFT**: $([math]::Round($bmResults.avgTtft, 0)) ms
- **Success Rate**: $([math]::Round($bmResults.successRate * 100, 1))%

### Overall Status: $(if ($finalReport.certification.all_passed) { "✅ PASS" } else { "❌ FAIL" })

Validation completed at: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
"@
    
    Set-GitHubStepSummary $summary
    
    # Upload artifacts if requested
    if ($UploadArtifacts) {
        Write-CILog "Preparing artifacts for upload..."
        
        # Create artifact archive
        $artifactName = "validation-results-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        $archivePath = "$OutputDir.zip"
        
        Compress-Archive -Path $OutputDir\* -DestinationPath $archivePath -Force
        
        Write-CILog "Artifacts archived to: $archivePath"
        
        # Set artifact path for CI systems
        Set-GitHubOutput "artifact_path" $archivePath
        Set-GitHubOutput "artifact_name" $artifactName
    }
    
    # Determine exit code
    if ($FailOnCertification -and -not $finalReport.certification.all_passed) {
        Write-CILog "Certification failed - exiting with error" "FAILURE"
        $script:ExitCode = 1
    } else {
        Write-CILog "Validation complete" $(if ($finalReport.certification.all_passed) { "SUCCESS" } else { "WARN" })
    }
    
    return $finalReport
}

# ============================================================================
# Main Execution
# ============================================================================

try {
    $results = Invoke-Validation
    
    # Output summary
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Validation Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Overall Status: $(if ($results.certification.all_passed) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($results.certification.all_passed) { "Green" } else { "Red" })
    Write-Host "Artifacts: $OutputDir" -ForegroundColor Gray
    Write-Host ""
    
} catch {
    Write-CILog "Validation failed: $_" "ERROR"
    $script:ExitCode = 1
}

exit $script:ExitCode
