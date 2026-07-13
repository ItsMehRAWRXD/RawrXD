# benchmark_runner.ps1
# Phase F.1 Batch 1/5: Automated benchmark execution pipeline

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("sovereign", "ollama", "both")]
    [string]$Backend = "both",
    
    [string]$Model = "phi-3-mini-Q4",
    [string]$OllamaModel = "phi3:mini",
    [string]$OutputDir = ".\reports",
    [string]$ConfigFile = ".\benchmark_config.json",
    [switch]$Quick,
    [switch]$StressTests,
    [switch]$CheckRegressions,
    [switch]$ExportCSV,
    [switch]$GenerateDashboard,
    [switch]$UploadResults,
    [string]$UploadEndpoint,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "Continue"

# ============================================================================
# Configuration
# ============================================================================

$ProductName = "RawrXD Sovereign Benchmark Suite"
$Version = "1.0.0"
$Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

# Default benchmark configuration
$DefaultConfig = @{
    warmup_runs = 5
    measured_runs = 50
    confidence_level = 0.95
    stress_duration_seconds = 60
    quick_mode = $Quick
}

# ============================================================================
# Logging Functions
# ============================================================================

function Write-Status($Message) {
    Write-Host "[BENCHMARK] $Message" -ForegroundColor Cyan
}

function Write-Success($Message) {
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warning($Message) {
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error($Message) {
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Write-Progress($Activity, $PercentComplete) {
    Write-Progress -Activity $Activity -PercentComplete $PercentComplete
}

# ============================================================================
# System Information Collection
# ============================================================================

function Get-SystemInfo {
    Write-Status "Collecting system information..."
    
    $info = @{
        timestamp = Get-Date -Format "o"
        hostname = $env:COMPUTERNAME
        os = (Get-CimInstance Win32_OperatingSystem).Caption
        arch = $env:PROCESSOR_ARCHITECTURE
        cpu = (Get-CimInstance Win32_Processor).Name
        cpu_cores = (Get-CimInstance Win32_Processor).NumberOfCores
        memory_gb = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
        gpu = "Unknown"
        gpu_memory_gb = 0
        git_commit = "unknown"
        compiler = "MSVC 14.3"
    }
    
    # Try to get GPU info
    try {
        $gpuInfo = Get-CimInstance Win32_VideoController | Where-Object { $_.Name -match "AMD|NVIDIA" } | Select-Object -First 1
        if ($gpuInfo) {
            $info.gpu = $gpuInfo.Name
            $info.gpu_memory_gb = [math]::Round($gpuInfo.AdapterRAM / 1GB, 2)
        }
    } catch {
        Write-Warning "Could not detect GPU information"
    }
    
    # Try to get git commit
    try {
        $gitCommit = git -C $PSScriptRoot rev-parse --short HEAD 2>$null
        if ($gitCommit) {
            $info.git_commit = $gitCommit
        }
    } catch {
        # Ignore git errors
    }
    
    return $info
}

# ============================================================================
# Backend Validation
# ============================================================================

function Test-Backend($BackendName) {
    Write-Status "Validating $BackendName backend..."
    
    switch ($BackendName) {
        "sovereign" {
            $exe = "rawrxd"
            if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) {
                Write-Error "RawrXD Sovereign not found in PATH. Please install first."
                return $false
            }
            
            # Test version
            $version = & $exe --version 2>$null
            Write-Status "  Found: $version"
            return $true
        }
        "ollama" {
            try {
                $response = Invoke-RestMethod -Uri "http://localhost:11434/api/version" -Method GET -TimeoutSec 5
                Write-Status "  Found: Ollama $response"
                return $true
            } catch {
                Write-Error "Ollama not running on localhost:11434. Please start Ollama first."
                return $false
            }
        }
    }
    
    return $false
}

# ============================================================================
# Benchmark Execution
# ============================================================================

function Invoke-BenchmarkSuite($BackendName, $ModelName, $Config) {
    Write-Status "Running benchmark suite for $BackendName..."
    
    $results = @{
        backend = $BackendName
        model = $ModelName
        start_time = Get-Date -Format "o"
        benchmarks = @()
        system_info = Get-SystemInfo
    }
    
    $benchmarks = @(
        @{ name = "inference_tps"; description = "Inference Throughput"; weight = 1.0 },
        @{ name = "agent_spawn"; description = "Agent Spawn Rate"; weight = 0.8 },
        @{ name = "swarm16"; description = "Swarm Scaling (16 agents)"; weight = 1.0 },
        @{ name = "seg_execution"; description = "SEG Execution"; weight = 0.9 },
        @{ name = "decision_making"; description = "Decision Quality"; weight = 0.8 },
        @{ name = "self_correction"; description = "Self-Correction"; weight = 1.0 },
        @{ name = "response_quality"; description = "Response Quality"; weight = 0.7 },
        @{ name = "context_handling"; description = "Context Handling"; weight = 0.8 },
        @{ name = "autonomous_runtime"; description = "Autonomous Runtime"; weight = 1.0 },
        @{ name = "resource_usage"; description = "Resource Usage"; weight = 0.6 }
    )
    
    if ($Quick) {
        $benchmarks = $benchmarks | Select-Object -First 3
        Write-Status "Quick mode: Running only first 3 benchmarks"
    }
    
    $total = $benchmarks.Count
    $current = 0
    
    foreach ($benchmark in $benchmarks) {
        $current++
        $percent = [math]::Round(($current / $total) * 100)
        Write-Progress -Activity "Running Benchmarks" -Status $benchmark.description -PercentComplete $percent
        
        Write-Status "  [$current/$total] $($benchmark.description)..."
        
        # Run benchmark executable
        $benchmarkExe = "RawrXD_Benchmark"
        $args = @(
            "--benchmark", $benchmark.name,
            "--backend", $BackendName,
            "--model", $ModelName,
            "--warmup", $Config.warmup_runs,
            "--runs", $Config.measured_runs,
            "--confidence", $Config.confidence_level,
            "--output", "$OutputDir\raw_$($BackendName)_$($benchmark.name).json"
        )
        
        if ($Verbose) {
            $args += "--verbose"
        }
        
        try {
            $output = & $benchmarkExe $args 2>&1
            $exitCode = $LASTEXITCODE
            
            if ($exitCode -eq 0) {
                # Load results
                $resultFile = "$OutputDir\raw_$($BackendName)_$($benchmark.name).json"
                if (Test-Path $resultFile) {
                    $result = Get-Content $resultFile | ConvertFrom-Json
                    $results.benchmarks += $result
                    Write-Success "    Completed: $($result.mean) $($result.unit)"
                }
            } else {
                Write-Error "    Benchmark failed with exit code $exitCode"
                $results.benchmarks += @{
                    name = $benchmark.name
                    status = "failed"
                    error = "Exit code $exitCode"
                }
            }
        } catch {
            Write-Error "    Exception: $_"
            $results.benchmarks += @{
                name = $benchmark.name
                status = "error"
                error = $_.ToString()
            }
        }
    }
    
    Write-Progress -Activity "Running Benchmarks" -Completed
    
    $results.end_time = Get-Date -Format "o"
    $results.duration_seconds = [math]::Round(
        ([datetime]$results.end_time - [datetime]$results.start_time).TotalSeconds, 2)
    
    return $results
}

# ============================================================================
# Stress Tests
# ============================================================================

function Invoke-StressTests($BackendName, $Config) {
    if (-not $StressTests) { return $null }
    
    Write-Status "Running stress tests for $BackendName..."
    
    $stressBenchmarks = @(
        "failure_storm",
        "mutation_storm",
        "resource_starvation",
        "oscillation_storm",
        "degraded_hardware"
    )
    
    $results = @()
    
    foreach ($test in $stressBenchmarks) {
        Write-Status "  Running $test..."
        
        $benchmarkExe = "RawrXD_Benchmark"
        $args = @(
            "--benchmark", $test,
            "--backend", $BackendName,
            "--duration", $Config.stress_duration_seconds,
            "--output", "$OutputDir\stress_$($BackendName)_$test.json"
        )
        
        try {
            & $benchmarkExe $args 2>&1 | Out-Null
            
            $resultFile = "$OutputDir\stress_$($BackendName)_$test.json"
            if (Test-Path $resultFile) {
                $result = Get-Content $resultFile | ConvertFrom-Json
                $results += $result
                Write-Success "    Completed"
            }
        } catch {
            Write-Warning "    Stress test $test failed: $_"
        }
    }
    
    return $results
}

# ============================================================================
# Report Generation
# ============================================================================

function Export-Reports($SovereignResults, $OllamaResults, $StressResults) {
    Write-Status "Generating reports..."
    
    # Create output directory
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    
    # Combine results
    $fullResults = @{
        timestamp = Get-Date -Format "o"
        version = $Version
        configuration = $DefaultConfig
        sovereign = $SovereignResults
        ollama = $OllamaResults
        stress_tests = $StressResults
    }
    
    # JSON report
    $jsonFile = "$OutputDir\benchmark_report_$Timestamp.json"
    $fullResults | ConvertTo-Json -Depth 10 | Out-File $jsonFile -Encoding UTF8
    Write-Success "JSON report: $jsonFile"
    
    # Markdown report
    $mdFile = "$OutputDir\benchmark_report_$Timestamp.md"
    Export-MarkdownReport $fullResults $mdFile
    Write-Success "Markdown report: $mdFile"
    
    # CSV export
    if ($ExportCSV) {
        $csvFile = "$OutputDir\benchmark_data_$Timestamp.csv"
        Export-CSVReport $fullResults $csvFile
        Write-Success "CSV report: $csvFile"
    }
    
    # HTML dashboard
    if ($GenerateDashboard) {
        $htmlFile = "$OutputDir\dashboard_$Timestamp.html"
        Export-HTMLDashboard $fullResults $htmlFile
        Write-Success "HTML dashboard: $htmlFile"
    }
    
    return $fullResults
}

function Export-MarkdownReport($Results, $FilePath) {
    $md = @"
# RawrXD Sovereign Benchmark Report

**Generated:** $($Results.timestamp)  
**Version:** $($Results.version)

## Executive Summary

| Backend | Overall Score | Grade |
|---------|---------------|-------|
"@
    
    if ($Results.sovereign) {
        $sis = Calculate-SIS $Results.sovereign
        $md += "| Sovereign | $([math]::Round($sis.overall, 1)) | $($sis.grade) |`n"
    }
    
    if ($Results.ollama) {
        $sis = Calculate-SIS $Results.ollama
        $md += "| Ollama | $([math]::Round($sis.overall, 1)) | $($sis.grade) |`n"
    }
    
    $md += "
## Detailed Results

"@
    
    # Add benchmark details
    if ($Results.sovereign -and $Results.sovereign.benchmarks) {
        $md += "### Sovereign Results`n`n"
        $md += "| Benchmark | Mean | StdDev | Unit |`n"
        $md += "|-----------|------|--------|------|`n"
        
        foreach ($bench in $Results.sovereign.benchmarks) {
            if ($bench.status -eq "failed") {
                $md += "| $($bench.name) | FAILED | - | - |`n"
            } else {
                $md += "| $($bench.name) | $([math]::Round($bench.mean, 2)) | $([math]::Round($bench.stddev, 2)) | $($bench.unit) |`n"
            }
        }
        $md += "`n"
    }
    
    $md | Out-File $FilePath -Encoding UTF8
}

function Export-CSVReport($Results, $FilePath) {
    $csv = "backend,benchmark,mean,stddev,unit,status`n"
    
    foreach ($backend in @("sovereign", "ollama")) {
        $data = $Results.$backend
        if ($data -and $data.benchmarks) {
            foreach ($bench in $data.benchmarks) {
                $mean = if ($bench.mean) { $bench.mean } else { "N/A" }
                $stddev = if ($bench.stddev) { $bench.stddev } else { "N/A" }
                $unit = if ($bench.unit) { $bench.unit } else { "N/A" }
                $status = if ($bench.status) { $bench.status } else { "ok" }
                $csv += "$backend,$($bench.name),$mean,$stddev,$unit,$status`n"
            }
        }
    }
    
    $csv | Out-File $FilePath -Encoding UTF8
}

function Export-HTMLDashboard($Results, $FilePath) {
    # Simplified HTML generation
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD Benchmark Dashboard</title>
    <style>
        body { font-family: sans-serif; margin: 40px; background: #1a1a2e; color: #eaeaea; }
        h1 { color: #00d9ff; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
        th { color: #00d9ff; }
        .success { color: #00ff88; }
        .error { color: #ff4757; }
    </style>
</head>
<body>
    <h1>RawrXD Sovereign Benchmark Dashboard</h1>
    <p>Generated: $($Results.timestamp)</p>
    
    <h2>Results</h2>
    <table>
        <tr><th>Backend</th><th>Benchmark</th><th>Mean</th><th>Status</th></tr>
"@
    
    foreach ($backend in @("sovereign", "ollama")) {
        $data = $Results.$backend
        if ($data -and $data.benchmarks) {
            foreach ($bench in $data.benchmarks) {
                $mean = if ($bench.mean) { [math]::Round($bench.mean, 2) } else { "N/A" }
                $status = if ($bench.status -eq "failed") { "<span class='error'>FAILED</span>" } else { "<span class='success'>OK</span>" }
                $html += "<tr><td>$backend</td><td>$($bench.name)</td><td>$mean</td><td>$status</td></tr>`n"
            }
        }
    }
    
    $html += @"
    </table>
</body>
</html>
"@
    
    $html | Out-File $FilePath -Encoding UTF8
}

function Calculate-SIS($Results) {
    # Simplified SIS calculation
    $total = 0
    $count = 0
    
    if ($Results.benchmarks) {
        foreach ($bench in $Results.benchmarks) {
            if ($bench.mean) {
                $total += [math]::Min($bench.mean / 100 * 100, 100)  # Normalize to 0-100
                $count++
            }
        }
    }
    
    $overall = if ($count -gt 0) { $total / $count } else { 0 }
    
    $grade = switch ($overall) {
        { $_ -ge 90 } { "A" }
        { $_ -ge 80 } { "B" }
        { $_ -ge 70 } { "C" }
        { $_ -ge 60 } { "D" }
        default { "F" }
    }
    
    return @{
        overall = $overall
        grade = $grade
    }
}

# ============================================================================
# Regression Check
# ============================================================================

function Test-Regressions($Results) {
    if (-not $CheckRegressions) { return }
    
    Write-Status "Checking for regressions..."
    
    # Load baseline
    $baselineFile = "$OutputDir\baseline.json"
    if (-not (Test-Path $baselineFile)) {
        Write-Warning "No baseline found. Creating new baseline."
        $Results | ConvertTo-Json -Depth 5 | Out-File $baselineFile
        return
    }
    
    $baseline = Get-Content $baselineFile | ConvertFrom-Json
    $regressions = @()
    
    # Compare results
    if ($Results.sovereign -and $baseline.sovereign) {
        for ($i = 0; $i -lt $Results.sovereign.benchmarks.Count; $i++) {
            $current = $Results.sovereign.benchmarks[$i]
            $base = $baseline.sovereign.benchmarks[$i]
            
            if ($current.mean -and $base.mean) {
                $change = ($current.mean - $base.mean) / $base.mean
                if ($change -lt -0.05) {  # 5% regression
                    $regressions += @{
                        benchmark = $current.name
                        change = [math]::Round($change * 100, 1)
                        current = $current.mean
                        baseline = $base.mean
                    }
                }
            }
        }
    }
    
    if ($regressions.Count -gt 0) {
        Write-Error "REGRESSIONS DETECTED:"
        foreach ($reg in $regressions) {
            Write-Error "  $($reg.benchmark): $($reg.change)% (was $($reg.baseline), now $($reg.current))"
        }
        exit 1
    } else {
        Write-Success "No regressions detected"
    }
}

# ============================================================================
# Upload Results
# ============================================================================

function Publish-Results($Results) {
    if (-not $UploadResults -or -not $UploadEndpoint) { return }
    
    Write-Status "Uploading results to $UploadEndpoint..."
    
    try {
        $json = $Results | ConvertTo-Json -Depth 5
        Invoke-RestMethod -Uri $UploadEndpoint -Method POST -Body $json -ContentType "application/json"
        Write-Success "Results uploaded successfully"
    } catch {
        Write-Warning "Failed to upload results: $_"
    }
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host ""
    Write-Host "=== $ProductName v$Version ===" -ForegroundColor Cyan
    Write-Host ""
    
    # Create output directory
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    
    # Validate backends
    $validBackends = @()
    if ($Backend -eq "sovereign" -or $Backend -eq "both") {
        if (Test-Backend "sovereign") {
            $validBackends += "sovereign"
        }
    }
    if ($Backend -eq "ollama" -or $Backend -eq "both") {
        if (Test-Backend "ollama") {
            $validBackends += "ollama"
        }
    }
    
    if ($validBackends.Count -eq 0) {
        Write-Error "No valid backends available. Exiting."
        exit 1
    }
    
    # Load configuration
    $config = $DefaultConfig
    if (Test-Path $ConfigFile) {
        Write-Status "Loading configuration from $ConfigFile"
        $loadedConfig = Get-Content $ConfigFile | ConvertFrom-Json
        $config = $loadedConfig
    }
    
    # Run benchmarks
    $sovereignResults = $null
    $ollamaResults = $null
    $stressResults = @()
    
    foreach ($backend in $validBackends) {
        $model = if ($backend -eq "sovereign") { $Model } else { $OllamaModel }
        $results = Invoke-BenchmarkSuite $backend $model $config
        
        if ($backend -eq "sovereign") {
            $sovereignResults = $results
        } else {
            $ollamaResults = $results
        }
        
        # Run stress tests
        if ($StressTests) {
            $stress = Invoke-StressTests $backend $config
            if ($stress) {
                $stressResults += $stress
            }
        }
    }
    
    # Generate reports
    $fullResults = Export-Reports $sovereignResults $ollamaResults $stressResults
    
    # Check regressions
    Test-Regressions $fullResults
    
    # Upload results
    Publish-Results $fullResults
    
    # Summary
    Write-Host ""
    Write-Host "=== Benchmark Suite Complete ===" -ForegroundColor Green
    Write-Host ""
    Write-Status "Results saved to: $OutputDir"
    
    if ($sovereignResults) {
        $sis = Calculate-SIS $sovereignResults
        Write-Status "Sovereign SIS: $([math]::Round($sis.overall, 1)) ($($sis.grade))"
    }
    
    if ($ollamaResults) {
        $sis = Calculate-SIS $ollamaResults
        Write-Status "Ollama SIS: $([math]::Round($sis.overall, 1)) ($($sis.grade))"
    }
    
    Write-Host ""
}

# Run main
Main
