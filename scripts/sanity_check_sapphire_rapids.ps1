#!/usr/bin/env powershell
# =============================================================================
# Sapphire Rapids Sanity Check Script
# Phase 18 Validation - On-Silicon Performance Verification
# =============================================================================
# 
# Purpose: Execute Sovereign_v1.2_INT8.exe on Sapphire Rapids test node
#          and validate 40-50 TPS target with telemetry capture
#
# Usage:   .\sanity_check_sapphire_rapids.ps1 -BinaryPath ".\Sovereign_v1.2_INT8.exe"
# =============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$BinaryPath,
    
    [string]$TestNode = "localhost",
    [int]$WarmupIterations = 10,
    [int]$BenchmarkIterations = 100,
    [string]$OutputDir = ".\telemetry",
    [switch]$ValidateAMX,
    [switch]$ValidateINT8
)

# =============================================================================
# Configuration
# =============================================================================

$TARGET_TPS_MIN = 40
$TARGET_TPS_MAX = 50
$TARGET_LATENCY_MS = 25  # 25ms = 40 TPS
$TELEMETRY_BUFFER_SIZE = 16384

$ErrorActionPreference = "Stop"

# =============================================================================
# Helper Functions
# =============================================================================

function Write-Header($text) {
    Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║ $text" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
}

function Write-Status($text, $status) {
    $color = switch($status) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "WARN" { "Yellow" }
        default { "White" }
    }
    Write-Host "[$status] $text" -ForegroundColor $color
}

function Test-AMXSupport {
    Write-Header "CPU Feature Detection"
    
    $cpuInfo = Get-WmiObject -Class Win32_Processor
    Write-Host "CPU: $($cpuInfo.Name)"
    Write-Host "Cores: $($cpuInfo.NumberOfCores)"
    Write-Host "Logical Processors: $($cpuInfo.NumberOfLogicalProcessors)"
    
    # Check for AMX support via CPUID (requires custom detection)
    # For now, check processor generation
    $isSapphireRapids = $cpuInfo.Name -match "Xeon.*(Sapphire|4th Gen)"
    
    if ($isSapphireRapids) {
        Write-Status "Sapphire Rapids detected" "PASS"
        return $true
    } else {
        Write-Status "Sapphire Rapids NOT detected - AMX may be unavailable" "WARN"
        return $false
    }
}

function Initialize-TelemetryEnvironment {
    Write-Header "Telemetry Environment Setup"
    
    # Create output directory
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        Write-Status "Created telemetry directory: $OutputDir" "PASS"
    }
    
    # Set environment variables for telemetry collection
    $env:SOVEREIGN_TELEMETRY_DIR = $OutputDir
    $env:SOVEREIGN_TELEMETRY_BUFFER_SIZE = $TELEMETRY_BUFFER_SIZE
    $env:SOVEREIGN_ENABLE_AMX_COUNTERS = "1"
    $env:SOVEREIGN_ENABLE_INT8_COUNTERS = "1"
    
    Write-Status "Telemetry environment configured" "PASS"
    Write-Host "  Output Directory: $OutputDir"
    Write-Host "  Buffer Size: $TELEMETRY_BUFFER_SIZE entries"
}

function Invoke-Warmup {
    Write-Header "Warmup Phase ($WarmupIterations iterations)"
    
    for ($i = 1; $i -le $WarmupIterations; $i++) {
        Write-Progress -Activity "Warmup" -Status "Iteration $i of $WarmupIterations" -PercentComplete (($i / $WarmupIterations) * 100)
        
        # Run binary with warmup flag
        $process = Start-Process -FilePath $BinaryPath -ArgumentList "--warmup","--iterations=1" -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -ne 0) {
            throw "Warmup iteration $i failed with exit code $($process.ExitCode)"
        }
    }
    
    Write-Progress -Activity "Warmup" -Completed
    Write-Status "Warmup complete" "PASS"
}

function Invoke-Benchmark {
    Write-Header "Benchmark Phase ($BenchmarkIterations iterations)"
    
    $results = @()
    $startTime = Get-Date
    
    for ($i = 1; $i -le $BenchmarkIterations; $i++) {
        Write-Progress -Activity "Benchmark" -Status "Iteration $i of $BenchmarkIterations" -PercentComplete (($i / $BenchmarkIterations) * 100)
        
        $iterationStart = Get-Date
        
        # Run benchmark iteration
        $process = Start-Process -FilePath $BinaryPath -ArgumentList "--benchmark","--iterations=1","--telemetry" -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$OutputDir\iteration_$i.log"
        
        $iterationEnd = Get-Date
        $latency = ($iterationEnd - $iterationStart).TotalMilliseconds
        
        $results += [PSCustomObject]@{
            Iteration = $i
            LatencyMs = $latency
            TPS = 1000.0 / $latency
            ExitCode = $process.ExitCode
        }
        
        if ($process.ExitCode -ne 0) {
            Write-Status "Iteration $i failed with exit code $($process.ExitCode)" "FAIL"
        }
    }
    
    Write-Progress -Activity "Benchmark" -Completed
    
    return $results
}

function Analyze-Results($results) {
    Write-Header "Performance Analysis"
    
    $successful = $results | Where-Object { $_.ExitCode -eq 0 }
    $failed = $results | Where-Object { $_.ExitCode -ne 0 }
    
    if ($failed.Count -gt 0) {
        Write-Status "$($failed.Count) iterations failed" "FAIL"
    }
    
    $avgLatency = ($successful | Measure-Object -Property LatencyMs -Average).Average
    $minLatency = ($successful | Measure-Object -Property LatencyMs -Minimum).Minimum
    $maxLatency = ($successful | Measure-Object -Property LatencyMs -Maximum).Maximum
    $stdDev = [math]::Sqrt((($successful | ForEach-Object { [math]::Pow($_.LatencyMs - $avgLatency, 2) } | Measure-Object -Average).Average))
    
    $avgTPS = ($successful | Measure-Object -Property TPS -Average).Average
    $minTPS = ($successful | Measure-Object -Property TPS -Minimum).Minimum
    $maxTPS = ($successful | Measure-Object -Property TPS -Maximum).Maximum
    
    Write-Host "`nLatency Statistics:"
    Write-Host "  Average: $([math]::Round($avgLatency, 2)) ms"
    Write-Host "  Min: $([math]::Round($minLatency, 2)) ms"
    Write-Host "  Max: $([math]::Round($maxLatency, 2)) ms"
    Write-Host "  StdDev: $([math]::Round($stdDev, 2)) ms"
    
    Write-Host "`nThroughput Statistics:"
    Write-Host "  Average: $([math]::Round($avgTPS, 2)) TPS"
    Write-Host "  Min: $([math]::Round($minTPS, 2)) TPS"
    Write-Host "  Max: $([math]::Round($maxTPS, 2)) TPS"
    
    # Validation
    Write-Host "`nTarget Validation:"
    Write-Host "  Target Range: $TARGET_TPS_MIN-$TARGET_TPS_MAX TPS"
    
    if ($avgTPS -ge $TARGET_TPS_MIN -and $avgTPS -le $TARGET_TPS_MAX) {
        Write-Status "Average TPS ($([math]::Round($avgTPS, 2))) within target range" "PASS"
    } elseif ($avgTPS -ge $TARGET_TPS_MIN) {
        Write-Status "Average TPS ($([math]::Round($avgTPS, 2))) exceeds target (excellent!)" "PASS"
    } else {
        Write-Status "Average TPS ($([math]::Round($avgTPS, 2))) below target ($TARGET_TPS_MIN)" "FAIL"
    }
    
    if ($maxLatency -le $TARGET_LATENCY_MS) {
        Write-Status "Max latency ($([math]::Round($maxLatency, 2))ms) within target" "PASS"
    } else {
        Write-Status "Max latency ($([math]::Round($maxLatency, 2))ms) exceeds target ($TARGET_LATENCY_MS)" "WARN"
    }
    
    # Jitter analysis
    $jitter = $stdDev / $avgLatency * 100
    Write-Host "`nJitter Analysis:"
    Write-Host "  Coefficient of Variation: $([math]::Round($jitter, 2))%"
    
    if ($jitter -lt 5) {
        Write-Status "Low jitter - consistent performance" "PASS"
    } elseif ($jitter -lt 10) {
        Write-Status "Moderate jitter - acceptable" "WARN"
    } else {
        Write-Status "High jitter - investigate NUMA/cache issues" "FAIL"
    }
    
    return [PSCustomObject]@{
        AvgLatency = $avgLatency
        AvgTPS = $avgTPS
        MinTPS = $minTPS
        MaxTPS = $maxTPS
        JitterPercent = $jitter
        SuccessRate = ($successful.Count / $results.Count) * 100
    }
}

function Export-Results($summary) {
    Write-Header "Results Export"
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = "$OutputDir\sanity_check_report_$timestamp.json"
    
    $report = [PSCustomObject]@{
        Timestamp = Get-Date -Format "o"
        Binary = $BinaryPath
        TestNode = $TestNode
        Configuration = [PSCustomObject]@{
            WarmupIterations = $WarmupIterations
            BenchmarkIterations = $BenchmarkIterations
            TargetTPS = "$TARGET_TPS_MIN-$TARGET_TPS_MAX"
            TargetLatency = $TARGET_LATENCY_MS
        }
        Results = $summary
    }
    
    $report | ConvertTo-Json -Depth 10 | Out-File $reportPath
    Write-Status "Report exported to: $reportPath" "PASS"
    
    # List telemetry files
    $telemetryFiles = Get-ChildItem -Path $OutputDir -Filter "amx_telemetry_*.csv" -ErrorAction SilentlyContinue
    if ($telemetryFiles) {
        Write-Host "`nTelemetry Files:"
        $telemetryFiles | ForEach-Object { Write-Host "  $($_.Name)" }
    }
}

# =============================================================================
# Main Execution
# =============================================================================

Write-Header "Sovereign Engine v1.2_INT8 - Sapphire Rapids Sanity Check"
Write-Host "Binary: $BinaryPath"
Write-Host "Test Node: $TestNode"
Write-Host ""

# Validate binary exists
if (-not (Test-Path $BinaryPath)) {
    throw "Binary not found: $BinaryPath"
}

# Phase 1: Feature Detection
$amxAvailable = Test-AMXSupport

# Phase 2: Environment Setup
Initialize-TelemetryEnvironment

# Phase 3: Warmup
Invoke-Warmup

# Phase 4: Benchmark
$results = Invoke-Benchmark

# Phase 5: Analysis
$summary = Analyze-Results $results

# Phase 6: Export
Export-Results $summary

Write-Header "Sanity Check Complete"
Write-Host "Review the telemetry files in $OutputDir for detailed analysis."
Write-Host "Next steps:"
Write-Host "  1. Review JSON report for performance summary"
Write-Host "  2. Import CSV telemetry into analysis tools"
Write-Host "  3. Proceed to Phase 19 if targets are met"
