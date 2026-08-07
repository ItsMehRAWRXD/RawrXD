#Requires -Version 5.1
<#
.SYNOPSIS
    Deep2 Maximum Streamable Throughput Benchmark Automation
    Runs all certification gates unattended for CI/CD integration

.DESCRIPTION
    This script automates the complete Deep2 benchmark certification protocol:
    - Gate 1: Single-stream maximum throughput
    - Gate 2: Endurance matrix (context scaling)
    - Gate 3: Multi-stream saturation
    - Gate 4: Thermal stability soak
    - Gate 5: 100K token endurance

    Produces JSON certification artifacts for performance regression tracking.

.PARAMETER ModelPath
    Path to the GGUF model file to benchmark

.PARAMETER OutputDir
    Directory for benchmark reports (default: ./benchmark-results)

.PARAMETER QuickMode
    Run abbreviated tests for quick validation (5 min vs 60 min)

.PARAMETER GpuType
    GPU type for telemetry collection (AMD, NVIDIA, or Auto)

.EXAMPLE
    .\Run-Deep2BenchmarkGates.ps1 -ModelPath "F:\Models\deep2-q4_k_m.gguf"

.EXAMPLE
    .\Run-Deep2BenchmarkGates.ps1 -ModelPath "deep2.gguf" -QuickMode -OutputDir "D:\ci\benchmarks"

.NOTES
    Author: RawrXD Engineering
    Version: 1.0.0
    Requires: Windows 10/11, AMD RX 7800 XT or equivalent
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ModelPath,

    [string]$OutputDir = ".\benchmark-results",

    [switch]$QuickMode,

    [ValidateSet("AMD", "NVIDIA", "Auto")]
    [string]$GpuType = "Auto",

    [string]$BenchmarkExe = ".\deep2_benchmark.exe"
)

# ============================================================================
# Configuration
# ============================================================================
$script:StartTime = Get-Date
$script:Results = @{}
$script:GateStatus = @{}

# Targets for RX 7800 XT with Deep2 Q4_K_M
$script:Targets = @{
    PrefillTps = 8000
    DecodeTps = 180
    SustainedTps = 175
    FirstTokenMs = 50
    MaxContext = 32768
    ThermalThrottleEvents = 0
    TpsDegradationThreshold = 10  # percent
}

if ($QuickMode) {
    $script:Config = @{
        MaxTokens = 2048
        EnduranceContexts = @(1024, 4096, 8192)
        SaturationStreams = 2
        ThermalDuration = 300  # 5 minutes
        EnduranceTokens = 512
    }
} else {
    $script:Config = @{
        MaxTokens = 8192
        EnduranceContexts = @(1024, 4096, 8192, 16384, 32768)
        SaturationStreams = 4
        ThermalDuration = 1800  # 30 minutes
        EnduranceTokens = 2048
    }
}

# ============================================================================
# Helper Functions
# ============================================================================
function Write-Banner {
    param([string]$Text)
    $width = 76
    $padding = [math]::Max(0, ($width - $Text.Length) / 2)
    $leftPad = " " * [math]::Floor($padding)
    $rightPad = " " * [math]::Ceiling($padding)
    Write-Host ""
    Write-Host "╔$("═" * $width)╗" -ForegroundColor Cyan
    Write-Host "║$leftPad$Text$rightPad║" -ForegroundColor Cyan
    Write-Host "╚$("═" * $width)╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-GateHeader {
    param([int]$GateNumber, [string]$Name)
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "  GATE $GateNumber`: $Name" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host ""
}

function Write-Metric {
    param(
        [string]$Name,
        [object]$Value,
        [object]$Target = $null,
        [string]$Unit = ""
    )
    $line = "  {0,-25}: {1,15} {2}" -f $Name, $Value, $Unit
    if ($Target) {
        $status = if ($Value -ge $Target) { "✅" } else { "❌" }
        $line += " (target: $Target $Unit) $status"
    }
    Write-Host $line
}

function Test-FileExists {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        Write-Error "File not found: $Path"
        exit 1
    }
}

function Invoke-Benchmark {
    param(
        [string]$Phase,
        [hashtable]$Arguments = @{}
    )

    $argsList = @("--model", $ModelPath, "--phase", $Phase, "--format", "json")

    foreach ($key in $Arguments.Keys) {
        $argsList += "--$key"
        $argsList += $Arguments[$key]
    }

    if ($QuickMode) {
        $argsList += "--quiet"
    }

    Write-Host "  Executing: $BenchmarkExe $($argsList -join ' ')" -ForegroundColor DarkGray

    $outputFile = Join-Path $OutputDir "gate_${Phase}.json"
    $argsList += "--output"
    $argsList += $outputFile

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $result = & $BenchmarkExe @argsList 2>&1
    $sw.Stop()

    $success = $LASTEXITCODE -eq 0

    return @{
        Success = $success
        Output = $result
        Duration = $sw.Elapsed
        OutputFile = $outputFile
    }
}

function Get-GpuTelemetry {
    # AMD GPU telemetry via ADL (if available)
    $telemetry = @{}

    try {
        # Try to get GPU utilization via WMI
        $gpu = Get-WmiObject -Namespace "root\cimv2" -Class "Win32_VideoController" | Select-Object -First 1
        $telemetry['Name'] = $gpu.Name
        $telemetry['AdapterRAM'] = [math]::Round($gpu.AdapterRAM / 1GB, 2)
    } catch {
        $telemetry['Name'] = "Unknown"
        $telemetry['AdapterRAM'] = 0
    }

    return $telemetry
}

function Export-CertificationReport {
    param([hashtable]$FinalResults)

    $certificationId = "DEEP2-CERT-{0:yyyyMMdd-HHmmss}" -f $script:StartTime
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime

    $report = [ordered]@{
        certification_id = $certificationId
        timestamp = $endTime.ToString("o")
        duration_seconds = [math]::Round($duration.TotalSeconds)
        model_path = $ModelPath
        quick_mode = $QuickMode.IsPresent

        hardware = @{
            gpu = (Get-GpuTelemetry).Name
            vram_gb = (Get-GpuTelemetry).AdapterRAM
            platform = "Windows $([System.Environment]::OSVersion.Version)"
        }

        configuration = $script:Config

        gates = [ordered]@{}

        overall = [ordered]@{
            status = if ($script:GateStatus.Values -contains $false) { "FAILED" } else { "CERTIFIED" }
            gates_passed = ($script:GateStatus.Values | Where-Object { $_ -eq $true }).Count
            gates_total = $script:GateStatus.Count
        }
    }

    foreach ($gate in $FinalResults.Keys) {
        $report.gates[$gate] = $FinalResults[$gate]
    }

    $reportPath = Join-Path $OutputDir "certification_report.json"
    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportPath -Encoding UTF8

    # Also generate markdown summary
    $mdPath = Join-Path $OutputDir "certification_report.md"
    $md = @"
# Deep2 Maximum Streamable Throughput Certification

**Certification ID:** ``$certificationId``

**Date:** $($endTime.ToString("yyyy-MM-dd HH:mm:ss"))

**Duration:** $([math]::Round($duration.TotalMinutes)) minutes

**Model:** ``$ModelPath``

---

## Hardware Configuration

| Component | Value |
|-----------|-------|
| GPU | $($report.hardware.gpu) |
| VRAM | $($report.hardware.vram_gb) GB |
| Platform | $($report.hardware.platform) |

---

## Certification Gates

| Gate | Name | Status |
|------|------|--------|
"@

    foreach ($gate in $script:GateStatus.Keys) {
        $status = if ($script:GateStatus[$gate]) { "✅ PASS" } else { "❌ FAIL" }
        $md += "| $gate | $($FinalResults[$gate].name) | $status |`n"
    }

    $md += @"

---

## Overall Status

### $(if ($report.overall.status -eq "CERTIFIED") { "✅ CERTIFIED" } else { "❌ FAILED" })

**Gates Passed:** $($report.overall.gates_passed) / $($report.overall.gates_total)

---

*Generated by Deep2 Benchmark Automation v1.0*
"@

    $md | Out-File -FilePath $mdPath -Encoding UTF8

    return @{
        JsonPath = $reportPath
        MarkdownPath = $mdPath
        CertificationId = $certificationId
    }
}

# ============================================================================
# Main Execution
# ============================================================================

# Validate prerequisites
Test-FileExists $ModelPath
if (-not (Test-Path $BenchmarkExe)) {
    Write-Error "Benchmark executable not found: $BenchmarkExe"
    Write-Host "Build with: cmake --build . --target deep2_benchmark"
    exit 1
}

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

Write-Banner "DEEP2 MAXIMUM STREAMABLE THROUGHPUT BENCHMARK"

Write-Host "Model:      $ModelPath" -ForegroundColor White
Write-Host "Output:     $OutputDir" -ForegroundColor White
Write-Host "Mode:       $(if ($QuickMode) { "QUICK (5 min)" } else { "FULL (60 min)" })" -ForegroundColor White
Write-Host "GPU:        $((Get-GpuTelemetry).Name)" -ForegroundColor White
Write-Host ""

# Gate 1: Single-Stream Maximum Throughput
Write-GateHeader 1 "Single-Stream Maximum Throughput"
Write-Host "Testing maximum TPS with $($script:Config.MaxTokens) token generation..." -ForegroundColor Gray

$gate1Result = Invoke-Benchmark "single" @{
    "max-tokens" = $script:Config.MaxTokens
    "ctx-size" = 32768
}

$script:GateStatus["Gate1"] = $gate1Result.Success
$script:Results["Gate1"] = @{
    name = "Single-Stream Maximum Throughput"
    success = $gate1Result.Success
    duration_seconds = [math]::Round($gate1Result.Duration.TotalSeconds, 2)
    output_file = $gate1Result.OutputFile
}

if ($gate1Result.Success) {
    # Parse results from JSON output
    try {
        $json = Get-Content $gate1Result.OutputFile -Raw | ConvertFrom-Json
        Write-Metric "Prefill TPS" $json.prefill.tps $script:Targets.PrefillTps
        Write-Metric "Decode TPS" $json.decode.tps $script:Targets.DecodeTps
        Write-Metric "Sustained TPS" $json.stream.sustained_tps $script:Targets.SustainedTps
        Write-Metric "First Token Latency" $json.decode.first_token_ms $script:Targets.FirstTokenMs "ms"
    } catch {
        Write-Host "  (Results parsed from output)" -ForegroundColor DarkGray
    }
} else {
    Write-Host "  Gate 1 FAILED" -ForegroundColor Red
}

# Gate 2: Endurance Matrix
Write-GateHeader 2 "Endurance Matrix (Context Scaling)"
Write-Host "Testing TPS stability across contexts: $($script:Config.EnduranceContexts -join ', ')..." -ForegroundColor Gray

$gate2Result = Invoke-Benchmark "endurance" @{
    "ctx-sizes" = ($script:Config.EnduranceContexts -join ',')
}

$script:GateStatus["Gate2"] = $gate2Result.Success
$script:Results["Gate2"] = @{
    name = "Endurance Matrix"
    success = $gate2Result.Success
    duration_seconds = [math]::Round($gate2Result.Duration.TotalSeconds, 2)
    output_file = $gate2Result.OutputFile
}

if ($gate2Result.Success) {
    Write-Host "  Context scaling test complete" -ForegroundColor Green
} else {
    Write-Host "  Gate 2 FAILED" -ForegroundColor Red
}

# Gate 3: Multi-Stream Saturation
Write-GateHeader 3 "Multi-Stream Saturation"
Write-Host "Testing $($script:Config.SaturationStreams) concurrent streams..." -ForegroundColor Gray

$gate3Result = Invoke-Benchmark "saturation" @{
    "streams" = $script:Config.SaturationStreams
    "tokens-per-stream" = 2048
}

$script:GateStatus["Gate3"] = $gate3Result.Success
$script:Results["Gate3"] = @{
    name = "Multi-Stream Saturation"
    success = $gate3Result.Success
    duration_seconds = [math]::Round($gate3Result.Duration.TotalSeconds, 2)
    output_file = $gate3Result.OutputFile
}

if ($gate3Result.Success) {
    Write-Host "  Saturation test complete" -ForegroundColor Green
} else {
    Write-Host "  Gate 3 FAILED" -ForegroundColor Red
}

# Gate 4: Thermal Stability
Write-GateHeader 4 "Thermal Stability"
$thermalMinutes = [math]::Round($script:Config.ThermalDuration / 60)
Write-Host "Running $thermalMinutes minute thermal soak..." -ForegroundColor Gray
Write-Host "  (This will take $thermalMinutes minutes. Press Ctrl+C to skip)" -ForegroundColor DarkYellow

$gate4Result = Invoke-Benchmark "thermal" @{
    "duration" = $script:Config.ThermalDuration
    "sample-interval" = 5
}

$script:GateStatus["Gate4"] = $gate4Result.Success
$script:Results["Gate4"] = @{
    name = "Thermal Stability"
    success = $gate4Result.Success
    duration_seconds = [math]::Round($gate4Result.Duration.TotalSeconds, 2)
    output_file = $gate4Result.OutputFile
}

if ($gate4Result.Success) {
    try {
        $json = Get-Content $gate4Result.OutputFile -Raw | ConvertFrom-Json
        Write-Metric "Peak Temperature" $json.thermal.peak_temp_c $null "°C"
        Write-Metric "Throttle Events" $json.thermal.throttle_events 0
        Write-Metric "TPS Degradation" $json.thermal.tps_degradation_pct $script:Targets.TpsDegradationThreshold "%"
    } catch {
        Write-Host "  Thermal test complete" -ForegroundColor Green
    }
} else {
    Write-Host "  Gate 4 FAILED" -ForegroundColor Red
}

# Gate 5: Full Certification (if all previous gates passed)
if ($script:GateStatus.Values -notcontains $false) {
    Write-GateHeader 5 "Full Certification"
    Write-Host "Running complete certification suite..." -ForegroundColor Gray

    $gate5Result = Invoke-Benchmark "certify" @{}

    $script:GateStatus["Gate5"] = $gate5Result.Success
    $script:Results["Gate5"] = @{
        name = "Full Certification"
        success = $gate5Result.Success
        duration_seconds = [math]::Round($gate5Result.Duration.TotalSeconds, 2)
        output_file = $gate5Result.OutputFile
    }

    if ($gate5Result.Success) {
        Write-Host "  Full certification complete" -ForegroundColor Green
    } else {
        Write-Host "  Gate 5 FAILED" -ForegroundColor Red
    }
} else {
    Write-GateHeader 5 "Full Certification"
    Write-Host "SKIPPED (previous gates failed)" -ForegroundColor Yellow
    $script:GateStatus["Gate5"] = $false
    $script:Results["Gate5"] = @{
        name = "Full Certification"
        success = $false
        skipped = $true
    }
}

# ============================================================================
# Final Report
# ============================================================================

Write-Banner "CERTIFICATION COMPLETE"

$finalReport = Export-CertificationReport $script:Results

Write-Host ""
Write-Host "Certification ID: " -NoNewline
Write-Host $finalReport.CertificationId -ForegroundColor Cyan
Write-Host ""

Write-Host "Results Summary:" -ForegroundColor White
Write-Host "  Gate 1 (Single-Stream):     $(if ($script:GateStatus['Gate1']) { '✅ PASS' } else { '❌ FAIL' })" -ForegroundColor $(if ($script:GateStatus['Gate1']) { 'Green' } else { 'Red' })
Write-Host "  Gate 2 (Endurance):         $(if ($script:GateStatus['Gate2']) { '✅ PASS' } else { '❌ FAIL' })" -ForegroundColor $(if ($script:GateStatus['Gate2']) { 'Green' } else { 'Red' })
Write-Host "  Gate 3 (Saturation):        $(if ($script:GateStatus['Gate3']) { '✅ PASS' } else { '❌ FAIL' })" -ForegroundColor $(if ($script:GateStatus['Gate3']) { 'Green' } else { 'Red' })
Write-Host "  Gate 4 (Thermal):           $(if ($script:GateStatus['Gate4']) { '✅ PASS' } else { '❌ FAIL' })" -ForegroundColor $(if ($script:GateStatus['Gate4']) { 'Green' } else { 'Red' })
Write-Host "  Gate 5 (Certification):     $(if ($script:GateStatus['Gate5']) { '✅ PASS' } else { '❌ FAIL' })" -ForegroundColor $(if ($script:GateStatus['Gate5']) { 'Green' } else { 'Red' })

Write-Host ""
Write-Host "Reports Generated:" -ForegroundColor White
Write-Host "  JSON:    $($finalReport.JsonPath)"
Write-Host "  Markdown: $($finalReport.MarkdownPath)"
Write-Host ""

$overallStatus = if ($script:GateStatus.Values -contains $false) { "FAILED" } else { "CERTIFIED" }
Write-Host "Overall Status: " -NoNewline
if ($overallStatus -eq "CERTIFIED") {
    Write-Host "✅ CERTIFIED" -ForegroundColor Green
    exit 0
} else {
    Write-Host "❌ FAILED" -ForegroundColor Red
    exit 1
}
