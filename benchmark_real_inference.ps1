#!/usr/bin/env pwsh
#===============================================================================
# Real Inference Benchmark - DeepSeek-V3.1 671B
# Tests ACTUAL transformer execution via NativeBackend
# Rotating cylinder weight loading - only active parameters in memory
#===============================================================================
[CmdletBinding()]
param(
    [string]$ModelPath = "F:\OllamaModels\blobs\sha256-8eeb1709986060613eb794d3fbbbf4ce7f2120cd174c95b64ee9f0c906c48910",
    [int]$TokensToGenerate = 32,
    [string]$Prompt = "void main() {",
    [switch]$UseGPU,
    [switch]$ProfileMemory,
    [int]$ContextWindow = 4096
)

$ErrorActionPreference = "Stop"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Real Inference Benchmark" -ForegroundColor Cyan
Write-Host "DeepSeek-V3.1 671B (376GB)" -ForegroundColor Cyan
Write-Host "Rotating Cylinder Architecture" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# System info
$cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
$ram = [math]::Round((Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB, 2)
$gpu = (Get-CimInstance Win32_VideoController | Select-Object -First 1).Name

Write-Host "`n[System]" -ForegroundColor Yellow
Write-Host "  CPU: $cpu"
Write-Host "  RAM: $ram GB"
Write-Host "  GPU: $gpu"

# Check for RawrXD runtime
$runtimePaths = @(
    "D:\RawrXD\src\sovereign\rawrxd.exe",
    "D:\RawrXD\bin\rawrxd.exe",
    "F:\RawrXD\bin\rawrxd.exe"
)

$runtime = $null
foreach ($path in $runtimePaths) {
    if (Test-Path $path) {
        $runtime = $path
        break
    }
}

if (-not $runtime) {
    Write-Error "RawrXD runtime not found. Build rawrxd.exe first."
    exit 1
}

Write-Host "`n[Runtime]" -ForegroundColor Yellow
Write-Host "  Path: $runtime"
Write-Host "  Version: $((Get-Item $runtime).LastWriteTime)"

# Verify model
$model = Get-Item $ModelPath
$modelSizeGB = [math]::Round($model.Length / 1GB, 2)
Write-Host "`n[Model]" -ForegroundColor Yellow
Write-Host "  File: $($model.Name)"
Write-Host "  Size: $modelSizeGB GB"
Write-Host "  Path: $($model.FullName)"

# Create benchmark config
$configPath = "D:\RawrXD\benchmark_config.json"
$config = @{
    model = $ModelPath
    prompt = $Prompt
    tokens = $TokensToGenerate
    context_window = $ContextWindow
    use_gpu = $UseGPU.IsPresent
    profile_memory = $ProfileMemory.IsPresent
    rotating_cylinder = $true
    active_layers = 2  # Only 2 layers in RAM at a time
    kv_cache_gb = 8    # KV cache size
    thread_count = 16
    batch_size = 1
} | ConvertTo-Json -Depth 3

$config | Set-Content $configPath
Write-Host "`n[Config]" -ForegroundColor Yellow
Write-Host "  Tokens: $TokensToGenerate"
Write-Host "  Context: $ContextWindow"
Write-Host "  GPU: $($UseGPU.IsPresent)"
Write-Host "  Rotating Cylinder: ENABLED (2 active layers)"

# Run benchmark
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Starting Real Inference..." -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Execute via RawrXD runtime
$env:RAWRXD_MODEL_PATH = $ModelPath
$env:RAWRXD_ACTIVE_LAYERS = "2"
$env:RAWRXD_KV_CACHE_MB = "8192"
$env:RAWRXD_ROTATING_CYLINDER = "1"

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $runtime
$psi.Arguments = "--benchmark --config `"$configPath`" --tokens $TokensToGenerate --prompt `"$Prompt`""
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$psi.WorkingDirectory = "D:\RawrXD"

$process = [System.Diagnostics.Process]::Start($psi)
$output = $process.StandardOutput.ReadToEnd()
$error = $process.StandardError.ReadToEnd()
$process.WaitForExit()

$stopwatch.Stop()

# Parse results
Write-Host "`n[Raw Output]" -ForegroundColor DarkGray
Write-Host $output

if ($error) {
    Write-Host "`n[Errors]" -ForegroundColor Red
    Write-Host $error
}

# Extract metrics
$tokensGenerated = 0
$ttft = 0
$tps = 0
$memoryPeak = 0

if ($output -match "Tokens generated:\s*(\d+)") {
    $tokensGenerated = [int]$matches[1]
}
if ($output -match "TTFT:\s*([\d.]+)") {
    $ttft = [float]$matches[1]
}
if ($output -match "Throughput:\s*([\d.]+)") {
    $tps = [float]$matches[1]
}
if ($output -match "Peak memory:\s*([\d.]+)") {
    $memoryPeak = [float]$matches[1]
}

# Calculate if not provided
if ($tokensGenerated -gt 0 -and $tps -eq 0) {
    $tps = $tokensGenerated / $stopwatch.Elapsed.TotalSeconds
}

# Results
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Results" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

Write-Host "`n[Timing]" -ForegroundColor Yellow
Write-Host "  Total time: $($stopwatch.Elapsed.ToString('mm\:ss\.fff'))"
Write-Host "  TTFT: $ttft ms"
Write-Host "  Tokens: $tokensGenerated"

Write-Host "`n[Performance]" -ForegroundColor Yellow
Write-Host "  Throughput: $([math]::Round($tps, 2)) tokens/sec"

if ($tps -gt 0) {
    $msPerToken = 1000 / $tps
    Write-Host "  Latency: $([math]::Round($msPerToken, 2)) ms/token"
}

Write-Host "`n[Memory]" -ForegroundColor Yellow
if ($memoryPeak -gt 0) {
    Write-Host "  Peak: $([math]::Round($memoryPeak, 2)) GB"
} else {
    Write-Host "  Peak: Not measured"
}
Write-Host "  Model: $modelSizeGB GB (on disk)"
Write-Host "  Active: ~10-20 GB (2 layers + KV cache)"

# Grade
Write-Host "`n[Grade]" -ForegroundColor Yellow
if ($tps -gt 10) {
    Write-Host "  A+ (Excellent) - GPU accelerated" -ForegroundColor Green
} elseif ($tps -gt 2) {
    Write-Host "  A (Very Good) - CPU optimized" -ForegroundColor Green
} elseif ($tps -gt 0.5) {
    Write-Host "  B (Good) - Usable for development" -ForegroundColor Yellow
} elseif ($tps -gt 0.1) {
    Write-Host "  C (Fair) - Requires patience" -ForegroundColor Yellow
} else {
    Write-Host "  D (Slow) - Check configuration" -ForegroundColor Red
}

# Save report
$report = @{
    timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    model = "DeepSeek-V3.1 671B"
    model_size_gb = $modelSizeGB
    system = @{ cpu = $cpu; ram_gb = $ram; gpu = $gpu }
    config = $config | ConvertFrom-Json
    results = @{
        total_time_sec = $stopwatch.Elapsed.TotalSeconds
        tokens_generated = $tokensGenerated
        ttft_ms = $ttft
        throughput_tps = $tps
        memory_peak_gb = $memoryPeak
    }
} | ConvertTo-Json -Depth 5

$reportPath = "D:\RawrXD\benchmark_real_inference_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
$report | Set-Content $reportPath

Write-Host "`n  Report: $reportPath" -ForegroundColor Green
Write-Host "`n========================================" -ForegroundColor Cyan
