#!/usr/bin/env pwsh
# RawrXD Performance Benchmark Suite
# Compares against llama.cpp baseline on same hardware

param(
    [string]$BuildDir = "build",
    [string]$LlamaCppPath = $env:LLAMA_CPP_PATH,
    [string]$ReportDir = "benchmark\reports",
    [string]$ModelsDir = "benchmark\models",
    [string]$OutputDir = "benchmark\results"
)

$ErrorActionPreference = "Stop"

# Benchmark configuration
$Benchmarks = @(
    @{ Name = "Throughput (512 ctx)"; Prompt = "benchmark\prompts\code_review.txt"; MaxTokens = 256; Context = 512; Repeats = 5 },
    @{ Name = "Throughput (4K ctx)"; Prompt = "benchmark\prompts\code_review.txt"; MaxTokens = 256; Context = 4096; Repeats = 3 },
    @{ Name = "Throughput (32K ctx)"; Prompt = "benchmark\prompts\code_review.txt"; MaxTokens = 256; Context = 32768; Repeats = 3 },
    @{ Name = "Long Context (128K)"; Prompt = "benchmark\prompts\long_context.txt"; MaxTokens = 128; Context = 131072; Repeats = 1 },
    @{ Name = "Startup Latency"; Prompt = "benchmark\prompts\short.txt"; MaxTokens = 1; Context = 512; Repeats = 10 }
)

$Models = @(
    @{ Name = "Qwen2.5-7B"; Path = "$ModelsDir\qwen2.5-7b-q4_k_m.gguf"; Size = "7B" },
    @{ Name = "Llama-3.1-8B"; Path = "$ModelsDir\llama-3.1-8b-q4_k_m.gguf"; Size = "8B" }
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RawrXD Performance Benchmark" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Build:       $BuildDir"
Write-Host "llama.cpp:   $LlamaCppPath"
Write-Host "Models:      $ModelsDir"
Write-Host ""

# Verify prerequisites
if (-not (Test-Path "$BuildDir\RawrXD.exe")) {
    Write-Host "ERROR: RawrXD.exe not found. Run build.ps1 first." -ForegroundColor Red
    exit 1
}

if (-not $LlamaCppPath -or -not (Test-Path "$LlamaCppPath\main.exe")) {
    Write-Host "WARNING: llama.cpp not found at `$LLAMA_CPP_PATH. Baseline comparison disabled." -ForegroundColor Yellow
}

New-Item -ItemType Directory -Force -Path $ReportDir, $OutputDir | Out-Null

$Results = @()
$StartTime = Get-Date

foreach ($model in $Models) {
    if (-not (Test-Path $model.Path)) {
        Write-Host "[SKIP] Model $($model.Name) not found at $($model.Path)" -ForegroundColor Yellow
        continue
    }
    
    Write-Host ""
    Write-Host "Model: $($model.Name) ($($model.Size))" -ForegroundColor Cyan
    Write-Host "----------------------------------------" -ForegroundColor Cyan
    
    foreach ($bench in $Benchmarks) {
        if (-not (Test-Path $bench.Prompt)) {
            Write-Host "  [SKIP] $($bench.Name) - prompt not found" -ForegroundColor Yellow
            continue
        }
        
        Write-Host "  Benchmark: $($bench.Name)..." -NoNewline
        
        # Run RawrXD benchmark
        $rawrXDResults = @()
        for ($i = 0; $i -lt $bench.Repeats; $i++) {
            $metrics = Run-RawrXD-Benchmark -Exe "$BuildDir\RawrXD.exe" -Model $model.Path -Prompt $bench.Prompt -MaxTokens $bench.MaxTokens -Context $bench.Context
            if ($metrics) { $rawrXDResults += $metrics }
        }
        
        # Run llama.cpp baseline if available
        $llamaResults = @()
        if ($LlamaCppPath -and (Test-Path "$LlamaCppPath\main.exe")) {
            for ($i = 0; $i -lt $bench.Repeats; $i++) {
                $metrics = Run-LlamaCpp-Benchmark -Exe "$LlamaCppPath\main.exe" -Model $model.Path -Prompt $bench.Prompt -MaxTokens $bench.MaxTokens -Context $bench.Context
                if ($metrics) { $llamaResults += $metrics }
            }
        }
        
        # Calculate statistics
        $rawrXDAvg = if ($rawrXDResults.Count -gt 0) { ($rawrXDResults | Measure-Object -Property TokensPerSec -Average).Average } else { 0 }
        $llamaAvg = if ($llamaResults.Count -gt 0) { ($llamaResults | Measure-Object -Property TokensPerSec -Average).Average } else { 0 }
        $ratio = if ($llamaAvg -gt 0) { $rawrXDAvg / $llamaAvg } else { 0 }
        
        $result = @{
            Model = $model.Name
            Benchmark = $bench.Name
            RawrXD_TPS = [math]::Round($rawrXDAvg, 2)
            LlamaCpp_TPS = [math]::Round($llamaAvg, 2)
            Ratio = [math]::Round($ratio, 2)
            Context = $bench.Context
            MaxTokens = $bench.MaxTokens
            Repeats = $bench.Repeats
        }
        $Results += $result
        
        $status = if ($ratio -ge 0.9) { "✓" } elseif ($ratio -ge 0.7) { "~" } else { "✗" }
        Write-Host " $status RawrXD: $([math]::Round($rawrXDAvg, 1)) tok/s, llama.cpp: $([math]::Round($llamaAvg, 1)) tok/s ($([math]::Round($ratio*100))%)" -ForegroundColor $(if ($ratio -ge 0.9) { "Green" } elseif ($ratio -ge 0.7) { "Yellow" } else { "Red" })
    }
}

$totalDuration = (Get-Date) - $StartTime

# Generate report
$report = @{
    timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    commit = (git rev-parse HEAD 2>$null) || "unknown"
    duration_seconds = [math]::Round($totalDuration.TotalSeconds, 2)
    system = @{
        cpu = (Get-WmiObject Win32_Processor).Name
        memory_gb = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
        gpu = if (Get-Command nvidia-smi -ErrorAction SilentlyContinue) { (nvidia-smi --query-gpu=name --format=csv,noheader) } else { "N/A" }
    }
    results = $Results
}

$reportPath = "$ReportDir\benchmark_report.json"
$report | ConvertTo-Json -Depth 4 | Set-Content $reportPath

# Print summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Benchmark Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$overallRatio = if ($Results.Count -gt 0) { ($Results | Measure-Object -Property Ratio -Average).Average } else { 0 }
Write-Host "Overall Performance: $([math]::Round($overallRatio*100, 1))% of llama.cpp baseline"
Write-Host "Time: $($totalDuration.TotalMinutes.ToString('F1')) minutes"
Write-Host "Report: $reportPath"

# Exit with error code if significantly below target
if ($overallRatio -lt 0.7 -and $Results.Count -gt 0) {
    Write-Host ""
    Write-Host "WARNING: Performance below 70% of baseline" -ForegroundColor Red
    exit 1
}

exit 0

# Helper functions
function Run-RawrXD-Benchmark {
    param($Exe, $Model, $Prompt, $MaxTokens, $Context)
    
    $promptText = Get-Content $Prompt -Raw
    $tempFile = [System.IO.Path]::GetTempFileName()
    $promptText | Set-Content $tempFile
    
    $start = Get-Date
    $output = & $Exe --model $Model --prompt-file $tempFile --max-tokens $MaxTokens --ctx-size $Context --benchmark-mode 2>&1
    $duration = (Get-Date) - $start
    
    Remove-Item $tempFile -ErrorAction SilentlyContinue
    
    # Parse output for metrics
    $tokens = if ($output -match "Generated (\d+) tokens") { [int]$Matches[1] } else { 0 }
    $tps = if ($duration.TotalSeconds -gt 0) { $tokens / $duration.TotalSeconds } else { 0 }
    
    return @{ TokensPerSec = $tps; Tokens = $tokens; Duration = $duration.TotalSeconds }
}

function Run-LlamaCpp-Benchmark {
    param($Exe, $Model, $Prompt, $MaxTokens, $Context)
    
    $promptText = Get-Content $Prompt -Raw
    $tempFile = [System.IO.Path]::GetTempFileName()
    $promptText | Set-Content $tempFile
    
    $start = Get-Date
    $output = & $Exe -m $Model -f $tempFile -n $MaxTokens -c $Context --temp 0.8 2>&1
    $duration = (Get-Date) - $start
    
    Remove-Item $tempFile -ErrorAction SilentlyContinue
    
    # Parse output for metrics
    $tokens = if ($output -match "generated (\d+) tokens") { [int]$Matches[1] } else { 0 }
    $tps = if ($duration.TotalSeconds -gt 0) { $tokens / $duration.TotalSeconds } else { 0 }
    
    return @{ TokensPerSec = $tps; Tokens = $tokens; Duration = $duration.TotalSeconds }
}
