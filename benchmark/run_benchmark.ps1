#!/usr/bin/env pwsh
# RawrXD End-to-End Benchmark Suite
# This script runs comprehensive benchmarks on the RawrXD inference engine

param(
    [string]$Executable = "d:\rawrxd\rawrxd_v3.exe",
    [string]$ModelDir = "F:\OllamaModels",
    [int]$MaxTokens = 64,
    [int]$WarmupTokens = 10
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RawrXD End-to-End Benchmark Suite" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check executable
if (-not (Test-Path $Executable)) {
    Write-Error "Executable not found: $Executable"
    exit 1
}

$exeInfo = Get-Item $Executable
Write-Host "Executable: $($exeInfo.FullName)" -ForegroundColor Green
Write-Host "Size: $([math]::Round($exeInfo.Length/1KB, 2)) KB" -ForegroundColor Green
Write-Host ""

# Find available models
Write-Host "Scanning for models in $ModelDir..." -ForegroundColor Yellow
$models = @()
if (Test-Path $ModelDir) {
    $models = Get-ChildItem $ModelDir -Recurse -Filter "*.gguf" | 
        Select-Object FullName, @{N="SizeGB";E={[math]::Round($_.Length/1GB,2)}}, @{N="SizeMB";E={[math]::Round($_.Length/1MB,2)}} |
        Sort-Object SizeGB
}

# Also check local models
$localModels = Get-ChildItem "d:\rawrxd\src\*.gguf" -ErrorAction SilentlyContinue | 
    Select-Object FullName, @{N="SizeGB";E={[math]::Round($_.Length/1GB,2)}}, @{N="SizeMB";E={[math]::Round($_.Length/1MB,2)}}
$models = @($models) + @($localModels) | Sort-Object SizeGB

Write-Host "Found $($models.Count) models" -ForegroundColor Green
Write-Host ""

# Filter to models under 2GB for initial testing
$testModels = $models | Where-Object { $_.SizeGB -lt 2.0 } | Select-Object -First 5

if ($testModels.Count -eq 0) {
    Write-Warning "No small models found (< 2GB). Using dummy model for smoke test."
    $testModels = @(@{ FullName = "d:\rawrxd\src\dummy.gguf"; SizeGB = 0; SizeMB = 0.25 })
}

Write-Host "Test Models (under 2GB):" -ForegroundColor Cyan
$testModels | ForEach-Object { 
    Write-Host "  - $($_.FullName) ($($_.SizeGB) GB / $($_.SizeMB) MB)" 
}
Write-Host ""

# Benchmark results storage
$results = @()

# Run benchmarks
foreach ($model in $testModels) {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Benchmarking: $($model.FullName)" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Test prompts of varying complexity
    $prompts = @(
        "Hello",
        "The quick brown fox",
        "Explain quantum computing in simple terms"
    )
    
    foreach ($prompt in $prompts) {
        Write-Host "Prompt: '$prompt'" -ForegroundColor Yellow
        
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        
        try {
            $output = & $Executable inference --model $model.FullName --prompt $prompt --max-tokens $MaxTokens --verbose 2>&1
            $sw.Stop()
            
            # Parse output for tokens generated
            $tokensMatch = $output | Select-String -Pattern "Tokens:\s+(\d+)"
            $tokens = if ($tokensMatch) { [int]$tokensMatch.Matches[0].Groups[1].Value } else { 0 }
            
            $timeMatch = $output | Select-String -Pattern "Total time:\s+([\d.]+)"
            $timeMs = if ($timeMatch) { [double]$timeMatch.Matches[0].Groups[1].Value } else { $sw.ElapsedMilliseconds }
            
            $tokensPerSec = if ($timeMs -gt 0) { $tokens / ($timeMs / 1000.0) } else { 0 }
            
            $result = [PSCustomObject]@{
                Model = Split-Path $model.FullName -Leaf
                SizeGB = $model.SizeGB
                Prompt = $prompt
                Tokens = $tokens
                TimeMs = $timeMs
                TokensPerSec = $tokensPerSec
                Status = "Success"
                Output = ($output | Select-Object -Last 5) -join "`n"
            }
            
            Write-Host "  Tokens: $tokens" -ForegroundColor Green
            Write-Host "  Time: $([math]::Round($timeMs, 2)) ms" -ForegroundColor Green
            Write-Host "  Tokens/sec: $([math]::Round($tokensPerSec, 2))" -ForegroundColor Green
        }
        catch {
            $sw.Stop()
            $result = [PSCustomObject]@{
                Model = Split-Path $model.FullName -Leaf
                SizeGB = $model.SizeGB
                Prompt = $prompt
                Tokens = 0
                TimeMs = $sw.ElapsedMilliseconds
                TokensPerSec = 0
                Status = "Failed: $_"
                Output = ""
            }
            Write-Host "  FAILED: $_" -ForegroundColor Red
        }
        
        $results += $result
        Write-Host ""
    }
}

# Summary Report
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Benchmark Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$successful = $results | Where-Object { $_.Status -eq "Success" }
if ($successful.Count -gt 0) {
    $avgTokensPerSec = ($successful | Measure-Object -Property TokensPerSec -Average).Average
    $maxTokensPerSec = ($successful | Measure-Object -Property TokensPerSec -Maximum).Maximum
    $minTokensPerSec = ($successful | Measure-Object -Property TokensPerSec -Minimum).Minimum
    
    Write-Host "Successful runs: $($successful.Count)" -ForegroundColor Green
    Write-Host "Average tokens/sec: $([math]::Round($avgTokensPerSec, 2))" -ForegroundColor Green
    Write-Host "Max tokens/sec: $([math]::Round($maxTokensPerSec, 2))" -ForegroundColor Green
    Write-Host "Min tokens/sec: $([math]::Round($minTokensPerSec, 2))" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "Performance Analysis:" -ForegroundColor Yellow
    
    if ($avgTokensPerSec -lt 1.0) {
        Write-Host "  => CRITICAL: Very low throughput (< 1 token/sec)" -ForegroundColor Red
        Write-Host "  => Likely causes: Memory allocation overhead, unoptimized kernels" -ForegroundColor Red
        Write-Host "  => Recommendations:" -ForegroundColor Red
        Write-Host "     1. Implement Q4_0/Q8_0 quantization (2-4x speedup)" -ForegroundColor Red
        Write-Host "     2. Add multi-threading across attention heads (1.5-2x speedup)" -ForegroundColor Red
        Write-Host "     3. Optimize KV cache layout" -ForegroundColor Red
    }
    elseif ($avgTokensPerSec -lt 10.0) {
        Write-Host "  => LOW: Sub-optimal throughput (1-10 tokens/sec)" -ForegroundColor Yellow
        Write-Host "  => Recommendations:" -ForegroundColor Yellow
        Write-Host "     1. Enable AVX512 kernels if available" -ForegroundColor Yellow
        Write-Host "     2. Implement memory prefetching" -ForegroundColor Yellow
        Write-Host "     3. Add layer fusion optimizations" -ForegroundColor Yellow
    }
    elseif ($avgTokensPerSec -lt 50.0) {
        Write-Host "  => MODERATE: Acceptable throughput (10-50 tokens/sec)" -ForegroundColor Green
        Write-Host "  => Recommendations:" -ForegroundColor Green
        Write-Host "     1. Profile attention vs MLP time distribution" -ForegroundColor Green
        Write-Host "     2. Consider speculative decoding for 2x speedup" -ForegroundColor Green
    }
    else {
        Write-Host "  => GOOD: Solid throughput (> 50 tokens/sec)" -ForegroundColor Cyan
        Write-Host "  => System is well-optimized for CPU inference" -ForegroundColor Cyan
    }
}
else {
    Write-Host "No successful benchmark runs." -ForegroundColor Red
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  1. Check that models exist and are valid GGUF files" -ForegroundColor Yellow
    Write-Host "  2. Verify executable has required dependencies" -ForegroundColor Yellow
    Write-Host "  3. Check Windows Event Viewer for crash details" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan

# Export results to CSV
$csvPath = "d:\src\benchmark\benchmark_results.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "Results exported to: $csvPath" -ForegroundColor Green
