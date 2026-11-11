#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Benchmark RawrXD model loading with actual GGUF files
.DESCRIPTION
    Tests real GGUF model loading performance using discovered models
#>

param(
    [string]$ModelDir = "D:\",
    [int]$TestTokens = 256,
    [string]$OutputDir = "D:\RawrXD\benchmark_results"
)

$ErrorActionPreference = "Stop"

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RawrXD Model Benchmark" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Auto-discover models
Write-Host "Discovering GGUF models..." -ForegroundColor Yellow
$models = Get-ChildItem -Path $ModelDir -Filter "*.gguf" -Recurse -ErrorAction SilentlyContinue | 
    Where-Object { $_.Length -gt 100MB } |  # Filter out tiny test files
    Select-Object FullName, @{N="SizeGB";E={[math]::Round($_.Length/1GB,2)}}, @{N="Name";E={$_.Name}}

if (-not $models) {
    Write-Host "No models found!" -ForegroundColor Red
    exit 1
}

Write-Host "Found $($models.Count) model(s):" -ForegroundColor Green
$models | ForEach-Object { Write-Host "  - $($_.Name) ($($_.SizeGB) GB)" -ForegroundColor Gray }
Write-Host ""

# System info
$sysInfo = @{
    CPU = (Get-CimInstance Win32_Processor).Name
    RAM_GB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}

Write-Host "System: $($sysInfo.CPU), $($sysInfo.RAM_GB) GB RAM" -ForegroundColor Cyan
Write-Host ""

# Results collection
$results = @()

# Test each model
foreach ($model in $models) {
    Write-Host "Testing: $($model.Name)" -ForegroundColor Cyan
    
    try {
        # File I/O benchmark
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $fileStream = [System.IO.File]::OpenRead($model.FullName)
        $buffer = New-Object byte[] (64MB)
        $totalRead = 0
        
        while ($totalRead -lt $model.SizeGB * 1GB -and $fileStream.Read($buffer, 0, $buffer.Length) -gt 0) {
            $totalRead += $buffer.Length
        }
        $fileStream.Close()
        $ioTime = $sw.Elapsed.TotalSeconds
        
        $throughput = [math]::Round($model.SizeGB / $ioTime, 2)
        
        Write-Host "  ✅ I/O: ${ioTime}s (${throughput} GB/s)" -ForegroundColor Green
        
        $results += [PSCustomObject]@{
            Model = $model.Name
            Size_GB = $model.SizeGB
            IO_Time_s = $ioTime
            Throughput_GBps = $throughput
            Status = "OK"
        }
        
    } catch {
        Write-Host "  ❌ Error: $_" -ForegroundColor Red
        $results += [PSCustomObject]@{
            Model = $model.Name
            Size_GB = $model.SizeGB
            IO_Time_s = 0
            Throughput_GBps = 0
            Status = "ERROR"
        }
    }
}

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Benchmark Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$avgThroughput = ($results | Where-Object { $_.Status -eq "OK" } | Measure-Object Throughput_GBps -Average).Average
$totalSize = ($results | Measure-Object Size_GB -Sum).Sum

Write-Host "Models tested: $($results.Count)" -ForegroundColor Yellow
Write-Host "Total size: $([math]::Round($totalSize, 2)) GB" -ForegroundColor Yellow
Write-Host "Average I/O throughput: $([math]::Round($avgThroughput, 2)) GB/s" -ForegroundColor Yellow

# Save results
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvPath = Join-Path $OutputDir "benchmark_${timestamp}.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation

Write-Host ""
Write-Host "Results saved to: $csvPath" -ForegroundColor Green

# Show top performers
Write-Host ""
Write-Host "Top Performers:" -ForegroundColor Cyan
$results | Where-Object { $_.Status -eq "OK" } | 
    Sort-Object Throughput_GBps -Descending | 
    Select-Object -First 5 | 
    Format-Table Model, Size_GB, Throughput_GBps -AutoSize
