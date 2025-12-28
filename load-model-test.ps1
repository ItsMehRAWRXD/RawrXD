#!/usr/bin/env pwsh
# Quick model loading test for RawrXD-QtShell

param(
    [string]$ModelPath = ""
)

$ErrorActionPreference = "Stop"

Write-Host "🚀 RawrXD-QtShell Model Loading Test" -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Green
Write-Host ""

$ExePath = Join-Path $PSScriptRoot "build\bin\Release\RawrXD-QtShell.exe"
if (-not (Test-Path $ExePath)) {
    Write-Host "❌ RawrXD-QtShell.exe not found" -ForegroundColor Red
    Write-Host "   Run build first: cmake --build . --config Release --target RawrXD-QtShell" -ForegroundColor Yellow
    exit 1
}

# Find a model if not specified
if ([string]::IsNullOrEmpty($ModelPath)) {
    $SearchPaths = @(
        "RawrXD-ModelLoader\phi-3-mini.gguf",
        "models\*.gguf",
        "..\models\*.gguf"
    )
    
    foreach ($pattern in $SearchPaths) {
        $found = Get-ChildItem -Path (Join-Path $PSScriptRoot $pattern) -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) {
            $ModelPath = $found.FullName
            break
        }
    }
}

if ([string]::IsNullOrEmpty($ModelPath) -or -not (Test-Path $ModelPath)) {
    Write-Host "❌ No GGUF model found" -ForegroundColor Red
    Write-Host "   Usage: .\load-model-test.ps1 path\to\model.gguf" -ForegroundColor Yellow
    exit 1
}

$ModelSize = (Get-Item $ModelPath).Length / 1MB
Write-Host "Model: $ModelPath" -ForegroundColor Cyan
Write-Host "Size:  $($ModelSize.ToString('F2')) MB" -ForegroundColor Cyan
Write-Host ""

Write-Host "Starting IDE..." -ForegroundColor Blue
Write-Host "Expected: Token streaming at 8,000+ TPS" -ForegroundColor Gray
Write-Host ""

# Launch IDE with model
$StartTime = Get-Date
& $ExePath --model "$ModelPath" --verbose
$Duration = (Get-Date) - $StartTime

Write-Host ""
Write-Host "Runtime: $($Duration.TotalSeconds.ToString('F2')) seconds" -ForegroundColor Yellow

# Check logs
$LogPath = Join-Path $PSScriptRoot "build\bin\Release\runlog.txt"
if (Test-Path $LogPath) {
    Write-Host ""
    Write-Host "📋 Execution Log:" -ForegroundColor Blue
    Get-Content $LogPath | Select-Object -Last 20
}
