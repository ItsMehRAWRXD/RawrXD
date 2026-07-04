#!/usr/bin/env pwsh
# Test 40B Qwen model loading with architecture detection

$ErrorActionPreference = "Stop"

$modelPath = "F:\OllamaModels\Qwen3.5-40B-Claude-4.6-Opus-Deckard-Heretic-Uncensored-Thinking.Q4_K_M.gguf"
$exePath = "d:\rawrxd\build\gold\RawrXD_Gold.exe"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "40B Qwen Model Loading Test" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Check if model exists
if (-not (Test-Path $modelPath)) {
    Write-Host "ERROR: Model not found at $modelPath" -ForegroundColor Red
    exit 1
}

# Check if executable exists
if (-not (Test-Path $exePath)) {
    Write-Host "ERROR: Executable not found at $exePath" -ForegroundColor Red
    exit 1
}

Write-Host "Model: $modelPath" -ForegroundColor Gray
Write-Host "Executable: $exePath" -ForegroundColor Gray
Write-Host ""

# Test 1: Check executable runs
Write-Host "Test 1: Verifying executable..." -ForegroundColor Yellow
$exeInfo = Get-Item $exePath
Write-Host "  Size: $([math]::Round($exeInfo.Length / 1MB, 2)) MB" -ForegroundColor Gray
Write-Host "  Modified: $($exeInfo.LastWriteTime)" -ForegroundColor Gray
Write-Host "  ✓ Executable exists" -ForegroundColor Green

# Test 2: Try to load model (capture first 50 lines of output)
Write-Host ""
Write-Host "Test 2: Loading 40B Qwen model..." -ForegroundColor Yellow
Write-Host "  This may take a moment for a 40B model..." -ForegroundColor Gray

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $exePath
$psi.Arguments = "--model `"$modelPath`" --verbose"
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true

$process = New-Object System.Diagnostics.Process
$process.StartInfo = $psi

# Start process
$started = $process.Start()
if (-not $started) {
    Write-Host "  ✗ Failed to start process" -ForegroundColor Red
    exit 1
}

# Read output with timeout
$output = @()
$errorOutput = @()
$timeout = 30  # seconds
$sw = [System.Diagnostics.Stopwatch]::StartNew()

while ($sw.ElapsedMilliseconds -lt ($timeout * 1000) -and -not $process.HasExited) {
    # Read available output
    while ($process.StandardOutput.Peek() -ge 0) {
        $line = $process.StandardOutput.ReadLine()
        if ($line) {
            $output += $line
            Write-Host "  [OUT] $line" -ForegroundColor Gray
        }
    }
    
    while ($process.StandardError.Peek() -ge 0) {
        $line = $process.StandardError.ReadLine()
        if ($line) {
            $errorOutput += $line
            # Check for our GGUF loader messages
            if ($line -match "GGUFLoader|Architecture|Layers|Context|Loading model") {
                Write-Host "  [ERR] $line" -ForegroundColor Cyan
            } else {
                Write-Host "  [ERR] $line" -ForegroundColor DarkGray
            }
        }
    }
    
    Start-Sleep -Milliseconds 100
    
    # Check if we got the key messages
    $hasArchitecture = $errorOutput | Where-Object { $_ -match "Architecture detected" }
    $hasLayers = $errorOutput | Where-Object { $_ -match "Layers:" }
    
    if ($hasArchitecture -and $hasLayers) {
        Write-Host ""
        Write-Host "  ✓ Model metadata detected successfully!" -ForegroundColor Green
        break
    }
}

# Kill process if still running
if (-not $process.HasExited) {
    $process.Kill()
    $process.WaitForExit(5000) | Out-Null
}

# Analyze results
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Results" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$architectureDetected = $errorOutput | Where-Object { $_ -match "Architecture detected" }
$layerCount = $errorOutput | Where-Object { $_ -match "Layers:\s*\d+" }
$contextLength = $errorOutput | Where-Object { $_ -match "Context:" }

if ($architectureDetected) {
    Write-Host "✓ Architecture detection: PASS" -ForegroundColor Green
    Write-Host "  $architectureDetected" -ForegroundColor Gray
} else {
    Write-Host "✗ Architecture detection: FAIL" -ForegroundColor Red
}

if ($layerCount) {
    Write-Host "✓ Layer count detection: PASS" -ForegroundColor Green
    Write-Host "  $layerCount" -ForegroundColor Gray
} else {
    Write-Host "✗ Layer count detection: FAIL" -ForegroundColor Red
}

if ($contextLength) {
    Write-Host "✓ Context length detection: PASS" -ForegroundColor Green
    Write-Host "  $contextLength" -ForegroundColor Gray
} else {
    Write-Host "✗ Context length detection: FAIL (may be OK)" -ForegroundColor Yellow
}

# Summary
Write-Host ""
$allPassed = ($architectureDetected -and $layerCount)
if ($allPassed) {
    Write-Host "✓ ALL CRITICAL TESTS PASSED" -ForegroundColor Green
    Write-Host "The 40B Qwen model loads correctly with architecture detection!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "✗ SOME TESTS FAILED" -ForegroundColor Red
    Write-Host "Check the output above for details." -ForegroundColor Yellow
    exit 1
}
