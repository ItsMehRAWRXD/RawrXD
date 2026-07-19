#
.SYNOPSIS
    Executes the bare-metal Deep2 MASM benchmark and calculates valuation metrics.
.DESCRIPTION
    Runs the Deep2 benchmark executable, parses the output, and calculates
    throughput metrics for the valuation deck.
#>

$ErrorActionPreference = "Stop"

# Benchmark constants (must match MASM source)
$TensorSizeBytes = 256L * 1024L * 1024L  # 256 MB
$VecElements = 1024L * 1024L * 64L         # 64M elements
$Iterations = 1000L
$BytesPerIteration = $VecElements * 4L     # 4 bytes per float
$TotalBytesProcessed = $BytesPerIteration * $Iterations

# Model assumptions for 40GB projection
$ModelSizeGB = 40.0
$BytesPerToken = 4.0 * $ModelSizeGB * 1024L * 1024L * 1024L / 2048L  # Rough estimate

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Deep2 Kernel Benchmark Runner" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$startTime = Get-Date

# 1. Run the MASM executable and capture output
$exePath = ".\bench_deep2.exe"
if (-Not (Test-Path $exePath)) {
    Write-Host "Error: $exePath not found. Building first..." -ForegroundColor Yellow
    
    # Try to build
    $buildScript = ".\build_bench.bat"
    if (Test-Path $buildScript) {
        & $buildScript
        if (-Not (Test-Path $exePath)) {
            Write-Host "Error: Build failed. Cannot find $exePath" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "Error: Build script not found at $buildScript" -ForegroundColor Red
        exit 1
    }
}

Write-Host "Executing Deep2 benchmark..." -ForegroundColor Green
$output = & $exePath 2>&1

# Display raw output
Write-Host ""
Write-Host "Raw Output:" -ForegroundColor Gray
$output | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }

# 2. Parse results
$results = @{}
$currentTest = ""

foreach ($line in $output) {
    if ($line -match "Testing (\w+)") {
        $currentTest = $matches[1]
    }
    if ($line -match "Elapsed Ticks:\s*(\d+)" -and $currentTest -ne "") {
        $results[$currentTest] = [long]$matches[1]
        $currentTest = ""
    }
}

if ($results.Count -eq 0) {
    Write-Host "Error: Failed to parse benchmark results." -ForegroundColor Red
    exit 1
}

# 3. Calculate Performance Metrics
$qpf = [System.Diagnostics.Stopwatch]::Frequency

Write-Host ""
Write-Host "========================================" -ForegroundColor White
Write-Host "  DEEP2 KERNEL VALUATION METRICS" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor White
Write-Host " Hardware QPF Timer:   $([string]::Format('{0:N0}', $qpf)) Hz" -ForegroundColor Cyan
Write-Host " Total Data/Iter:      $([string]::Format('{0:N2}', $BytesPerIteration / 1MB)) MB" -ForegroundColor Cyan
Write-Host " Iterations:           $Iterations" -ForegroundColor Cyan
Write-Host "----------------------------------------" -ForegroundColor White

foreach ($test in $results.Keys) {
    $ticks = $results[$test]
    $elapsedSeconds = $ticks / $qpf
    $bytesPerSecond = $TotalBytesProcessed / $elapsedSeconds
    $gbPerSecond = $bytesPerSecond / 1GB
    
    # Calculate cycles per element (assuming 3.5GHz base clock)
    $cpuFreq = 3.5e9
    $totalCycles = $elapsedSeconds * $cpuFreq
    $cyclesPerElement = $totalCycles / ($VecElements * $Iterations)
    
    # Projected TPS for 40GB model
    $projectedTPS = $gbPerSecond / $ModelSizeGB * 1000  # Rough scaling
    
    Write-Host ""
    Write-Host "  $test Results:" -ForegroundColor Yellow
    Write-Host "    Elapsed Time:     $([string]::Format('{0:N4}', $elapsedSeconds)) sec" -ForegroundColor White
    Write-Host "    Throughput:       $([string]::Format('{0:N2}', $gbPerSecond)) GB/s" -ForegroundColor Green
    Write-Host "    Cycles/Element:   $([string]::Format('{0:N2}', $cyclesPerElement))" -ForegroundColor Green
    Write-Host "    Projected TPS:    $([string]::Format('{0:N0}', $projectedTPS)) tokens/sec" -ForegroundColor Magenta
}

Write-Host ""
Write-Host "========================================" -ForegroundColor White
Write-Host "  Benchmark completed in $([string]::Format('{0:N2}', ((Get-Date) - $startTime).TotalSeconds)) seconds" -ForegroundColor Gray
Write-Host "========================================" -ForegroundColor White

# Export to CSV for valuation deck
$csvPath = "Deep2_Benchmark_Results.csv"
$csvData = @()
foreach ($test in $results.Keys) {
    $ticks = $results[$test]
    $elapsedSeconds = $ticks / $qpf
    $bytesPerSecond = $TotalBytesProcessed / $elapsedSeconds
    $gbPerSecond = $bytesPerSecond / 1GB
    
    $csvData += [PSCustomObject]@{
        Kernel = $test
        ElapsedTicks = $ticks
        ElapsedSeconds = $elapsedSeconds
        Throughput_GBps = $gbPerSecond
        TotalBytes = $TotalBytesProcessed
        Iterations = $Iterations
    }
}

$csvData | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host ""
Write-Host "Results exported to: $csvPath" -ForegroundColor Green
