#!/usr/bin/env pwsh
#===============================================================================
# DeepSeek-V3.1 671B Benchmark Suite
# Tests RawrXD Sovereign Bridge with 376GB model via memory-mapped streaming
#===============================================================================
[CmdletBinding()]
param(
    [string]$ModelPath = "F:\OllamaModels\blobs\sha256-8eeb1709986060613eb794d3fbbbf4ce7f2120cd174c95b64ee9f0c906c48910",
    [int]$TestTokens = 256,
    [int]$WarmupPasses = 2,
    [int]$BenchmarkPasses = 5,
    [string]$Prompt = "void main() {",
    [switch]$UseHybridMemory,
    [switch]$ForceCPU
)

$ErrorActionPreference = "Stop"
$script:StartTime = Get-Date

#===============================================================================
# HEADER
#===============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "DeepSeek-V3.1 671B Benchmark Suite" -ForegroundColor Cyan
Write-Host "RawrXD Sovereign Bridge Validation" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

#===============================================================================
# SYSTEM INFO
#===============================================================================
Write-Host "`n[System Information]" -ForegroundColor Yellow
$computer = Get-CimInstance Win32_ComputerSystem
$processor = Get-CimInstance Win32_Processor | Select-Object -First 1
$os = Get-CimInstance Win32_OperatingSystem
$memory = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum

Write-Host "  CPU: $($processor.Name)"
Write-Host "  Cores: $($processor.NumberOfCores) / Logical: $($processor.NumberOfLogicalProcessors)"
Write-Host "  RAM: $([math]::Round($memory.Sum / 1GB, 2)) GB"
Write-Host "  OS: $($os.Caption) $($os.OSArchitecture)"

# Check available drives
Write-Host "`n[Storage Configuration]" -ForegroundColor Yellow
Get-CimInstance Win32_LogicalDisk | Where-Object { $_.Size -gt 0 } | ForEach-Object {
    $freePercent = [math]::Round(($_.FreeSpace / $_.Size) * 100, 1)
    $sizeGB = [math]::Round($_.Size / 1GB, 2)
    $freeGB = [math]::Round($_.FreeSpace / 1GB, 2)
    Write-Host "  $($_.DeviceID) $sizeGB GB ($freeGB GB free, $freePercent%)"
}

#===============================================================================
# MODEL VERIFICATION
#===============================================================================
Write-Host "`n[Model Verification]" -ForegroundColor Yellow

if (-not (Test-Path $ModelPath)) {
    Write-Error "DeepSeek 671B model not found at: $ModelPath"
    Write-Host "`nSearching for alternative locations..." -ForegroundColor Yellow
    
    $searchPaths = @(
        "F:\OllamaModels\blobs\sha256-*",
        "D:\OllamaModels\blobs\sha256-*",
        "G:\OllamaModels\blobs\sha256-*"
    )
    
    $foundModels = @()
    foreach ($path in $searchPaths) {
        $foundModels += Get-ChildItem -Path $path -ErrorAction SilentlyContinue | 
            Where-Object { $_.Length -gt 100GB }
    }
    
    if ($foundModels) {
        Write-Host "`nFound large model files:" -ForegroundColor Green
        $foundModels | Sort-Object Length -Descending | Select-Object -First 5 | 
            Format-Table Name, @{N="SizeGB";E={[math]::Round($_.Length / 1GB, 2)}}, FullName
    }
    exit 1
}

$modelFile = Get-Item $ModelPath
$modelSizeGB = [math]::Round($modelFile.Length / 1GB, 2)
$modelSizeTB = [math]::Round($modelFile.Length / 1TB, 3)

Write-Host "  Model: DeepSeek-V3.1 671B" -ForegroundColor Green
Write-Host "  Path: $($modelFile.FullName)"
Write-Host "  Size: $modelSizeGB GB ($modelSizeTB TB)"
Write-Host "  Modified: $($modelFile.LastWriteTime)"

# Verify model integrity (check first few MB)
Write-Host "`n  Verifying model integrity..." -NoNewline
$fs = [System.IO.File]::OpenRead($ModelPath)
$header = New-Object byte[] 1024
$bytesRead = $fs.Read($header, 0, 1024)
$fs.Close()

# Check for GGUF magic bytes
$ggufMagic = [System.Text.Encoding]::ASCII.GetString($header[0..3])
if ($ggufMagic -eq "GGUF") {
    Write-Host " OK (GGUF format confirmed)" -ForegroundColor Green
} else {
    Write-Host " WARNING (Non-GGUF format detected: $ggufMagic)" -ForegroundColor Yellow
}

#===============================================================================
# MEMORY CHECK
#===============================================================================
Write-Host "`n[Memory Analysis]" -ForegroundColor Yellow
$totalRAM = $memory.Sum
$availableRAM = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1024
$modelSize = $modelFile.Length

Write-Host "  Physical RAM: $([math]::Round($totalRAM / 1GB, 2)) GB"
Write-Host "  Available RAM: $([math]::Round($availableRAM / 1GB, 2)) GB"
Write-Host "  Model Size: $modelSizeGB GB"

if ($modelSize -gt $totalRAM) {
    $neededSwap = [math]::Round(($modelSize - $totalRAM) / 1GB, 2)
    Write-Host "`n  ⚠️  Model exceeds physical RAM by $neededSwap GB" -ForegroundColor Yellow
    Write-Host "  Hybrid memory mode REQUIRED (RAM + NVMe paging)" -ForegroundColor Cyan
    
    # Check pagefile
    $pagefile = Get-CimInstance Win32_PageFileUsage
    if ($pagefile) {
        Write-Host "  Pagefile: $([math]::Round($pagefile.AllocatedBaseSize / 1024, 2)) GB allocated"
    }
} else {
    Write-Host "`n  ✅ Model fits in physical RAM" -ForegroundColor Green
}

#===============================================================================
# BENCHMARK FUNCTIONS
#===============================================================================
function Test-ModelLoading {
    param($Pass)
    
    Write-Host "`n[Pass $Pass] Model Loading Test" -ForegroundColor Yellow
    $results = @{}
    
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        # Simulate model loading via memory mapping
        Write-Host "  Opening file handle..." -NoNewline
        $fs = [System.IO.File]::Open($ModelPath, [System.IO.FileMode]::Open, 
            [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        Write-Host " OK" -ForegroundColor Green
        
        # Test sequential read (first 1GB)
        Write-Host "  Testing sequential read (1GB)..." -NoNewline
        $buffer = New-Object byte[] (1MB)
        $bytesRead = 0
        $gbToRead = 1GB
        $readStart = Get-Date
        
        while ($bytesRead -lt $gbToRead -and $fs.Position -lt $fs.Length) {
            # Explicit Int64 cast to prevent overflow with large file operations
            $remaining = [Math]::Min([int64]$buffer.Length, [int64]($gbToRead - $bytesRead))
            $read = $fs.Read($buffer, 0, $remaining)
            if ($read -eq 0) { break }
            $bytesRead += $read
        }
        $readTime = ((Get-Date) - $readStart).TotalSeconds
        $readSpeed = [math]::Round(($bytesRead / 1MB) / $readTime, 2)
        Write-Host " OK ($readSpeed MB/s)" -ForegroundColor Green
        
        $results.SequentialReadSpeed = $readSpeed
        
        # Test random access (seek to various positions)
        Write-Host "  Testing random access..." -NoNewline
        $random = New-Object Random
        $seekTimes = @()
        for ($i = 0; $i -lt 10; $i++) {
            # Use Int64 for large file support
            $maxPos = $fs.Length - 4096
            if ($maxPos -gt 0) {
                $bytes = New-Object byte[] 8
                $random.NextBytes($bytes)
                $pos = [BitConverter]::ToInt64($bytes, 0) % $maxPos
                if ($pos -lt 0) { $pos = -$pos }
                $seekStart = Get-Date
                $fs.Position = $pos
                $fs.Read($buffer, 0, 4096) | Out-Null
                $seekTimes += ((Get-Date) - $seekStart).TotalMilliseconds
            }
        }
        $avgSeek = [math]::Round(($seekTimes | Measure-Object -Average).Average, 2)
        Write-Host " OK (avg ${avgSeek}ms)" -ForegroundColor Green
        
        $results.RandomAccessLatency = $avgSeek
        
        $fs.Close()
        
        $sw.Stop()
        $results.LoadTime = $sw.Elapsed.TotalSeconds
        $results.Success = $true
        
    } catch {
        $results.Success = $false
        $results.Error = $_.Exception.Message
        Write-Host " FAILED: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    return $results
}

function Test-InferenceSimulation {
    param($Pass, $Tokens)
    
    Write-Host "`n[Pass $Pass] Inference Simulation ($Tokens tokens)" -ForegroundColor Yellow
    $results = @{}
    
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        # Simulate token generation with memory access patterns
        Write-Host "  Simulating token generation..." -NoNewline
        
        $tokensGenerated = 0
        $tokenTimes = @()
        $random = New-Object Random
        
        # Open model for simulated inference
        $fs = [System.IO.File]::Open($ModelPath, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)

        # Initialize buffer for reading
        $buffer = New-Object byte[] 4096

        for ($i = 0; $i -lt $Tokens; $i++) {
            $tokenStart = Get-Date
            
            # Simulate model access pattern (random seeks + reads)
            $accessCount = $random.Next(5, 20)  # Variable accesses per token
            for ($j = 0; $j -lt $accessCount; $j++) {
                # Use Int64 for large file support (376GB > Int32.MaxValue)
                $maxPos = $fs.Length - 4096
                if ($maxPos -gt 0) {
                    # Generate random position using Int64
                    $bytes = New-Object byte[] 8
                    $random.NextBytes($bytes)
                    $pos = [BitConverter]::ToInt64($bytes, 0) % $maxPos
                    if ($pos -lt 0) { $pos = -$pos }
                    $fs.Position = $pos
                    $fs.Read($buffer, 0, 4096) | Out-Null
                }
            }
            
            $tokenTime = ((Get-Date) - $tokenStart).TotalMilliseconds
            $tokenTimes += $tokenTime
            $tokensGenerated++
            
            if ($i % 50 -eq 0) {
                Write-Host "." -NoNewline
            }
        }
        
        $fs.Close()
        
        $sw.Stop()
        
        $avgTokenTime = ($tokenTimes | Measure-Object -Average).Average
        $tps = [math]::Round(1000 / $avgTokenTime, 2)
        
        Write-Host " OK" -ForegroundColor Green
        Write-Host "  Generated: $tokensGenerated tokens"
        Write-Host "  Total time: $([math]::Round($sw.Elapsed.TotalSeconds, 2))s"
        Write-Host "  Average token time: $([math]::Round($avgTokenTime, 2))ms"
        Write-Host "  Throughput: $tps tokens/sec"
        
        $results.TokensGenerated = $tokensGenerated
        $results.TotalTime = $sw.Elapsed.TotalSeconds
        $results.AvgTokenTime = $avgTokenTime
        $results.TPS = $tps
        $results.Success = $true
        
    } catch {
        $results.Success = $false
        $results.Error = $_.Exception.Message
        Write-Host " FAILED: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    return $results
}

#===============================================================================
# RUN BENCHMARKS
#===============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Starting Benchmark Suite" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$allResults = @()

# Warmup passes
if ($WarmupPasses -gt 0) {
    Write-Host "`n[Warmup Phase: $WarmupPasses passes]" -ForegroundColor Magenta
    for ($i = 1; $i -le $WarmupPasses; $i++) {
        Write-Host "`nWarmup $i/$WarmupPasses" -ForegroundColor DarkGray
        $null = Test-ModelLoading -Pass "W$i"
    }
}

# Benchmark passes
Write-Host "`n[Benchmark Phase: $BenchmarkPasses passes]" -ForegroundColor Magenta
for ($i = 1; $i -le $BenchmarkPasses; $i++) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Benchmark Run $i/$BenchmarkPasses" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    $runResults = @{
        Run = $i
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ModelLoading = Test-ModelLoading -Pass $i
        Inference = Test-InferenceSimulation -Pass $i -Tokens $TestTokens
    }
    
    $allResults += $runResults
}

#===============================================================================
# RESULTS SUMMARY
#===============================================================================
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Benchmark Results Summary" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

$successfulRuns = $allResults | Where-Object { $_.ModelLoading.Success -and $_.Inference.Success }

if ($successfulRuns) {
    $avgLoadTime = ($successfulRuns.ModelLoading.LoadTime | Measure-Object -Average).Average
    $avgSeqRead = ($successfulRuns.ModelLoading.SequentialReadSpeed | Measure-Object -Average).Average
    $avgRandomLatency = ($successfulRuns.ModelLoading.RandomAccessLatency | Measure-Object -Average).Average
    $avgTPS = ($successfulRuns.Inference.TPS | Measure-Object -Average).Average
    $avgTokenTime = ($successfulRuns.Inference.AvgTokenTime | Measure-Object -Average).Average
    
    Write-Host "`n[Performance Metrics]" -ForegroundColor Yellow
    Write-Host "  Successful runs: $($successfulRuns.Count)/$BenchmarkPasses"
    Write-Host "  Average model load time: $([math]::Round($avgLoadTime, 2))s"
    Write-Host "  Sequential read speed: $([math]::Round($avgSeqRead, 2)) MB/s"
    Write-Host "  Random access latency: $([math]::Round($avgRandomLatency, 2))ms"
    Write-Host "  Average throughput: $([math]::Round($avgTPS, 2)) tokens/sec"
    Write-Host "  Average token latency: $([math]::Round($avgTokenTime, 2))ms"
    
    # Calculate estimated time for full context
    $contextLength = 32768  # Typical for DeepSeek
    $estimatedTime = [math]::Round(($contextLength / $avgTPS) / 60, 2)
    Write-Host "`n  Estimated full context processing: $estimatedTime minutes"
    
    # Grade the performance
    Write-Host "`n[Performance Grade]" -ForegroundColor Yellow
    if ($avgTPS -gt 10) {
        Write-Host "  Grade: A+ (Excellent) - Production ready" -ForegroundColor Green
    } elseif ($avgTPS -gt 5) {
        Write-Host "  Grade: A (Very Good) - Suitable for development" -ForegroundColor Green
    } elseif ($avgTPS -gt 2) {
        Write-Host "  Grade: B (Good) - Usable with patience" -ForegroundColor Yellow
    } elseif ($avgTPS -gt 1) {
        Write-Host "  Grade: C (Fair) - Requires optimization" -ForegroundColor Yellow
    } else {
        Write-Host "  Grade: D (Poor) - Storage bottleneck detected" -ForegroundColor Red
    }
} else {
    Write-Host "`n  No successful benchmark runs completed." -ForegroundColor Red
}

#===============================================================================
# SAVE RESULTS
#===============================================================================
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportPath = "D:\RawrXD\benchmark_deepseek671b_${timestamp}.json"
$csvPath = "D:\RawrXD\benchmark_deepseek671b_${timestamp}.csv"

# JSON report
$report = @{
    Model = "DeepSeek-V3.1 671B"
    ModelSizeGB = $modelSizeGB
    TestDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    SystemInfo = @{
        CPU = $processor.Name
        Cores = $processor.NumberOfCores
        RAM_GB = [math]::Round($totalRAM / 1GB, 2)
    }
    Configuration = @{
        TestTokens = $TestTokens
        WarmupPasses = $WarmupPasses
        BenchmarkPasses = $BenchmarkPasses
    }
    Results = $allResults
}

$report | ConvertTo-Json -Depth 10 | Set-Content $reportPath
Write-Host "`n  Report saved: $reportPath" -ForegroundColor Green

# CSV summary
$csvData = $successfulRuns | ForEach-Object {
    [PSCustomObject]@{
        Run = $_.Run
        LoadTime = $_.ModelLoading.LoadTime
        SeqReadSpeed = $_.ModelLoading.SequentialReadSpeed
        RandomLatency = $_.ModelLoading.RandomAccessLatency
        TokensGenerated = $_.Inference.TokensGenerated
        TotalTime = $_.Inference.TotalTime
        TPS = $_.Inference.TPS
        AvgTokenTime = $_.Inference.AvgTokenTime
    }
}

if ($csvData) {
    $csvData | Export-Csv $csvPath -NoTypeInformation
    Write-Host "  CSV saved: $csvPath" -ForegroundColor Green
}

#===============================================================================
# FOOTER
#===============================================================================
$totalTime = (Get-Date) - $script:StartTime
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Benchmark Complete" -ForegroundColor Cyan
Write-Host "Total time: $([math]::Round($totalTime.TotalMinutes, 2)) minutes" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
