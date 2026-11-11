# RawrXD Telemetry Diagnostic Test
# Captures latency histograms to identify bottlenecks

param(
    [int]$TestDurationSeconds = 30,
    [int]$TargetTPS = 100
)

$ErrorActionPreference = "Stop"
$TestLog = "d:\RawrXD\telemetry-diagnostic.log"

function Write-Log($Message, $Level = "INFO") {
    $timestamp = Get-Date -Format "HH:mm:ss.fff"
    $line = "[$timestamp] [$Level] $Message"
    Add-Content -Path $TestLog -Value $line -ErrorAction SilentlyContinue
    
    $color = switch ($Level) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "WARN" { "Yellow" }
        "DATA" { "Cyan" }
        default { "Gray" }
    }
    Write-Host "  $line" -ForegroundColor $color
}

# Initialize log
"RawrXD Telemetry Diagnostic - Started: $(Get-Date)" | Out-File -FilePath $TestLog -Encoding UTF8
"Target TPS: $TargetTPS | Duration: ${TestDurationSeconds}s" | Add-Content -Path $TestLog

Clear-Host
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "RawrXD Telemetry Diagnostic Test" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Check for zombie processes
Write-Log "Checking for zombie processes..." "INFO"
$processes = Get-Process | Where-Object { $_.Name -like "*RawrXD*" -or $_.Name -like "*telemetry*" -or $_.Name -like "*test*" }
if ($processes) {
    Write-Log "Found $($processes.Count) related processes:" "WARN"
    $processes | ForEach-Object { Write-Log "  - $($_.Name) (PID: $($_.Id))" "WARN" }
    Write-Log "Consider killing these before testing" "WARN"
} else {
    Write-Log "No zombie processes found" "PASS"
}

# Test 1: Local Memory-Mapped File (no admin required)
Write-Log "`nTest 1: Local Memory-Mapped File" "INFO"
try {
    $localName = "RawrXD_Diag_$(Get-Random)"
    $mmf = [System.IO.MemoryMappedFiles.MemoryMappedFile]::CreateNew($localName, 65536)
    $accessor = $mmf.CreateViewAccessor()
    
    # Measure write latency
    $writeLatencies = @()
    $readLatencies = @()
    
    for ($i = 0; $i -lt 1000; $i++) {
        $data = New-Object byte[] 64
        [System.Buffer]::BlockCopy([BitConverter]::GetBytes($i), 0, $data, 0, 4)
        
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $accessor.WriteArray(($i % 1024) * 64, $data, 0, 64)
        $sw.Stop()
        $writeLatencies += $sw.Elapsed.TotalMicroseconds
        
        $sw.Restart()
        $readData = New-Object byte[] 64
        $accessor.ReadArray(($i % 1024) * 64, $readData, 0, 64)
        $sw.Stop()
        $readLatencies += $sw.Elapsed.TotalMicroseconds
    }
    
    $accessor.Dispose()
    $mmf.Dispose()
    
    $avgWrite = ($writeLatencies | Measure-Object -Average).Average
    $avgRead = ($readLatencies | Measure-Object -Average).Average
    $maxWrite = ($writeLatencies | Measure-Object -Maximum).Maximum
    $maxRead = ($readLatencies | Measure-Object -Maximum).Maximum
    
    Write-Log "Memory-mapped file R/W: PASS" "PASS"
    Write-Log "  Write latency: avg=$([math]::Round($avgWrite, 2))μs, max=$([math]::Round($maxWrite, 2))μs" "DATA"
    Write-Log "  Read latency: avg=$([math]::Round($avgRead, 2))μs, max=$([math]::Round($maxRead, 2))μs" "DATA"
    
    if ($maxWrite -gt 1000) {
        Write-Log "  ⚠️  WARNING: Write latency spike detected (>1ms)" "WARN"
    }
} catch {
    Write-Log "Memory-mapped file test failed: $_" "FAIL"
}

# Test 2: Event Loop Latency Distribution
Write-Log "`nTest 2: Event Loop Latency Distribution" "INFO"
Write-Log "Collecting latency samples at $TargetTPS TPS..." "INFO"

$latencies = @()
$events = 0
$start = Get-Date
$targetInterval = 1000 / $TargetTPS

while (((Get-Date) - $start).TotalSeconds -lt $TestDurationSeconds) {
    $loopStart = Get-Date
    
    # Simulate event
    $events++
    
    # Calculate processing time
    $processingTime = ((Get-Date) - $loopStart).TotalMilliseconds
    $latencies += $processingTime
    
    # Adaptive delay
    $sleepTime = $targetInterval - $processingTime
    if ($sleepTime -gt 0) {
        Start-Sleep -Milliseconds $sleepTime
    }
}

$actualDuration = ((Get-Date) - $start).TotalSeconds
$actualTPS = $events / $actualDuration

# Calculate latency statistics
$sortedLatencies = $latencies | Sort-Object
$p50 = $sortedLatencies[[math]::Floor($sortedLatencies.Count * 0.50)]
$p90 = $sortedLatencies[[math]::Floor($sortedLatencies.Count * 0.90)]
$p99 = $sortedLatencies[[math]::Floor($sortedLatencies.Count * 0.99)]
$avgLatency = ($latencies | Measure-Object -Average).Average
$maxLatency = ($latencies | Measure-Object -Maximum).Maximum

Write-Log "Latency Distribution:" "DATA"
Write-Log "  P50: $([math]::Round($p50, 3)) ms" "DATA"
Write-Log "  P90: $([math]::Round($p90, 3)) ms" "DATA"
Write-Log "  P99: $([math]::Round($p99, 3)) ms" "DATA"
Write-Log "  Avg: $([math]::Round($avgLatency, 3)) ms" "DATA"
Write-Log "  Max: $([math]::Round($maxLatency, 3)) ms" "DATA"
Write-Log "  Events: $events in $([math]::Round($actualDuration, 1))s ($([math]::Round($actualTPS, 1)) TPS)" "DATA"

# Test 3: Thread Pool Analysis
Write-Log "`nTest 3: Thread Pool Analysis" "INFO"
$proc = Get-Process -Id $PID
$threadCount = $proc.Threads.Count
$handleCount = $proc.HandleCount
Write-Log "Current process threads: $threadCount" "DATA"
Write-Log "Current process handles: $handleCount" "DATA"

# Check for thread pool limits
$threadPoolThreads = [System.Threading.ThreadPool]::GetAvailableThreads([ref]0, [ref]0)
$maxThreads = [System.Threading.ThreadPool]::GetMaxThreads([ref]0, [ref]0)
Write-Log "Thread pool max: $maxThreads" "DATA"

# Test 4: CPU Affinity Check
Write-Log "`nTest 4: Processor Affinity" "INFO"
$processorCount = [Environment]::ProcessorCount
Write-Log "Logical processors: $processorCount" "DATA"

$affinity = $proc.ProcessorAffinity
Write-Log "Process affinity mask: $affinity" "DATA"

# Diagnosis
Write-Log "`n================================================" "INFO"
Write-Host "Diagnostic Analysis" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

# Check for 64-limit pattern
if ($actualTPS -ge 60 -and $actualTPS -le 68) {
    Write-Log "⚠️  DETECTED: 64-limit pattern (actual: $([math]::Round($actualTPS, 1)) TPS)" "WARN"
    Write-Log "  Possible causes:" "WARN"
    Write-Log "    1. Thread pool capped at 64 threads" "WARN"
    Write-Log "    2. Batch size of 64 with serialization" "WARN"
    Write-Log "    3. Lock contention on 64-byte cache line" "WARN"
}

# Check latency spikes
if ($p99 -gt 100) {
    Write-Log "⚠️  DETECTED: High P99 latency ($([math]::Round($p99, 2)) ms)" "WARN"
    Write-Log "  Indicates blocking operations or GC pauses" "WARN"
}

# Check throughput vs target
$variance = [math]::Abs($actualTPS - $TargetTPS) / $TargetTPS * 100
if ($variance -gt 30) {
    Write-Log "⚠️  DETECTED: Throughput variance ${variance}% from target" "WARN"
    Write-Log "  Target: $TargetTPS TPS, Actual: $([math]::Round($actualTPS, 1)) TPS" "WARN"
}

Write-Log "`nRecommendations:" "INFO"
if ($actualTPS -lt 100 -and $TargetTPS -ge 100) {
    Write-Log "1. Check for thread pool limits in telemetry code" "INFO"
    Write-Log "2. Verify spinlock isn't causing excessive contention" "INFO"
    Write-Log "3. Consider using lock-free ring buffer (SPSC queue)" "INFO"
}

Write-Log "`nLog file: $TestLog" "INFO"
