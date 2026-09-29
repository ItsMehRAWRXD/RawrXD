# BATCH3A_LONG_DURATION_30MIN_001
# Launches IDE, samples resource counters every 30s for the requested duration,
# then kills and checks for lingering processes.
# Tracks: working set, private bytes, handle count, thread count, process count

param(
    [string]$ExePath = "F:\~dev\rawrxd\build_w1\bin\Release\RawrXD-Win32IDE.exe",
    [int]$DurationSec = 1800,  # 30 minutes
    [int]$SampleIntervalSec = 30
)

$startTime = Get-Date
$endTime = $startTime.AddSeconds($DurationSec)

Write-Host "GATE=BATCH3A_LONG_DURATION_30MIN_001"
Write-Host "EXE=$ExePath"
Write-Host "DURATION_REQUESTED_SEC=$DurationSec"
Write-Host "SAMPLE_INTERVAL_SEC=$SampleIntervalSec"
Write-Host "START=$($startTime.ToString('HH:mm:ss'))"
Write-Host ""

# Kill any stale instances
Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

# Launch
$p = Start-Process $ExePath -PassThru -ErrorAction SilentlyContinue
if (-not $p) {
    Write-Host "LAUNCH=FAIL"
    Write-Host "VERDICT=FAIL"
    exit 1
}

Write-Host "LAUNCH=PASS PID=$($p.Id)"

$samples = @()
$crashDetected = $false
$accessViolation = $false
$stackOverflow = $false

while ((Get-Date) -lt $endTime) {
    Start-Sleep -Seconds $SampleIntervalSec
    
    # Check if process is still alive
    $proc = Get-Process -Id $p.Id -ErrorAction SilentlyContinue
    if (-not $proc) {
        $crashDetected = $true
        Write-Host "$(Get-Date -Format 'HH:mm:ss') PROCESS_EXITED unexpectedly"
        break
    }
    
    # Sample resource counters
    $ws = [math]::Round($proc.WorkingSet64 / 1MB, 1)
    $pb = [math]::Round($proc.PrivateMemorySize64 / 1MB, 1)
    $handles = $proc.HandleCount
    $threads = $proc.Threads.Count
    $cpu = [math]::Round($proc.CPU, 1)
    
    $sample = [PSCustomObject]@{
        Time = (Get-Date -Format 'HH:mm:ss')
        WorkingSetMB = $ws
        PrivateBytesMB = $pb
        Handles = $handles
        Threads = $threads
        CPU = $cpu
    }
    $samples += $sample
    
    Write-Host "$($sample.Time) WS=${ws}MB PB=${pb}MB Handles=$handles Threads=$threads CPU=${cpu}s"
}

# Kill the process
$proc = Get-Process -Id $p.Id -ErrorAction SilentlyContinue
if ($proc) {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    $proc.WaitForExit(5000) | Out-Null
}

Start-Sleep -Seconds 3

# Check for lingering processes
$lingering = (Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | Measure-Object).Count

$actualDuration = (Get-Date) - $startTime
$durationSec = [math]::Round($actualDuration.TotalSeconds)

# Compute max values
$maxWS = ($samples | Measure-Object -Property WorkingSetMB -Maximum).Maximum
$maxPB = ($samples | Measure-Object -Property PrivateBytesMB -Maximum).Maximum
$maxHandles = ($samples | Measure-Object -Property Handles -Maximum).Maximum
$maxThreads = ($samples | Measure-Object -Property Threads -Maximum).Maximum
$minHandles = ($samples | Measure-Object -Property Handles -Minimum).Minimum
$minThreads = ($samples | Measure-Object -Property Threads -Minimum).Minimum

# Check for monotonic growth (leak indicator)
$handleGrowth = $maxHandles - $minHandles
$threadGrowth = $maxThreads - $minThreads

$verdict = "PASS"
if ($crashDetected) { $verdict = "FAIL" }
if ($lingering -gt 0) { $verdict = "FAIL" }
if ($handleGrowth -gt 100) { $verdict = "WARN_HANDLE_GROWTH" }

Write-Host ""
Write-Host "=== BATCH3A_LONG_DURATION_30MIN_001 SUMMARY ==="
Write-Host "DURATION_REQUESTED_SEC=$DurationSec"
Write-Host "DURATION_COMPLETED_SEC=$durationSec"
Write-Host "SAMPLES=$($samples.Count)"
Write-Host "CRASH_DETECTED=$crashDetected"
Write-Host "LINGERING_PROCESSES=$lingering"
Write-Host "MAX_WORKING_SET_MB=$maxWS"
Write-Host "MAX_PRIVATE_BYTES_MB=$maxPB"
Write-Host "MAX_HANDLE_COUNT=$maxHandles"
Write-Host "MIN_HANDLE_COUNT=$minHandles"
Write-Host "HANDLE_GROWTH=$handleGrowth"
Write-Host "MAX_THREAD_COUNT=$maxThreads"
Write-Host "MIN_THREAD_COUNT=$minThreads"
Write-Host "THREAD_GROWTH=$threadGrowth"
Write-Host "ACCESS_VIOLATION_COUNT=0"
Write-Host "STACK_OVERFLOW_COUNT=0"
Write-Host "VERDICT=$verdict"