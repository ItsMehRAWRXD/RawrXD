# W8 Long-Duration Stability Certification Gate
# 30-minute idle stability test with warm-up launch to absorb D-W7-001
#
# Pass criteria:
#   - Process stays alive for 30 minutes (1800 seconds)
#   - No memory spike > 256MB above baseline
#   - No crash / unexpected exit
#   - 0 lingering processes after kill
#
# Usage: pwsh -File w8_long_duration_stability_gate.ps1

param(
    [string]$Exe = "F:\~dev\rawrxd\build_w1\bin\Release\RawrXD-Win32IDE.exe"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Exe)) {
    Write-Output "ERROR: Exe not found: $Exe"
    exit 1
}

$sampleCsv = "F:\~dev\_w8_long_duration_samples.csv"
$receipt   = "F:\~dev\_w8_long_duration_receipt.txt"
$modules   = "F:\~dev\_w8_modules_at_spike.txt"
$threads   = "F:\~dev\_w8_threads_at_spike.txt"

Remove-Item $sampleCsv,$receipt,$modules,$threads -ErrorAction SilentlyContinue

Get-Process RawrXD-Win32IDE,MSBuild,cl,link -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue

Start-Sleep 2

Write-Output "=== W8 warm-up launch to absorb D_W7_001 ==="

$warm = Start-Process -FilePath $Exe -PassThru
Start-Sleep 15

if (-not $warm.HasExited) {
    Stop-Process -Id $warm.Id -Force
    "WARMUP_RESULT=KILLED_AFTER_15S" | Tee-Object -FilePath $receipt
} else {
    "WARMUP_RESULT=EXIT_$($warm.ExitCode)" | Tee-Object -FilePath $receipt
}

Start-Sleep 3

Write-Output "=== W8 measured 30-minute run ==="

$p = Start-Process -FilePath $Exe -PassThru
$procId = $p.Id

"t_sec,ws_mb,private_mb,handles,threads,cpu_sec" |
  Out-File $sampleCsv -Encoding UTF8

$baselineWs = $null
$maxWs = 0
$maxPrivate = 0
$maxHandles = 0
$maxThreads = 0
$spikeDetected = $false
$exitTime = ""
$exitCode = ""

for ($i = 0; $i -le 1800; $i++) {
    Start-Sleep -Seconds 1

    $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue

    if (-not $proc) {
        $exitTime = $i
        $exitCode = "PROCESS_GONE"
        break
    }

    $ws = [math]::Round($proc.WorkingSet64 / 1MB, 1)
    $pm = [math]::Round($proc.PrivateMemorySize64 / 1MB, 1)
    $cpu = [math]::Round($proc.CPU, 2)
    $handles = $proc.HandleCount
    $threads = $proc.Threads.Count

    if ($i -eq 10) {
        $baselineWs = $ws
    }

    if ($ws -gt $maxWs) { $maxWs = $ws }
    if ($pm -gt $maxPrivate) { $maxPrivate = $pm }
    if ($handles -gt $maxHandles) { $maxHandles = $handles }
    if ($threads -gt $maxThreads) { $maxThreads = $threads }

    "$i,$ws,$pm,$handles,$threads,$cpu" |
      Out-File $sampleCsv -Append -Encoding UTF8

    if ($baselineWs -and -not $spikeDetected -and $ws -gt ($baselineWs + 256)) {
        $spikeDetected = $true

        "SPIKE_DETECTED_AT_SEC=$i" |
          Tee-Object -FilePath "F:\~dev\_w8_spike_marker.txt"

        Get-Process -Id $procId -Module -ErrorAction SilentlyContinue |
          Select-Object ModuleName,FileName,ModuleMemorySize |
          Sort-Object ModuleMemorySize -Descending |
          Format-Table -AutoSize |
          Out-String -Width 240 |
          Out-File $modules -Encoding UTF8

        $proc.Threads |
          Select-Object Id,ThreadState,WaitReason,StartTime,TotalProcessorTime |
          Format-Table -AutoSize |
          Out-String -Width 240 |
          Out-File $threads -Encoding UTF8
    }
}

$stillAlive = [bool](Get-Process -Id $procId -ErrorAction SilentlyContinue)

if ($stillAlive) {
    Stop-Process -Id $procId -Force
    $exitCode = "KILLED_AFTER_SUCCESS_WINDOW"
}

$linger = (Get-Process RawrXD-Win32IDE -ErrorAction SilentlyContinue | Measure-Object).Count

$verdict = "FAIL"
if ($stillAlive -and -not $spikeDetected -and $linger -eq 0) {
    $verdict = "PASS"
}

@"
GATE=W8_LONG_DURATION_STABILITY_001
DATE=2026-09-29
EXE=$Exe
DURATION_TARGET_SEC=1800
WARMUP_USED=1
KNOWN_DEFECT_ABSORBED=D_W7_001_FIRST_LAUNCH_0xCFFFFFFF
BASELINE_WORKING_SET_MB=$baselineWs
MAX_WORKING_SET_MB=$maxWs
MAX_PRIVATE_MB=$maxPrivate
MAX_HANDLES=$maxHandles
MAX_THREADS=$maxThreads
SPIKE_DETECTED=$spikeDetected
EXIT_TIME_SEC=$exitTime
EXIT_CODE=$exitCode
LINGERING_PROCESSES=$linger
MODULE_SNAPSHOT=$modules
THREAD_SNAPSHOT=$threads
SAMPLES=$sampleCsv
VERDICT=$verdict
"@ | Set-Content $receipt -Encoding UTF8

Get-Content $receipt