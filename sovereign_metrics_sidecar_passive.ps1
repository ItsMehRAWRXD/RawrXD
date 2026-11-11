# ==============================================================================
# Sovereign Observability Sidecar (Passive MMF Reader)
# Reads published MMF ring metrics directly (no CMD_GET_METRICS traffic).
# ==============================================================================
param(
    [int]$DurationSec = 60,
    [int]$IntervalMs = 25,
    [int]$FlushEvery = 128,
    [int]$HighFillThreshold = 48,
    [switch]$IncludeSlotMetadata = $true,
    [string]$StopSignalPath = "",
    [string]$CsvPath = "d:\rawrxd-ci-bootstrap\sovereign_metrics_sidecar.csv"
)

$ErrorActionPreference = "Stop"

if ($IntervalMs -lt 5) { throw "IntervalMs must be >= 5" }
if ($FlushEvery -lt 1) { throw "FlushEvery must be >= 1" }

Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class NativeMethods {
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenFileMappingA(uint dwDesiredAccess, bool bInheritHandle, string lpName);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject, uint dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, UIntPtr dwNumberOfBytesToMap);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr hObject);
    public const uint FILE_MAP_ALL_ACCESS = 0xF001F;
}
"@

$OFF_MAGIC_COOKIE = 0xFFF0
$OFF_HEARTBEAT    = 0xFFF8
$OFF_MODEL_STATE  = 0x2030
$OFF_RING_HEAD    = 0x2040
$OFF_RING_TAIL    = 0x2048
$OFF_RING_DROPPED = 0x2050
$OFF_RING_BP      = 0x2058
$OFF_FILL_LEVEL   = 0x2060
$OFF_RING_CAP     = 0x2064
$OFF_LAST_CMD_ID  = 0x2068
$OFF_LAST_STATUS  = 0x206C
$OFF_LAST_PLEN    = 0x2070
$OFF_LAST_FLAGS   = 0x2074
$OFF_LAST_TS      = 0x2078
$OFF_LAST_PAYLOAD0= 0x2080
$OFF_LAST_PAYLOAD1= 0x2088

$MAGIC_COOKIE = [Convert]::ToUInt64("CAFEBABEDEADBEEF", 16)

function Read-U32([IntPtr]$base, [int]$off) {
    $buf = New-Object byte[] 4
    [Runtime.InteropServices.Marshal]::Copy([IntPtr]::Add($base, $off), $buf, 0, 4)
    [BitConverter]::ToUInt32($buf, 0)
}

function Read-U64([IntPtr]$base, [int]$off) {
    $buf = New-Object byte[] 8
    [Runtime.InteropServices.Marshal]::Copy([IntPtr]::Add($base, $off), $buf, 0, 8)
    [BitConverter]::ToUInt64($buf, 0)
}

function Wait-OrchestratorReady([IntPtr]$base, [int]$timeoutMs) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $timeoutMs) {
        if ((Read-U64 $base $OFF_MAGIC_COOKIE) -eq $MAGIC_COOKIE) { return $true }
        Start-Sleep -Milliseconds 25
    }
    return $false
}

function Get-PearsonCorrelation([double[]]$x, [double[]]$y) {
    if ($x.Length -ne $y.Length -or $x.Length -lt 2) { return [double]::NaN }
    $n = $x.Length
    $sumX = 0.0; $sumY = 0.0; $sumXY = 0.0; $sumX2 = 0.0; $sumY2 = 0.0
    for ($i = 0; $i -lt $n; $i++) {
        $xi = $x[$i]; $yi = $y[$i]
        $sumX += $xi; $sumY += $yi
        $sumXY += ($xi * $yi)
        $sumX2 += ($xi * $xi)
        $sumY2 += ($yi * $yi)
    }
    $num = ($n * $sumXY) - ($sumX * $sumY)
    $denX = ($n * $sumX2) - ($sumX * $sumX)
    $denY = ($n * $sumY2) - ($sumY * $sumY)
    if ($denX -le 0 -or $denY -le 0) { return [double]::NaN }
    return ($num / [Math]::Sqrt($denX * $denY))
}

$hMap = [IntPtr]::Zero
$pMap = [IntPtr]::Zero
function Cleanup-All {
    if ($pMap -ne [IntPtr]::Zero) { [void][NativeMethods]::UnmapViewOfFile($pMap) }
    if ($hMap -ne [IntPtr]::Zero) { [void][NativeMethods]::CloseHandle($hMap) }
}

try {
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "Sovereign Observability Sidecar (Passive)" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "DurationSec=$DurationSec IntervalMs=$IntervalMs CsvPath=$CsvPath"

    $hMap = [NativeMethods]::OpenFileMappingA([NativeMethods]::FILE_MAP_ALL_ACCESS, $false, "SOVEREIGN_BEACON_V1")
    if ($hMap -eq [IntPtr]::Zero) { throw "OpenFileMapping failed. Start SovereignOrchestrator.exe first." }

    $pMap = [NativeMethods]::MapViewOfFile($hMap, [NativeMethods]::FILE_MAP_ALL_ACCESS, 0, 0, [UIntPtr]::new(65536))
    if ($pMap -eq [IntPtr]::Zero) { throw "MapViewOfFile failed" }

    if (-not (Wait-OrchestratorReady $pMap 5000)) { throw "Magic cookie timeout" }

    if (Test-Path $CsvPath) { Remove-Item $CsvPath -Force }

    $rows = New-Object System.Collections.Generic.List[object]
    $fillSamples = New-Object System.Collections.Generic.List[double]
    $bpDeltaSamples = New-Object System.Collections.Generic.List[double]

    $sampleIdx = 0
    $timeoutCount = 0
    $statusErrorCount = 0
    $lenErrorCount = 0
    $highFillCount = 0
    $bpEventCount = 0

    $prevBackpressure = $null
    $prevDropped = $null
    $maxFill = 0

    $sw = [Diagnostics.Stopwatch]::StartNew()
    $nextDueMs = 0

    while ($sw.Elapsed.TotalSeconds -lt $DurationSec) {
        if (-not [string]::IsNullOrWhiteSpace($StopSignalPath) -and (Test-Path $StopSignalPath)) { break }

        $modelState = [uint32](Read-U32 $pMap $OFF_MODEL_STATE)
        $heartbeat = [uint64](Read-U64 $pMap $OFF_HEARTBEAT)
        $ringHead = [uint64](Read-U64 $pMap $OFF_RING_HEAD)
        $ringTail = [uint64](Read-U64 $pMap $OFF_RING_TAIL)
        $fillLevel = [uint32](Read-U32 $pMap $OFF_FILL_LEVEL)
        $ringCap = [uint32](Read-U32 $pMap $OFF_RING_CAP)
        $ringBackpressure = [uint64](Read-U64 $pMap $OFF_RING_BP)
        $ringDropped = [uint64](Read-U64 $pMap $OFF_RING_DROPPED)

        $lastCmdId = [uint32](Read-U32 $pMap $OFF_LAST_CMD_ID)
        $lastStatus = [uint32](Read-U32 $pMap $OFF_LAST_STATUS)
        $lastPayloadLen = [uint32](Read-U32 $pMap $OFF_LAST_PLEN)
        $lastFlags = [uint32](Read-U32 $pMap $OFF_LAST_FLAGS)
        $lastTs = [uint64](Read-U64 $pMap $OFF_LAST_TS)
        $lastPayload0 = [uint64](Read-U64 $pMap $OFF_LAST_PAYLOAD0)
        $lastPayload1 = [uint32](Read-U32 $pMap $OFF_LAST_PAYLOAD1)

        $backpressureDelta = 0
        if ($prevBackpressure -ne $null) {
            $backpressureDelta = [int64]$ringBackpressure - [int64]$prevBackpressure
        }

        $droppedDelta = 0
        if ($prevDropped -ne $null) {
            $droppedDelta = [int64]$ringDropped - [int64]$prevDropped
        }

        $prevBackpressure = $ringBackpressure
        $prevDropped = $ringDropped

        $calcFill = [int64](($ringTail - $ringHead) -band 63)
        if ($fillLevel -gt $maxFill) { $maxFill = $fillLevel }

        $isHighFill = ($fillLevel -ge $HighFillThreshold)
        if ($isHighFill) { $highFillCount++ }

        $isBpEvent = ($backpressureDelta -gt 0)
        if ($isBpEvent) { $bpEventCount++ }

        $fillSamples.Add([double]$fillLevel)
        $bpDeltaSamples.Add([double][Math]::Max(0, $backpressureDelta))

        $utilPct = if ($ringCap -gt 0) { [uint32]([math]::Floor(($fillLevel * 100.0) / $ringCap)) } else { 0 }

        $row = [PSCustomObject]@{
            sample_idx               = $sampleIdx
            utc                      = [DateTime]::UtcNow.ToString("o")
            elapsed_ms               = [int64]$sw.ElapsedMilliseconds
            model_state              = $modelState
            heartbeat                = $heartbeat
            ring_head                = $ringHead
            ring_tail                = $ringTail
            fill_level               = $fillLevel
            fill_level_calc          = $calcFill
            ring_capacity            = $ringCap
            utilization_pct          = $utilPct
            ring_backpressure        = $ringBackpressure
            ring_backpressure_delta  = $backpressureDelta
            ring_dropped             = $ringDropped
            ring_dropped_delta       = $droppedDelta
            high_fill                = [int]$isHighFill
            bp_event                 = [int]$isBpEvent
            last_load_result         = 0
            last_load_win32          = 0
            last_load_duration_ms    = 0
        }

        if ($IncludeSlotMetadata) {
            $row | Add-Member -NotePropertyName last_cmd_id -NotePropertyValue $lastCmdId
            $row | Add-Member -NotePropertyName last_status -NotePropertyValue $lastStatus
            $row | Add-Member -NotePropertyName last_payload_len -NotePropertyValue $lastPayloadLen
            $row | Add-Member -NotePropertyName last_flags -NotePropertyValue $lastFlags
            $row | Add-Member -NotePropertyName last_timestamp_qpc -NotePropertyValue $lastTs
            $row | Add-Member -NotePropertyName last_payload0 -NotePropertyValue $lastPayload0
            $row | Add-Member -NotePropertyName last_payload1 -NotePropertyValue $lastPayload1
        }

        $rows.Add($row)
        $sampleIdx++

        if ($rows.Count -ge $FlushEvery) {
            $rows | Export-Csv -Path $CsvPath -NoTypeInformation -Append:([bool](Test-Path $CsvPath))
            $rows.Clear()
        }

        $nextDueMs += $IntervalMs
        $remain = $nextDueMs - $sw.ElapsedMilliseconds
        if ($remain -gt 0) { Start-Sleep -Milliseconds $remain }
    }

    if ($rows.Count -gt 0) {
        $rows | Export-Csv -Path $CsvPath -NoTypeInformation -Append:([bool](Test-Path $CsvPath))
        $rows.Clear()
    }

    $corr = Get-PearsonCorrelation ($fillSamples.ToArray()) ($bpDeltaSamples.ToArray())

    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "SIDECAR SUMMARY" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "Samples: $sampleIdx"
    Write-Host "DurationMs: $($sw.ElapsedMilliseconds)"
    Write-Host "MaxFill: $maxFill"
    Write-Host "BackpressureEvents: $bpEventCount"
    Write-Host "HighFillSamples(>=$HighFillThreshold): $highFillCount"
    Write-Host "Timeouts: $timeoutCount StatusErrors: $statusErrorCount LenErrors: $lenErrorCount"
    if ([double]::IsNaN($corr)) { Write-Host "FillVsBackpressureDeltaCorrelation: n/a" }
    else { Write-Host ("FillVsBackpressureDeltaCorrelation: {0}" -f ([Math]::Round($corr, 4))) }
    Write-Host "CSV: $CsvPath"

    Cleanup-All
    exit 0
}
catch {
    Write-Host "`n[SIDECAR] FAILED" -ForegroundColor Red
    Write-Host ("Reason: {0}" -f $_.Exception.Message) -ForegroundColor Red
    Cleanup-All
    exit 1
}
