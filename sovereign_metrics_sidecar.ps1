# ==============================================================================
# Sovereign Observability Sidecar
# Samples CMD_GET_METRICS at high frequency and writes ring telemetry to CSV.
# ==============================================================================
param(
    [int]$DurationSec = 60,
    [int]$IntervalMs = 25,
    [int]$ResponseTimeoutMs = 2000,
    [int]$FlushEvery = 128,
    [int]$HighFillThreshold = 48,
    [switch]$IncludeSlotMetadata = $true,
    [string]$StopSignalPath = "",
    [string]$CsvPath = "d:\rawrxd-ci-bootstrap\sovereign_metrics_sidecar.csv"
)

$ErrorActionPreference = "Stop"

if ($IntervalMs -lt 5) {
    throw "IntervalMs must be >= 5"
}
if ($FlushEvery -lt 1) {
    throw "FlushEvery must be >= 1"
}

Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class NativeMethods {
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenEventA(uint dwDesiredAccess, bool bInheritHandle, string lpName);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenFileMappingA(uint dwDesiredAccess, bool bInheritHandle, string lpName);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject, uint dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, UIntPtr dwNumberOfBytesToMap);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool SetEvent(IntPtr hEvent);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    public const uint EVENT_MODIFY_STATE = 0x0002;
    public const uint SYNCHRONIZE = 0x00100000;
    public const uint FILE_MAP_ALL_ACCESS = 0xF001F;
    public const uint WAIT_OBJECT_0 = 0;
}
"@

$OFF_STATE        = 0x00
$OFF_CMD_TYPE     = 0x08
$OFF_PAYLOAD_LEN  = 0x0C
$OFF_RESP_STATUS  = 0x10
$OFF_RESP_LEN     = 0x14
$OFF_CMD_PAYLOAD  = 0x18
$OFF_RESP_PAYLOAD = 0x1018
$OFF_MAGIC_COOKIE = 0xFFF0

$BEACON_READY     = 0x01
$CMD_GET_METRICS  = 0x7000
$RESP_OK          = 0
$MAGIC_COOKIE     = [Convert]::ToUInt64("CAFEBABEDEADBEEF", 16)

# Payload layout from HandleTelemetry (len=104)
$METRICS_LEN_MIN  = 104
$P_MODEL_STATE    = 0
$P_LAST_LOAD_RES  = 4
$P_LAST_LOAD_WIN  = 8
$P_LAST_LOAD_MS   = 12
$P_HEARTBEAT      = 16
$P_RING_HEAD      = 24
$P_RING_TAIL      = 32
$P_FILL_LEVEL     = 40
$P_RING_CAP       = 44
$P_BACKPRESSURE   = 48
$P_DROPPED        = 56
$P_LAST_CMD_ID    = 64
$P_LAST_STATUS    = 68
$P_LAST_PLEN      = 72
$P_LAST_FLAGS     = 76
$P_LAST_TS        = 80
$P_LAST_PAYLOAD0  = 88
$P_LAST_PAYLOAD1  = 96
$P_UTIL_PCT       = 100

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

function Write-U32([IntPtr]$base, [int]$off, [uint32]$value) {
    $buf = [BitConverter]::GetBytes($value)
    [Runtime.InteropServices.Marshal]::Copy($buf, 0, [IntPtr]::Add($base, $off), 4)
}

function Wait-OrchestratorReady([IntPtr]$base, [int]$timeoutMs) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $timeoutMs) {
        if ((Read-U64 $base $OFF_MAGIC_COOKIE) -eq $MAGIC_COOKIE) {
            return $true
        }
        Start-Sleep -Milliseconds 25
    }
    return $false
}

function Send-Command([IntPtr]$base, [IntPtr]$hCmd, [IntPtr]$hResp, [uint32]$cmd, [int]$timeoutMs) {
    Write-U32 $base $OFF_CMD_TYPE $cmd
    Write-U32 $base $OFF_PAYLOAD_LEN 0
    Write-U32 $base $OFF_STATE $BEACON_READY

    [void][NativeMethods]::SetEvent($hCmd)
    $wait = [NativeMethods]::WaitForSingleObject($hResp, [uint32]$timeoutMs)
    if ($wait -ne [NativeMethods]::WAIT_OBJECT_0) {
        return @{ Success = $false; Error = "RESP_TIMEOUT" }
    }

    return @{
        Success = $true
        Status  = (Read-U32 $base $OFF_RESP_STATUS)
        Len     = (Read-U32 $base $OFF_RESP_LEN)
    }
}

function Read-Metrics([IntPtr]$base) {
    [PSCustomObject]@{
        ModelState        = [uint32](Read-U32 $base ($OFF_RESP_PAYLOAD + $P_MODEL_STATE))
        LastLoadResult    = [uint32](Read-U32 $base ($OFF_RESP_PAYLOAD + $P_LAST_LOAD_RES))
        LastLoadWin32     = [uint32](Read-U32 $base ($OFF_RESP_PAYLOAD + $P_LAST_LOAD_WIN))
        LastLoadDurationMs= [uint32](Read-U32 $base ($OFF_RESP_PAYLOAD + $P_LAST_LOAD_MS))
        Heartbeat         = [uint64](Read-U64 $base ($OFF_RESP_PAYLOAD + $P_HEARTBEAT))
        RingHead          = [uint64](Read-U64 $base ($OFF_RESP_PAYLOAD + $P_RING_HEAD))
        RingTail          = [uint64](Read-U64 $base ($OFF_RESP_PAYLOAD + $P_RING_TAIL))
        FillLevel         = [uint32](Read-U32 $base ($OFF_RESP_PAYLOAD + $P_FILL_LEVEL))
        RingCapacity      = [uint32](Read-U32 $base ($OFF_RESP_PAYLOAD + $P_RING_CAP))
        RingBackpressure  = [uint64](Read-U64 $base ($OFF_RESP_PAYLOAD + $P_BACKPRESSURE))
        RingDropped       = [uint64](Read-U64 $base ($OFF_RESP_PAYLOAD + $P_DROPPED))
        LastCmdId         = [uint32](Read-U32 $base ($OFF_RESP_PAYLOAD + $P_LAST_CMD_ID))
        LastStatus        = [uint32](Read-U32 $base ($OFF_RESP_PAYLOAD + $P_LAST_STATUS))
        LastPayloadLen    = [uint32](Read-U32 $base ($OFF_RESP_PAYLOAD + $P_LAST_PLEN))
        LastFlags         = [uint32](Read-U32 $base ($OFF_RESP_PAYLOAD + $P_LAST_FLAGS))
        LastTimestampQpc  = [uint64](Read-U64 $base ($OFF_RESP_PAYLOAD + $P_LAST_TS))
        LastPayload0      = [uint64](Read-U64 $base ($OFF_RESP_PAYLOAD + $P_LAST_PAYLOAD0))
        LastPayload1      = [uint32](Read-U32 $base ($OFF_RESP_PAYLOAD + $P_LAST_PAYLOAD1))
        UtilizationPct    = [uint32](Read-U32 $base ($OFF_RESP_PAYLOAD + $P_UTIL_PCT))
    }
}

function Get-PearsonCorrelation([double[]]$x, [double[]]$y) {
    if ($x.Length -ne $y.Length -or $x.Length -lt 2) {
        return [double]::NaN
    }

    $n = $x.Length
    $sumX = 0.0; $sumY = 0.0; $sumXY = 0.0; $sumX2 = 0.0; $sumY2 = 0.0

    for ($i = 0; $i -lt $n; $i++) {
        $xi = $x[$i]
        $yi = $y[$i]
        $sumX += $xi
        $sumY += $yi
        $sumXY += ($xi * $yi)
        $sumX2 += ($xi * $xi)
        $sumY2 += ($yi * $yi)
    }

    $num = ($n * $sumXY) - ($sumX * $sumY)
    $denX = ($n * $sumX2) - ($sumX * $sumX)
    $denY = ($n * $sumY2) - ($sumY * $sumY)

    if ($denX -le 0 -or $denY -le 0) {
        return [double]::NaN
    }

    return ($num / [Math]::Sqrt($denX * $denY))
}

$hMap = [IntPtr]::Zero
$pMap = [IntPtr]::Zero
$hCmd = [IntPtr]::Zero
$hResp = [IntPtr]::Zero

function Cleanup-All {
    if ($hResp -ne [IntPtr]::Zero) { [void][NativeMethods]::CloseHandle($hResp) }
    if ($hCmd -ne [IntPtr]::Zero)  { [void][NativeMethods]::CloseHandle($hCmd) }
    if ($pMap -ne [IntPtr]::Zero)  { [void][NativeMethods]::UnmapViewOfFile($pMap) }
    if ($hMap -ne [IntPtr]::Zero)  { [void][NativeMethods]::CloseHandle($hMap) }
}

try {
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "Sovereign Observability Sidecar" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "DurationSec=$DurationSec IntervalMs=$IntervalMs CsvPath=$CsvPath"

    $hMap = [NativeMethods]::OpenFileMappingA([NativeMethods]::FILE_MAP_ALL_ACCESS, $false, "SOVEREIGN_BEACON_V1")
    if ($hMap -eq [IntPtr]::Zero) {
        throw "OpenFileMapping failed. Start SovereignOrchestrator.exe first."
    }

    $pMap = [NativeMethods]::MapViewOfFile($hMap, [NativeMethods]::FILE_MAP_ALL_ACCESS, 0, 0, [UIntPtr]::new(65536))
    if ($pMap -eq [IntPtr]::Zero) {
        throw "MapViewOfFile failed"
    }

    if (-not (Wait-OrchestratorReady $pMap 5000)) {
        throw "Magic cookie timeout"
    }

    $access = [NativeMethods]::EVENT_MODIFY_STATE -bor [NativeMethods]::SYNCHRONIZE
    $hCmd = [NativeMethods]::OpenEventA($access, $false, "SOVEREIGN_CMD_EVENT")
    $hResp = [NativeMethods]::OpenEventA($access, $false, "SOVEREIGN_RESP_EVENT")
    if ($hCmd -eq [IntPtr]::Zero -or $hResp -eq [IntPtr]::Zero) {
        throw "OpenEvent failed"
    }

    if (Test-Path $CsvPath) {
        Remove-Item $CsvPath -Force
    }

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
        if (-not [string]::IsNullOrWhiteSpace($StopSignalPath) -and (Test-Path $StopSignalPath)) {
            break
        }

        $resp = Send-Command $pMap $hCmd $hResp $CMD_GET_METRICS $ResponseTimeoutMs
        if (-not $resp.Success) {
            $timeoutCount++
            Start-Sleep -Milliseconds $IntervalMs
            continue
        }

        if ([uint32]$resp.Status -ne $RESP_OK) {
            $statusErrorCount++
            Start-Sleep -Milliseconds $IntervalMs
            continue
        }

        if ([uint32]$resp.Len -lt $METRICS_LEN_MIN) {
            $lenErrorCount++
            Start-Sleep -Milliseconds $IntervalMs
            continue
        }

        $m = Read-Metrics $pMap

        $backpressureDelta = 0
        if ($prevBackpressure -ne $null) {
            $backpressureDelta = [int64]$m.RingBackpressure - [int64]$prevBackpressure
        }

        $droppedDelta = 0
        if ($prevDropped -ne $null) {
            $droppedDelta = [int64]$m.RingDropped - [int64]$prevDropped
        }

        $prevBackpressure = $m.RingBackpressure
        $prevDropped = $m.RingDropped

        $calcFill = [int64](($m.RingTail - $m.RingHead) -band 63)
        if ($m.FillLevel -gt $maxFill) {
            $maxFill = $m.FillLevel
        }

        $isHighFill = ($m.FillLevel -ge $HighFillThreshold)
        if ($isHighFill) {
            $highFillCount++
        }

        $isBpEvent = ($backpressureDelta -gt 0)
        if ($isBpEvent) {
            $bpEventCount++
        }

        $fillSamples.Add([double]$m.FillLevel)
        $bpDeltaSamples.Add([double][Math]::Max(0, $backpressureDelta))

        $row = [PSCustomObject]@{
            sample_idx               = $sampleIdx
            utc                      = [DateTime]::UtcNow.ToString("o")
            elapsed_ms               = [int64]$sw.ElapsedMilliseconds
            model_state              = $m.ModelState
            heartbeat                = $m.Heartbeat
            ring_head                = $m.RingHead
            ring_tail                = $m.RingTail
            fill_level               = $m.FillLevel
            fill_level_calc          = $calcFill
            ring_capacity            = $m.RingCapacity
            utilization_pct          = $m.UtilizationPct
            ring_backpressure        = $m.RingBackpressure
            ring_backpressure_delta  = $backpressureDelta
            ring_dropped             = $m.RingDropped
            ring_dropped_delta       = $droppedDelta
            high_fill                = [int]$isHighFill
            bp_event                 = [int]$isBpEvent
            last_load_result         = $m.LastLoadResult
            last_load_win32          = $m.LastLoadWin32
            last_load_duration_ms    = $m.LastLoadDurationMs
        }

        if ($IncludeSlotMetadata) {
            $row | Add-Member -NotePropertyName last_cmd_id -NotePropertyValue $m.LastCmdId
            $row | Add-Member -NotePropertyName last_status -NotePropertyValue $m.LastStatus
            $row | Add-Member -NotePropertyName last_payload_len -NotePropertyValue $m.LastPayloadLen
            $row | Add-Member -NotePropertyName last_flags -NotePropertyValue $m.LastFlags
            $row | Add-Member -NotePropertyName last_timestamp_qpc -NotePropertyValue $m.LastTimestampQpc
            $row | Add-Member -NotePropertyName last_payload0 -NotePropertyValue $m.LastPayload0
            $row | Add-Member -NotePropertyName last_payload1 -NotePropertyValue $m.LastPayload1
        }

        $rows.Add($row)
        $sampleIdx++

        if ($rows.Count -ge $FlushEvery) {
            $rows | Export-Csv -Path $CsvPath -NoTypeInformation -Append:([bool](Test-Path $CsvPath))
            $rows.Clear()
        }

        $nextDueMs += $IntervalMs
        $remain = $nextDueMs - $sw.ElapsedMilliseconds
        if ($remain -gt 0) {
            Start-Sleep -Milliseconds $remain
        }
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
    if ([double]::IsNaN($corr)) {
        Write-Host "FillVsBackpressureDeltaCorrelation: n/a"
    } else {
        Write-Host ("FillVsBackpressureDeltaCorrelation: {0}" -f ([Math]::Round($corr, 4)))
    }
    Write-Host "CSV: $CsvPath"

    Cleanup-All
    exit 0
}
catch {
    Write-Host "`n[SIDEcar] FAILED" -ForegroundColor Red
    Write-Host ("Reason: {0}" -f $_.Exception.Message) -ForegroundColor Red
    Cleanup-All
    exit 1
}
