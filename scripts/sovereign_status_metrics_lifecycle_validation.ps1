$ErrorActionPreference = 'Stop'

$CMD_STATUS = 0x1002
$CMD_LOAD_MODEL = 0x2000
$CMD_UNLOAD_MODEL = 0x2001
$CMD_METRICS = 0x7000

function Invoke-Cmd {
    param(
        [int]$Id,
        [int]$Type,
        [string]$Payload = '',
        [int]$TimeoutMs = 10000
    )

    $mmf = [System.IO.MemoryMappedFiles.MemoryMappedFile]::OpenExisting('SOVEREIGN_BEACON_V1')
    $cmd = [System.Threading.EventWaitHandle]::OpenExisting('SOVEREIGN_CMD_EVENT')
    $resp = [System.Threading.EventWaitHandle]::OpenExisting('SOVEREIGN_RESP_EVENT')
    $acc = $mmf.CreateViewAccessor()

    try {
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($Payload)
        $acc.Write(0,[byte]1)
        $acc.Write(4,$Id)
        $acc.Write(8,$Type)
        $acc.Write(12,[int]$bytes.Length)
        if ($bytes.Length -gt 0) {
            [void]$acc.WriteArray(0x18,$bytes,0,$bytes.Length)
        }
        $acc.Write(0x18 + $bytes.Length,[byte]0)

        [void]$cmd.Set()
        if (-not $resp.WaitOne($TimeoutMs)) {
            throw "Timeout waiting for response: cmd=0x$('{0:X}' -f $Id)"
        }

        $status = $acc.ReadInt32(0x10)
        $len = $acc.ReadInt32(0x14)
        $heartbeat = $acc.ReadInt64(0xFFF8)
        $out = New-Object byte[] ([Math]::Max($len,0))
        if ($len -gt 0) {
            [void]$acc.ReadArray(0x1018,$out,0,$len)
        }

        [pscustomobject]@{
            Cmd = ('0x{0:X}' -f $Id)
            RespStatus = $status
            RespLen = $len
            Heartbeat = $heartbeat
            Payload = [System.Text.Encoding]::ASCII.GetString($out)
        }
    }
    finally {
        $acc.Dispose()
        $mmf.Dispose()
        $cmd.Dispose()
        $resp.Dispose()
    }
}

function Wait-ReadyState {
    param([int]$MaxSeconds = 20)

    $deadline = (Get-Date).AddSeconds($MaxSeconds)
    while ((Get-Date) -lt $deadline) {
        $s = Invoke-Cmd -Id $CMD_STATUS -Type $CMD_STATUS
        if ($s.Payload -match '"state":"READY"') {
            return $s
        }
        Start-Sleep -Milliseconds 250
    }

    throw 'Timed out waiting for READY state'
}

function Ensure-StatusOk {
    param([string]$Name,[object]$Resp)

    if ($Resp.RespStatus -ne 0) {
        throw "$Name expected status=0 but got $($Resp.RespStatus), payload=$($Resp.Payload)"
    }
}

$model = 'D:\TinyLlama-1.1B-Chat-v1.0.Q4_0.gguf'

Write-Host '=== STATUS baseline ==='
$st0 = Invoke-Cmd -Id $CMD_STATUS -Type $CMD_STATUS
Ensure-StatusOk -Name 'STATUS baseline' -Resp $st0
Write-Host $st0.Payload

if ($st0.Payload -match '"state":"READY"' -or $st0.Payload -match '"state":"INFERENCE_ACTIVE"') {
    Write-Host '=== Pre-clean UNLOAD for deterministic baseline ==='
    $preUnload = Invoke-Cmd -Id $CMD_UNLOAD_MODEL -Type $CMD_UNLOAD_MODEL
    if ($preUnload.RespStatus -ne 0 -and $preUnload.RespStatus -ne 6) {
        throw "Pre-clean UNLOAD unexpected status=$($preUnload.RespStatus)"
    }
}

Write-Host '=== LOAD_MODEL ==='
$load = Invoke-Cmd -Id $CMD_LOAD_MODEL -Type $CMD_LOAD_MODEL -Payload $model
Ensure-StatusOk -Name 'LOAD_MODEL' -Resp $load
if ($load.Payload -notmatch '"status":"ready"') {
    throw "LOAD_MODEL expected ready payload, got: $($load.Payload)"
}
Write-Host $load.Payload

Write-Host '=== WAIT READY ==='
$stReady = Wait-ReadyState -MaxSeconds 20
Ensure-StatusOk -Name 'STATUS ready' -Resp $stReady
Write-Host $stReady.Payload

Write-Host '=== METRICS ==='
$metrics = Invoke-Cmd -Id $CMD_METRICS -Type $CMD_METRICS
Ensure-StatusOk -Name 'METRICS' -Resp $metrics
if ($metrics.RespLen -lt 24) {
    throw "METRICS expected 24-byte telemetry payload, got len=$($metrics.RespLen)"
}

$bytes = [System.Text.Encoding]::ASCII.GetBytes($metrics.Payload)
if ($metrics.Payload.StartsWith('{')) {
    Write-Host $metrics.Payload
} else {
    Write-Host "METRICS returned binary payload len=$($metrics.RespLen) (expected for raw protocol)."
}

Write-Host '=== UNLOAD_MODEL ==='
$unload = Invoke-Cmd -Id $CMD_UNLOAD_MODEL -Type $CMD_UNLOAD_MODEL
Ensure-StatusOk -Name 'UNLOAD_MODEL' -Resp $unload
Write-Host $unload.Payload

Write-Host '=== STATUS final ==='
$stFinal = Invoke-Cmd -Id $CMD_STATUS -Type $CMD_STATUS
Ensure-StatusOk -Name 'STATUS final' -Resp $stFinal
Write-Host $stFinal.Payload

if ($stFinal.Payload -notmatch '"state":"UNLOADED"') {
    throw "Final STATUS expected UNLOADED state, got: $($stFinal.Payload)"
}

if ($stFinal.Heartbeat -lt $st0.Heartbeat) {
    throw "Heartbeat regressed from $($st0.Heartbeat) to $($stFinal.Heartbeat)"
}

Write-Host '=== PASS: STATUS/LOAD/READY/METRICS/UNLOAD state+heartbeat coherence validated ==='
