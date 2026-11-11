$ErrorActionPreference = 'Stop'

$CMD_STATUS        = 0x1002
$CMD_LOAD_MODEL    = 0x2000
$CMD_UNLOAD_MODEL  = 0x2001
$CMD_INFER         = 0x3003
$CMD_CANCEL_INFER  = 0x3005
$CMD_STREAM_STATUS = 0x4004

function Invoke-Cmd {
    param(
        [int]$Id,
        [int]$Type,
        [string]$Payload = '',
        [int]$TimeoutMs = 20000
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
        $out = New-Object byte[] ([Math]::Max($len,0))
        if ($len -gt 0) {
            [void]$acc.ReadArray(0x1018,$out,0,$len)
        }

        [pscustomobject]@{
            Cmd = ('0x{0:X}' -f $Id)
            RespStatus = $status
            RespLen = $len
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

function Assert-Resp {
    param(
        [string]$Name,
        [object]$Resp,
        [int]$ExpectedStatus,
        [string]$PayloadContains = $null
    )

    if ($Resp.RespStatus -ne $ExpectedStatus) {
        throw "$Name expected status $ExpectedStatus but got $($Resp.RespStatus). Payload=$($Resp.Payload)"
    }

    if ($null -ne $PayloadContains -and $Resp.Payload -notmatch [Regex]::Escape($PayloadContains)) {
        throw "$Name expected payload to contain '$PayloadContains' but got '$($Resp.Payload)'"
    }

    Write-Host "[PASS] $Name -> status=$($Resp.RespStatus) payload=$($Resp.Payload)"
}

$model = 'D:\TinyLlama-1.1B-Chat-v1.0.Q4_0.gguf'
$prompt1 = 'a'
$prompt2 = 'b'
$prompt3 = 'c'

Write-Host '=== Baseline status ==='
$baseline = Invoke-Cmd -Id $CMD_STATUS -Type $CMD_STATUS
Write-Host $baseline.Payload

if ($baseline.Payload -match '"state":"READY"' -or $baseline.Payload -match '"state":"INFERENCE_ACTIVE"') {
    Write-Host '=== Pre-clean: forcing UNLOADED baseline ==='
    [void](Invoke-Cmd -Id $CMD_UNLOAD_MODEL -Type $CMD_UNLOAD_MODEL)
    $baseline = Invoke-Cmd -Id $CMD_STATUS -Type $CMD_STATUS
    Write-Host $baseline.Payload
}

Write-Host '=== Sequence A: LOAD -> INFER -> INFER -> INFER -> UNLOAD ==='
$aLoad = Invoke-Cmd -Id $CMD_LOAD_MODEL -Type $CMD_LOAD_MODEL -Payload $model
Assert-Resp -Name 'A/LOAD_MODEL' -Resp $aLoad -ExpectedStatus 0 -PayloadContains 'ready'

$ready = Wait-ReadyState -MaxSeconds 20
Assert-Resp -Name 'A/WAIT_READY' -Resp $ready -ExpectedStatus 0 -PayloadContains '"state":"READY"'

$aInfer1 = Invoke-Cmd -Id $CMD_INFER -Type $CMD_INFER -Payload $prompt1
Assert-Resp -Name 'A/INFER#1' -Resp $aInfer1 -ExpectedStatus 0 -PayloadContains 'inference_complete'

$aInfer2 = Invoke-Cmd -Id $CMD_INFER -Type $CMD_INFER -Payload $prompt2
Assert-Resp -Name 'A/INFER#2' -Resp $aInfer2 -ExpectedStatus 0 -PayloadContains 'inference_complete'

$aInfer3 = Invoke-Cmd -Id $CMD_INFER -Type $CMD_INFER -Payload $prompt3
Assert-Resp -Name 'A/INFER#3' -Resp $aInfer3 -ExpectedStatus 0 -PayloadContains 'inference_complete'

$aUnload = Invoke-Cmd -Id $CMD_UNLOAD_MODEL -Type $CMD_UNLOAD_MODEL
Assert-Resp -Name 'A/UNLOAD' -Resp $aUnload -ExpectedStatus 0 -PayloadContains 'unloaded'

Write-Host '=== Sequence B: LOAD -> INFER -> CANCEL -> INFER -> UNLOAD ==='
$bLoad = Invoke-Cmd -Id $CMD_LOAD_MODEL -Type $CMD_LOAD_MODEL -Payload $model
Assert-Resp -Name 'B/LOAD_MODEL' -Resp $bLoad -ExpectedStatus 0 -PayloadContains 'ready'

$ready2 = Wait-ReadyState -MaxSeconds 20
Assert-Resp -Name 'B/WAIT_READY' -Resp $ready2 -ExpectedStatus 0 -PayloadContains '"state":"READY"'

$bInfer1 = Invoke-Cmd -Id $CMD_INFER -Type $CMD_INFER -Payload 'cancel window prompt'
Assert-Resp -Name 'B/INFER#1' -Resp $bInfer1 -ExpectedStatus 0 -PayloadContains 'inference_complete'

$bCancel = Invoke-Cmd -Id $CMD_CANCEL_INFER -Type $CMD_CANCEL_INFER
Assert-Resp -Name 'B/CANCEL (post-complete expected not-ready)' -Resp $bCancel -ExpectedStatus 5

$bStreamStatus = Invoke-Cmd -Id $CMD_STREAM_STATUS -Type $CMD_STREAM_STATUS
Assert-Resp -Name 'B/STREAM_STATUS (outside active expected not-ready)' -Resp $bStreamStatus -ExpectedStatus 5

$bInfer2 = Invoke-Cmd -Id $CMD_INFER -Type $CMD_INFER -Payload 'post cancel retry'
Assert-Resp -Name 'B/INFER#2' -Resp $bInfer2 -ExpectedStatus 0 -PayloadContains 'inference_complete'

$bUnload = Invoke-Cmd -Id $CMD_UNLOAD_MODEL -Type $CMD_UNLOAD_MODEL
Assert-Resp -Name 'B/UNLOAD' -Resp $bUnload -ExpectedStatus 0 -PayloadContains 'unloaded'

Write-Host '=== Completed: state-gate stress validation passed ==='
