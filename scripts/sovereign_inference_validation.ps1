$ErrorActionPreference = 'Stop'

$CMD_STATUS = 0x1002
$CMD_LOAD_MODEL = 0x2000
$CMD_INFER = 0x3003

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
        $hb = $acc.ReadInt64(0xFFF8)
        $out = New-Object byte[] ([Math]::Max($len,0))
        if ($len -gt 0) {
            [void]$acc.ReadArray(0x1018,$out,0,$len)
        }

        [pscustomobject]@{
            Cmd = ('0x{0:X}' -f $Id)
            RespStatus = $status
            RespLen = $len
            Heartbeat = $hb
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

$model = 'D:\TinyLlama-1.1B-Chat-v1.0.Q4_0.gguf'
$prompt = 'hello sovereign inference path'

'--- STATUS (initial) ---'
Invoke-Cmd -Id $CMD_STATUS -Type $CMD_STATUS | Format-List | Out-String

'--- LOAD_MODEL ---'
Invoke-Cmd -Id $CMD_LOAD_MODEL -Type $CMD_LOAD_MODEL -Payload $model | Format-List | Out-String

'--- WAIT READY ---'
Wait-ReadyState -MaxSeconds 20 | Format-List | Out-String

'--- INFER ---'
Invoke-Cmd -Id $CMD_INFER -Type $CMD_INFER -Payload $prompt | Format-List | Out-String

'--- STATUS (post infer) ---'
Invoke-Cmd -Id $CMD_STATUS -Type $CMD_STATUS | Format-List | Out-String
