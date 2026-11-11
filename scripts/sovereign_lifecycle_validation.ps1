$ErrorActionPreference = 'Stop'

function Invoke-Cmd {
    param([int]$Id,[int]$Type,[string]$Payload='',[int]$TimeoutMs=10000)

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

$model = 'D:\TinyLlama-1.1B-Chat-v1.0.Q4_0.gguf'

'--- STATUS (initial) ---'
Invoke-Cmd -Id 0x1002 -Type 0x1002 | Format-List | Out-String

'--- LOAD_MODEL #1 ---'
Invoke-Cmd -Id 0x2000 -Type 0x2000 -Payload $model | Format-List | Out-String

'--- STATUS (after load) ---'
Invoke-Cmd -Id 0x1002 -Type 0x1002 | Format-List | Out-String

'--- LOAD_MODEL #2 (expect reject) ---'
Invoke-Cmd -Id 0x2000 -Type 0x2000 -Payload $model | Format-List | Out-String

'--- UNLOAD_MODEL ---'
Invoke-Cmd -Id 0x2001 -Type 0x2001 | Format-List | Out-String

'--- STATUS (after unload) ---'
Invoke-Cmd -Id 0x1002 -Type 0x1002 | Format-List | Out-String
