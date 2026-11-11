param(
    [string]$ModelPath = "D:\TinyLlama-1.1B-Chat-v1.0.Q4_0.gguf",
    [int]$TimeoutMs = 20000,
    [switch]$StatusOnly,
    [switch]$LoadOnly
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.IO.MemoryMappedFiles

$CMD_LOAD_MODEL = 0x2000
$CMD_STATUS = 0x1002

$OFF_STATE = 0x00
$OFF_CMD_ID = 0x04
$OFF_CMD_TYPE = 0x08
$OFF_PAYLOAD_LEN = 0x0C
$OFF_RESP_STATUS = 0x10
$OFF_RESP_LEN = 0x14
$OFF_CMD_PAYLOAD = 0x18
$OFF_RESP_PAYLOAD = 0x1018

function Invoke-BeaconCommand {
    param(
        [int]$CmdType,
        [int]$CmdId,
        [string]$Payload = ""
    )

    $mmf = [System.IO.MemoryMappedFiles.MemoryMappedFile]::OpenExisting("SOVEREIGN_BEACON_V1")
    $cmdEvt = [System.Threading.EventWaitHandle]::OpenExisting("SOVEREIGN_CMD_EVENT")
    $respEvt = [System.Threading.EventWaitHandle]::OpenExisting("SOVEREIGN_RESP_EVENT")
    $acc = $mmf.CreateViewAccessor()

    try {
        $payloadBytes = [System.Text.Encoding]::ASCII.GetBytes($Payload)
        $maxPayload = $OFF_RESP_PAYLOAD - $OFF_CMD_PAYLOAD - 1
        if ($payloadBytes.Length -gt $maxPayload) {
            throw "Payload too large: $($payloadBytes.Length) > $maxPayload"
        }

        $acc.Write($OFF_STATE, [byte]1)
        $acc.Write($OFF_CMD_ID, [int]$CmdId)
        $acc.Write($OFF_CMD_TYPE, [int]$CmdType)
        $acc.Write($OFF_PAYLOAD_LEN, [int]$payloadBytes.Length)

        if ($payloadBytes.Length -gt 0) {
            [void]$acc.WriteArray($OFF_CMD_PAYLOAD, $payloadBytes, 0, $payloadBytes.Length)
        }

        $acc.Write($OFF_CMD_PAYLOAD + $payloadBytes.Length, [byte]0)

        [void]$cmdEvt.Set()
        if (-not $respEvt.WaitOne($TimeoutMs)) {
            throw "Timed out waiting for SOVEREIGN_RESP_EVENT ($TimeoutMs ms)"
        }

        $state = $acc.ReadInt32($OFF_STATE)
        $respStatus = $acc.ReadInt32($OFF_RESP_STATUS)
        $respLen = $acc.ReadInt32($OFF_RESP_LEN)

        $respBytes = New-Object byte[] ([Math]::Max($respLen, 0))
        if ($respLen -gt 0) {
            [void]$acc.ReadArray($OFF_RESP_PAYLOAD, $respBytes, 0, $respLen)
        }

        $respText = [System.Text.Encoding]::ASCII.GetString($respBytes)
        $loaderResult = $null
        $loaderWin32 = $null
        if ($CmdType -eq $CMD_LOAD_MODEL -and $respStatus -ne 0 -and $respLen -ge 8) {
            $loaderResult = [BitConverter]::ToInt32($respBytes, 0)
            $loaderWin32 = [BitConverter]::ToInt32($respBytes, 4)
        }

        [pscustomobject]@{
            CmdType = ('0x{0:X}' -f $CmdType)
            CmdId = $CmdId
            State = $state
            RespStatus = $respStatus
            RespLen = $respLen
            RespPayload = $respText
            LoaderResult = $loaderResult
            LoaderWin32 = $loaderWin32
        }
    }
    finally {
        $acc.Dispose()
        $mmf.Dispose()
        $cmdEvt.Dispose()
        $respEvt.Dispose()
    }
}

if (-not $LoadOnly) {
    Write-Output "--- STATUS ---"
    Invoke-BeaconCommand -CmdType $CMD_STATUS -CmdId $CMD_STATUS | Format-List | Out-String | Write-Output
}

if (-not $StatusOnly) {
    Write-Output "--- LOAD_MODEL ---"
    Write-Output "ModelPath=$ModelPath"
    Invoke-BeaconCommand -CmdType $CMD_LOAD_MODEL -CmdId $CMD_LOAD_MODEL -Payload $ModelPath | Format-List | Out-String | Write-Output
}
