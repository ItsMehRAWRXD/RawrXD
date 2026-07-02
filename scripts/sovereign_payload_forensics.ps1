param(
    [int]$CommandId = 0x1002,
    [int]$CommandType = 0x1002,
    [string]$Payload = '',
    [int]$TimeoutMs = 10000
)

$ErrorActionPreference = 'Stop'

$OFF_STATE = 0x0000
$OFF_CMD_ID = 0x0004
$OFF_CMD_TYPE = 0x0008
$OFF_PAYLOAD_LEN = 0x000C
$OFF_RESP_STATUS = 0x0010
$OFF_RESP_LEN = 0x0014
$OFF_CMD_PAYLOAD = 0x0018
$OFF_RESP_PAYLOAD = 0x1018
$OFF_HEARTBEAT = 0xFFF8
$RESP_PAYLOAD_MAX = 0xEFD8

function Open-WithRetry {
    param(
        [scriptblock]$OpenAction,
        [int]$MaxMs = 5000
    )

    $deadline = (Get-Date).AddMilliseconds($MaxMs)
    while ((Get-Date) -lt $deadline) {
        try {
            return & $OpenAction
        } catch {
            Start-Sleep -Milliseconds 100
        }
    }

    throw 'Timed out waiting for IPC objects to become available.'
}

$mmf = Open-WithRetry -OpenAction { [System.IO.MemoryMappedFiles.MemoryMappedFile]::OpenExisting('SOVEREIGN_BEACON_V1') }
$cmd = Open-WithRetry -OpenAction { [System.Threading.EventWaitHandle]::OpenExisting('SOVEREIGN_CMD_EVENT') }
$resp = Open-WithRetry -OpenAction { [System.Threading.EventWaitHandle]::OpenExisting('SOVEREIGN_RESP_EVENT') }
$acc = $mmf.CreateViewAccessor()

try {
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($Payload)
    $sendLen = [Math]::Min($bytes.Length, 0x0FFF)

    $acc.Write($OFF_STATE, [byte]1)
    $acc.Write($OFF_CMD_ID, $CommandId)
    $acc.Write($OFF_CMD_TYPE, $CommandType)
    $acc.Write($OFF_PAYLOAD_LEN, [int]$sendLen)

    if ($sendLen -gt 0) {
        [void]$acc.WriteArray($OFF_CMD_PAYLOAD, $bytes, 0, $sendLen)
    }
    $acc.Write($OFF_CMD_PAYLOAD + $sendLen, [byte]0)

    [void]$cmd.Set()
    if (-not $resp.WaitOne($TimeoutMs)) {
        throw "Timeout waiting for response for cmd=0x$('{0:X}' -f $CommandId)"
    }

    $respStatus = $acc.ReadInt32($OFF_RESP_STATUS)
    $respLenRaw = $acc.ReadInt32($OFF_RESP_LEN)
    $respLen = [Math]::Max([Math]::Min($respLenRaw, $RESP_PAYLOAD_MAX), 0)
    $heartbeat = $acc.ReadInt64($OFF_HEARTBEAT)

    $raw = New-Object byte[] $respLen
    if ($respLen -gt 0) {
        [void]$acc.ReadArray($OFF_RESP_PAYLOAD, $raw, 0, $respLen)
    }

    $ascii = [System.Text.Encoding]::ASCII.GetString($raw)
    $utf8 = [System.Text.Encoding]::UTF8.GetString($raw)

    $jsonCandidate = $ascii.Trim()
    $jsonValid = $false
    if ($jsonCandidate.StartsWith('{') -or $jsonCandidate.StartsWith('[')) {
        try {
            $null = $jsonCandidate | ConvertFrom-Json
            $jsonValid = $true
        } catch {
            $jsonValid = $false
        }
    }

    [pscustomobject]@{
        CommandId = ('0x{0:X}' -f $CommandId)
        CommandType = ('0x{0:X}' -f $CommandType)
        ResponseStatus = $respStatus
        ResponseLenRaw = $respLenRaw
        ResponseLenClamped = $respLen
        Heartbeat = $heartbeat
        JsonValid = $jsonValid
        AsciiPreview = if ($ascii.Length -gt 240) { $ascii.Substring(0,240) } else { $ascii }
        Utf8Preview = if ($utf8.Length -gt 240) { $utf8.Substring(0,240) } else { $utf8 }
        RawHex = [BitConverter]::ToString($raw)
    } | Format-List | Out-String | Write-Host
}
finally {
    $acc.Dispose()
    $mmf.Dispose()
    $cmd.Dispose()
    $resp.Dispose()
}
