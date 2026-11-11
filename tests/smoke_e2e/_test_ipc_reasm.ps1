$Script:ErrorActionPreference = 'Stop'
. "$PSScriptRoot\modules\IpcFramingHelper.ps1"

$Script:boundary = 'b' * 65522
$Script:legacyFrame = New-LegacyFrame -PayloadUtf8 $boundary -MessageType 2
$Script:reasm = [MockIpcReassembler]::new()
$Script:outType = 0
$Script:outPayload = ''
$Script:ok = $reasm.FeedPhysicalFrame($legacyFrame, [ref]$outType, [ref]$outPayload)
Write-Host "reasm ok=$ok type=$outType payloadLen=$($outPayload.Length)"
