$Script:ErrorActionPreference = 'Stop'
. "$PSScriptRoot\modules\IpcFramingHelper.ps1"

$Script:f = New-LegacyFrame -PayloadUtf8 ('a' * 1024)
$Script:w = Add-WirePrefix -PhysicalFrame $f
$Script:m = New-Object System.IO.MemoryStream
$m.Write($w, 0, $w.Length)
$m.Position = 0
$Script:h = [MockIpcStreamHandler]::new($m)
$Script:e = $h.TryExtractPhysicalFrame()
Write-Host "small extract ok=$($null -ne $e) len=$($e.Length)"

$Script:m2 = New-Object System.IO.MemoryStream
$Script:big = New-LegacyFrame -PayloadUtf8 ('b' * 65522)
$Script:w2 = Add-WirePrefix -PhysicalFrame $big
$m2.Write($w2, 0, $w2.Length)
$m2.Position = 0
$Script:h2 = [MockIpcStreamHandler]::new($m2)
$Script:e2 = $h2.TryExtractPhysicalFrame()
Write-Host "max extract ok=$($null -ne $e2) len=$($e2.Length)"
