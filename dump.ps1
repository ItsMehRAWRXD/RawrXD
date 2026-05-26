$f = 'D:\rawrxd\phi3-mini-Q2_K.gguf'
$bytes = [System.IO.File]::ReadAllBytes($f)
Write-Output ("Magic (bytes 0-3): " + ([System.BitConverter]::ToString($bytes[0..3]) -replace '-',''))
Write-Output ("Version (bytes 4-7): " + [System.BitConverter]::ToUInt32($bytes[4..7], 0))
Write-Output ("Tensor/Metadata count (bytes 8-15): " + [System.BitConverter]::ToUInt64($bytes[8..15], 0))
Write-Output ("First 64 bytes hex: " + ([System.BitConverter]::ToString($bytes[0..63]) -replace '-',' '))
