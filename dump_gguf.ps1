$f = "D:\rawrxd\phi3-mini-Q2_K.gguf"
if (-Not (Test-Path $f)) { "File not found: $f" ; exit }
$fs = [System.IO.File]::OpenRead($f)
$header = New-Object byte[] 64
$fs.Read($header, 0, 64) | Out-Null
$tensorCount = [System.BitConverter]::ToUInt64($header, 8)

# Skip metadata kv pairs
$buf = New-Object byte[] 65536
$totalRead = 64
while ($totalRead -lt 65536) {
    $n = $fs.Read($buf, 0, 65536)
    if ($n -eq 0) { break }
    $totalRead += $n
}

"Tensor Count: $tensorCount"
"First 20 tensors:"
for ($i = 0; $i -lt [Math]::Min(20, $tensorCount); $i++) {
    $nameLenBytes = New-Object byte[] 8
    $fs.Read($nameLenBytes, 0, 8) | Out-Null
    $nameLen = [System.BitConverter]::ToUInt64($nameLenBytes, 0)
    $nameBytes = New-Object byte[] $nameLen
    $fs.Read($nameBytes, 0, $nameLen) | Out-Null
    $name = [System.Text.Encoding]::UTF8.GetString($nameBytes)
    
    $nDimsBytes = New-Object byte[] 4
    $fs.Read($nDimsBytes, 0, 4) | Out-Null
    $nDims = [System.BitConverter]::ToUInt32($nDimsBytes, 0)
    
    $dims = @()
    for ($d = 0; $d -lt $nDims; $d++) {
        $dimBytes = New-Object byte[] 8
        $fs.Read($dimBytes, 0, 8) | Out-Null
        $dims += [System.BitConverter]::ToUInt64($dimBytes, 0)
    }
    
    $typeBytes = New-Object byte[] 4
    $fs.Read($typeBytes, 0, 4) | Out-Null
    $type = [System.BitConverter]::ToUInt32($typeBytes, 0)
    
    $offsetBytes = New-Object byte[] 8
    $fs.Read($offsetBytes, 0, 8) | Out-Null
    $offset = [System.BitConverter]::ToUInt64($offsetBytes, 0)
    
    "$name | Type=$type | Dims=$($dims -join 'x') | Offset=$offset"
}
$fs.Close()
