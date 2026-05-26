$f = "D:\rawrxd\phi3-mini-Q2_K.gguf"
if (-Not (Test-Path $f)) { "File not found: $f" ; exit }
$fs = [System.IO.File]::OpenRead($f)
$header = New-Object byte[] 64
$fs.Read($header, 0, 64) | Out-Null
$tensorCount = [System.BitConverter]::ToUInt64($header, 8)
$metaCount = [System.BitConverter]::ToUInt64($header, 16)

# We need to skip exactly the kv pairs, not just 64k.
$fs.Position = 24
for ($i = 0; $i -lt $metaCount; $i++) {
    $lenBytes = New-Object byte[] 8
    $fs.Read($lenBytes, 0, 8) | Out-Null
    $len = [System.BitConverter]::ToUInt64($lenBytes, 0)
    $fs.Position += $len
    $typeBytes = New-Object byte[] 4
    $fs.Read($typeBytes, 0, 4) | Out-Null
    $type = [System.BitConverter]::ToUInt32($typeBytes, 0)
    
    if ($type -eq 0) { $fs.Position += 1 }
    elseif ($type -eq 1) { $fs.Position += 2 }
    elseif ($type -eq 2) { $fs.Position += 4 }
    elseif ($type -eq 3) { $fs.Position += 4 }
    elseif ($type -eq 4) { $fs.Position += 8 }
    elseif ($type -eq 5) { $fs.Position += 8 }
    elseif ($type -eq 6) { $fs.Position += 8 }
    elseif ($type -eq 7) { $fs.Position += 1 }
    elseif ($type -eq 8) {
        $lenBytes = New-Object byte[] 8
        $fs.Read($lenBytes, 0, 8) | Out-Null
        $len = [System.BitConverter]::ToUInt64($lenBytes, 0)
        $fs.Position += $len
    }
    elseif ($type -eq 9) {
        $typeBytes2 = New-Object byte[] 4
        $fs.Read($typeBytes2, 0, 4) | Out-Null
        $lenBytes = New-Object byte[] 8
        $fs.Read($lenBytes, 0, 8) | Out-Null
        $len = [System.BitConverter]::ToUInt64($lenBytes, 0)
        $arrType = [System.BitConverter]::ToUInt32($typeBytes2, 0)
        if ($arrType -eq 0) { $fs.Position += $len * 1 }
        elseif ($arrType -eq 1) { $fs.Position += $len * 2 }
        elseif ($arrType -eq 2) { $fs.Position += $len * 4 }
        elseif ($arrType -eq 3) { $fs.Position += $len * 4 }
        elseif ($arrType -eq 4) { $fs.Position += $len * 8 }
        elseif ($arrType -eq 5) { $fs.Position += $len * 8 }
        elseif ($arrType -eq 6) { $fs.Position += $len * 8 }
        elseif ($arrType -eq 7) { $fs.Position += $len * 1 }
        elseif ($arrType -eq 8) {
            for ($k = 0; $k -lt $len; $k++) {
                $slenBytes = New-Object byte[] 8
                $fs.Read($slenBytes, 0, 8) | Out-Null
                $slen = [System.BitConverter]::ToUInt64($slenBytes, 0)
                $fs.Position += $slen
            }
        }
    }
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
