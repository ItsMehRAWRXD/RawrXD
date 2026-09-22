# Strip BOM from CMakeLists.txt
$path = 'F:\~dev\CMakeLists.txt'
$bytes = [System.IO.File]::ReadAllBytes($path)
$bomUtf8 = @(0xEF,0xBB,0xBF)
$bomUtf16LE = @(0xFF,0xFE)
$bomUtf16BE = @(0xFE,0xFF)

if ($bytes.Length -ge 3 -and $bytes[0] -eq $bomUtf8[0] -and $bytes[1] -eq $bomUtf8[1] -and $bytes[2] -eq $bomUtf8[2]) {
    $bytes = $bytes[3..($bytes.Length-1)]
    Write-Host 'Removed UTF-8 BOM'
} elseif ($bytes.Length -ge 2 -and $bytes[0] -eq $bomUtf16LE[0] -and $bytes[1] -eq $bomUtf16LE[1]) {
    $bytes = $bytes[2..($bytes.Length-1)]
    Write-Host 'Removed UTF-16 LE BOM'
} elseif ($bytes.Length -ge 2 -and $bytes[0] -eq $bomUtf16BE[0] -and $bytes[1] -eq $bomUtf16BE[1]) {
    $bytes = $bytes[2..($bytes.Length-1)]
    Write-Host 'Removed UTF-16 BE BOM'
} else {
    Write-Host 'No recognized BOM'
}

[System.IO.File]::WriteAllBytes($path, $bytes)
Write-Host 'Done'
