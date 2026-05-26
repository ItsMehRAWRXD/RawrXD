# Align-Tensor.ps1: Ensures tensor.bin meets SEC_LARGE_PAGES requirements
$filePath = "D:\rawrxd\tensor.bin"
$largePageSize = 2MB

if (-not (Test-Path $filePath)) {
    Write-Error "Error: tensor.bin not found at $filePath"
    exit 1
}

$fileInfo = Get-Item $filePath
$currentSize = $fileInfo.Length
$remainder = $currentSize % $largePageSize

if ($remainder -eq 0) {
    Write-Host "[SUCCESS] tensor.bin is already aligned to 2MB boundary."
    exit 0
}

$paddingNeeded = $largePageSize - $remainder
Write-Host "[INFO] File size: $currentSize bytes. Padding with $paddingNeeded bytes to reach 2MB alignment."

try {
    $fs = [System.IO.File]::Open($filePath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write)
    $nullBuffer = [byte[]]::new($paddingNeeded)
    $fs.Write($nullBuffer, 0, $paddingNeeded)
    $fs.Flush()
    $fs.Close()
    Write-Host "[SUCCESS] tensor.bin successfully aligned."
} catch {
    Write-Error "Failed to apply padding: $($_.Exception.Message)"
    exit 1
}
