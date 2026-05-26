# Sovereign_Align_Tensor.ps1
# Usage: ./Sovereign_Align_Tensor.ps1 -Path "path\to\tensor.bin"

param([Parameter(Mandatory=$true)][string]$Path)

$LargePageSize = 2MB
$file = Get-Item $Path -ErrorAction Stop
$currentSize = $file.Length
$remainder = $currentSize % $LargePageSize

if ($remainder -eq 0) {
    Write-Host "[SUCCESS] File is already 2MB-aligned: $($file.FullName)" -ForegroundColor Green
    exit 0
}

$paddingNeeded = $LargePageSize - $remainder
Write-Host "[ALIGNING] File size: $currentSize bytes. Applying $paddingNeeded bytes of padding..." -ForegroundColor Yellow

try {
    $fs = [System.IO.File]::Open($file.FullName, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write)
    $paddingBuffer = [byte[]]::new($paddingNeeded) # Default byte array of zeros
    $fs.Write($paddingBuffer, 0, $paddingNeeded)
    $fs.Flush()
    $fs.Close()
    Write-Host "[SUCCESS] Padding applied. New size: $($file.Length) bytes." -ForegroundColor Green
} catch {
    Write-Error "[FATAL] Failed to apply padding: $_"
    exit 1
}
