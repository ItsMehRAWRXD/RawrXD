# Sovereign_Ingestion_Aligner.ps1
# Usage: ./Sovereign_Ingestion_Aligner.ps1 -FilePath "D:\rawrxd\data\tensor.bin"

param (
    [Parameter(Mandatory=$true)]
    [string]$FilePath
)

$HugePageSize = 2MB
$File = Get-Item $FilePath
$CurrentSize = $File.Length
$Remainder = $CurrentSize % $HugePageSize

if ($Remainder -eq 0) {
    Write-Host "[SUCCESS] File is already 2MB aligned." -ForegroundColor Green
    exit 0
}

$PaddingNeeded = $HugePageSize - $Remainder
Write-Host "[INFO] Current size: $CurrentSize bytes."
Write-Host "[INFO] Applying $PaddingNeeded bytes of padding to reach alignment."

try {
    $Stream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write)
    $Buffer = [byte[]]::new($PaddingNeeded) # Zero-initialized by default
    $Stream.Write($Buffer, 0, $PaddingNeeded)
    $Stream.Flush()
    $Stream.Close()
    Write-Host "[SUCCESS] Alignment complete. New file size: $($File.Length + $PaddingNeeded) bytes." -ForegroundColor Green
} catch {
    Write-Error "[FATAL] Failed to apply padding: $($_.Exception.Message)"
    exit 1
}
