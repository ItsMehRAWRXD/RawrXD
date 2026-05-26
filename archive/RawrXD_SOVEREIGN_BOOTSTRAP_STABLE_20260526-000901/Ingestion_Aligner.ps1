# Ingestion_Aligner.ps1
# Usage: ./Ingestion_Aligner.ps1 -FilePath "D:\rawrxd\data\tensor.bin"

param (
    [Parameter(Mandatory=$true)]
    [string]$FilePath
)

$HugePageSize = 2MB
$File = Get-Item -Path $FilePath
$CurrentSize = $File.Length
$Remainder = $CurrentSize % $HugePageSize

if ($Remainder -ne 0) {
    $PaddingNeeded = $HugePageSize - $Remainder
    Write-Host "[INFO] Tensor blob alignment required: $($PaddingNeeded) bytes." -ForegroundColor Yellow
    
    try {
        $FileStream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write)
        $PaddingBuffer = [byte[]]::new($PaddingNeeded)
        $FileStream.Write($PaddingBuffer, 0, $PaddingNeeded)
        $FileStream.Close()
        Write-Host "[SUCCESS] Padding applied. Final Size: $( (Get-Item $FilePath).Length ) bytes." -ForegroundColor Green
    }
    catch {
        Write-Host "[FATAL] Alignment failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[INFO] Tensor blob is already 2MB aligned." -ForegroundColor Green
}
