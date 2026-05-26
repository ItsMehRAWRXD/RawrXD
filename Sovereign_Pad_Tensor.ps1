# Sovereign_Pad_Tensor.ps1
# Ensures tensor.bin is aligned to a 2MB boundary for SEC_LARGE_PAGES
param (
    [string]$FilePath = "D:\rawrxd\tensor.bin"
)

$HugePageSize = 2 * 1024 * 1024 # 2MB
$File = Get-Item -Path $FilePath -ErrorAction Stop
$CurrentSize = $File.Length
$Remainder = $CurrentSize % $HugePageSize

if ($Remainder -ne 0) {
    $PaddingNeeded = $HugePageSize - $Remainder
    Write-Host "[INFO] File size $CurrentSize bytes is not 2MB aligned." -ForegroundColor Yellow
    Write-Host "[INFO] Applying $PaddingNeeded bytes of padding to reach $HugePageSize boundary." -ForegroundColor Cyan
    
    try {
        $Stream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write)
        $Buffer = [byte[]]::new($PaddingNeeded) # Zero-initialized by default
        $Stream.Write($Buffer, 0, $PaddingNeeded)
        $Stream.Close()
        Write-Host "[SUCCESS] Tensor blob successfully aligned." -ForegroundColor Green
    }
    catch {
        Write-Error "[FATAL] Failed to pad tensor: $($_.Exception.Message)"
        exit 1
    }
} else {
    Write-Host "[SUCCESS] Tensor blob is already 2MB aligned." -ForegroundColor Green
}
