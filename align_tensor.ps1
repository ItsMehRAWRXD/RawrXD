param (
    [Parameter(Mandatory=$true)]
    [string]$FilePath
)

$LargePageSize = 2MB
$File = Get-Item $FilePath -ErrorAction Stop
$CurrentSize = $File.Length
$Remainder = $CurrentSize % $LargePageSize

if ($Remainder -eq 0) {
    Write-Host "[SUCCESS] Tensor payload $FilePath is already 2MB aligned." -ForegroundColor Green
    exit 0
}

$PaddingNeeded = $LargePageSize - $Remainder
Write-Host "[INFO] Tensor size: $CurrentSize bytes. Applying $PaddingNeeded bytes of padding to reach 2MB alignment." -ForegroundColor Yellow

try {
    $Stream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write)
    $Padding = [byte[]]::new($PaddingNeeded)
    $Stream.Write($Padding, 0, $Padding.Length)
    $Stream.Flush()
    $Stream.Close()
    Write-Host "[SUCCESS] Padding applied. New file size: $($File.Length + $PaddingNeeded) bytes." -ForegroundColor Green
}
catch {
    Write-Error "[FATAL] Failed to apply padding: $_"
    exit 1
}
