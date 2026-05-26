# Sovereign_Flash.ps1
# RAW STORAGE FLASH: DANGEROUS OPERATION - REQUIRES ELEVATION
# Writes Sovereign.exe directly to a physical drive for cold-boot.

$binaryPath = "D:\rawrxd\Sovereign.exe"
$targetDrive = "\\.\PhysicalDrive1" # Caution: MUST BE VERIFIED BY USER

Write-Host "--- SOVEREIGN SUBSTRATE FLASH ENGINE ---" -ForegroundColor Cyan
Write-Host "TARGET: $targetDrive" -ForegroundColor Yellow

if (-not (Test-Path $binaryPath)) {
    Write-Host "ERROR: $binaryPath not found. Please build first." -ForegroundColor Red
    exit
}

try {
    $bytes = [System.IO.File]::ReadAllBytes($binaryPath)
    $stream = [System.IO.File]::Open($targetDrive, 'Open', 'Write')
    
    Write-Host "WRITING BINARY ($($bytes.Length) bytes)..." -ForegroundColor Gray
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.SetLength($bytes.Length)
    $stream.Flush()
    
    Write-Host "FLASH SUCCESSFUL: Substrate immutable. Detach host now." -ForegroundColor Green
}
catch {
    Write-Host "FATAL: Flash failed. Access denied or drive busy." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Gray
}
finally {
    if ($null -ne $stream) { $stream.Close() }
}
