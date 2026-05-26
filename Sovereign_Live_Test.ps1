# Sovereign_Live_Test.ps1
# Initiates Market Data MMF and triggers Sovereign_Engine execution

$mapName = "Local\SovereignMarketData"
$size = 4096

# Create MMF with real production parameters
$mmf = [System.IO.MemoryMappedFiles.MemoryMappedFile]::CreateNew($mapName, $size)
$accessor = $mmf.CreateViewAccessor()

# Write Test Tick (Bid 100.0, Ask 100.01)
$accessor.Write(0, [double]100.0)
$accessor.Write(8, [double]100.1)

Write-Host "[SYSTEM] Production Binary: Sovereign_Engine.exe" -ForegroundColor Cyan
Write-Host "[SYSTEM] Memory Mapped File: $mapName" -ForegroundColor Cyan
Write-Host "[SYSTEM] Initiating Execution..." -ForegroundColor Green

# Execute the production binary
$proc = Start-Process -FilePath "D:\rawrxd\Sovereign_Engine.exe" -PassThru -NoNewWindow
$proc.WaitForExit()

Write-Host "[SYSTEM] Process Exit Code: $($proc.ExitCode)" -ForegroundColor Green

# Cleanup
$mmf.Dispose()
