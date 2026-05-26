# Sovereign_Simulator.ps1
$name = "Local\SovereignMarketData"
$size = 4096

try {
    $mmf = [System.IO.MemoryMappedFiles.MemoryMappedFile]::CreateNew($name, $size)
    $accessor = $mmf.CreateViewAccessor()
    
    # Write some data
    $accessor.Write(0, [double]100.0) # Bid
    $accessor.Write(8, [double]100.01) # Ask
    
    Write-Host "[SIMULATOR] Shared Memory '$name' created. Logic ready."
    Write-Host "[SIMULATOR] Launching Engine..."
    
    # Launch engine and wait a bit
    $p = Start-Process "D:\rawrxd\Sovereign_Engine.exe" -PassThru -NoNewWindow
    Start-Sleep -Seconds 5
    
    if ($p.HasExited) {
        Write-Host "[SIMULATOR] Engine exited with code: $($p.ExitCode)"
    } else {
        Write-Host "[SIMULATOR] Engine still running. Signaling shutdown..."
        $p | Stop-Process
    }
} finally {
    if ($mmf) { $mmf.Dispose() }
}
