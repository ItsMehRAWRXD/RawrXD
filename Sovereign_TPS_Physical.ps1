# Sovereign_TPS_Physical.ps1
# High-Precision Physical Throughput Monitor for Sovereign Platinum
# Uses .NET to map the actual substrate telemetry region.

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class SubstrateAccess {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr OpenFileMapping(uint dwDesiredAccess, bool bInheritHandle, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject, uint dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, UIntPtr dwNumberOfBytesToMap);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    public const uint FILE_MAP_READ = 0x0004;
}
"@

$SharedMemName = "Sovereign_Telemetry_Block"
$hMap = [SubstrateAccess]::OpenFileMapping([SubstrateAccess]::FILE_MAP_READ, $false, $SharedMemName)

if ($hMap -eq [IntPtr]::Zero) {
    Write-Host "[ERROR] Could not open shared memory: $SharedMemName" -ForegroundColor Red
    Write-Host "Ensure Sovereign_Platinum_Engine.exe is running." -ForegroundColor Yellow
    exit
}

$pBase = [SubstrateAccess]::MapViewOfFile($hMap, [SubstrateAccess]::FILE_MAP_READ, 0, 0, [UIntPtr]4096)
if ($pBase -eq [IntPtr]::Zero) {
    Write-Host "[ERROR] Could not map view of substrate telemetry." -ForegroundColor Red
    [SubstrateAccess]::CloseHandle($hMap)
    exit
}

Write-Host "Connected to Sovereign Physical Substrate. Monitoring hardware cycles..." -ForegroundColor Cyan

$lastPulse = [System.Runtime.InteropServices.Marshal]::ReadInt64($pBase, 0) # Read TokenCount at offset 0
$lastTime = Get-Date

try {
    while ($true) {
        Start-Sleep -Milliseconds 1000
        $currentTime = Get-Date
        $currentPulse = [System.Runtime.InteropServices.Marshal]::ReadInt64($pBase, 0)
        
        $deltaT = ($currentTime - $lastTime).TotalSeconds
        $deltaP = $currentPulse - $lastPulse
        
        $tps = if ($deltaT -gt 0) { $deltaP / $deltaT } else { 0 }
        $latency = if ($tps -gt 0) { 1000 / $tps } else { 0 }
        
        # Read Thermal from offset 64 (Sovereign_Telemetry_Layout.inc definition)
        $thermal = [System.Runtime.InteropServices.Marshal]::ReadInt32($pBase, 64)

        Write-Host "[Sovereign Hardware] TPS: $($tps.ToString("0.00").PadLeft(6)) | Thermal: $($thermal)C | Pulse Index: $currentPulse | Latency: $($latency.ToString("0.00")) ms" -ForegroundColor Green
        
        $lastPulse = $currentPulse
        $lastTime = $currentTime
    }
} finally {
    [SubstrateAccess]::UnmapViewOfFile($pBase)
    [SubstrateAccess]::CloseHandle($hMap)
}
