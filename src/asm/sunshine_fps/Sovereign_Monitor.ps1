# Sovereign_Monitor.ps1
# Calibrated for SOVEREIGN_FABRIC_CONTEXT
# Telemetry Offset: 0x148
# Lane0_Result Offset: 0x28 (Relative to 0x148)

param(
    [Parameter(Mandatory=$true)][int]$ProcessId,
    [Parameter(Mandatory=$true)][Int64]$BaseAddress 
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Native {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);
}
"@

$PROCESS_VM_READ = 0x0010
$PROCESS_VM_WRITE = 0x0020
$PROCESS_VM_OPERATION = 0x0008
$hProcess = [Native]::OpenProcess($PROCESS_VM_READ -bor $PROCESS_VM_WRITE -bor $PROCESS_VM_OPERATION, $false, $ProcessId)

if ($hProcess -eq [IntPtr]::Zero) {
    Write-Error "Failed to acquire handle to Sovereign Fabric (PID: $ProcessId)."
    exit
}

$TelemetryBase = [IntPtr]($BaseAddress + 0x158)
$BeaconBase = [IntPtr]($BaseAddress + 0x00)
$Buffer = New-Object byte[] 64
$bytesRead = 0
$bytesWritten = 0

# Handshake Magic Number
$HandshakeMagic = 0x534F56524549474E

Write-Host "Initializing Observer Interface..." -ForegroundColor Cyan
Start-Sleep -Seconds 1

$frame_count = 0

while ($true) {
    if ([Native]::ReadProcessMemory($hProcess, $TelemetryBase, $Buffer, 64, [ref]$bytesRead)) {
        
        # Extract fields
        $TickCount    = [BitConverter]::ToUInt64($Buffer, 0)
        $Lane0Result  = [BitConverter]::ToUInt64($Buffer, 0x28)
        $SystemStatus = [BitConverter]::ToUInt64($Buffer, 0x30)
        
        # Evaluate Operational State
        $StatusLabel = "INITIALIZING"
        $StatusColor = "Yellow"
        
        if ($SystemStatus -eq $HandshakeMagic) {
            $StatusLabel = "OPERATIONAL"
            $StatusColor = "Green"
        }
        
        # Render Telemetry
        [Console]::Clear()
        Write-Host "--- SOVEREIGN FABRIC MONITOR ---" -ForegroundColor Cyan
        Write-Host "Context Base  : 0x$($BaseAddress.ToString('X'))"
        Write-Host "Global Tick   : $TickCount"
        Write-Host "Lane 0 Result : 0x$($Lane0Result.ToString('X'))"
        Write-Host "Fabric State  : [$StatusLabel]" -ForegroundColor $StatusColor

        # Write to Beacon_Registers for Camera Orbit
        $time = [Math]::PI * $frame_count / 180.0
        $cos_t = [Math]::Cos($time)
        $sin_t = [Math]::Sin($time)

        # Write cos_t to +0, and sin_t to +8
        $bytes = [BitConverter]::GetBytes([float]$cos_t) + [BitConverter]::GetBytes([float]0.0) + [BitConverter]::GetBytes([float]$sin_t)
        
        [Native]::WriteProcessMemory($hProcess, $BeaconBase, $bytes, 12, [ref]$bytesWritten)
        $frame_count += 3

    } else {
        Write-Host "[!] Fabric Signal Lost (Read Process Memory Failed)" -ForegroundColor Red
        break
    }
    Start-Sleep -Milliseconds 16 
}
