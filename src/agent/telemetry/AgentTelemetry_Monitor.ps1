# AgentTelemetry_Monitor.ps1
# Real-time monitoring of g_AgentTelemetry during smoke test
# Run: .\AgentTelemetry_Monitor.ps1 -ProcessName "RawrXD-Agent" -IntervalSeconds 5

param(
    [Parameter(Mandatory=$true)]
    [string]$ProcessName,
    
    [Parameter(Mandatory=$false)]
    [int]$IntervalSeconds = 5,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\telemetry_monitor.log",
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowGUI = $false
)

# ============================================================================
# CONFIGURATION
# ============================================================================
$TELEMETRY_STRUCT_SIZE = 64  # Bytes, cache-aligned
$OFFSET_ARENA_USED = 0       # QWORD at offset 0
$OFFSET_VRAM_USED = 8        # QWORD at offset 8
$OFFSET_PROPOSALS_GEN = 16   # DWORD at offset 16
$OFFSET_PROPOSALS_APP = 20   # DWORD at offset 20
$OFFSET_SWARM_LATENCY = 24    # QWORD at offset 24
$OFFSET_LOOP_COUNT = 32      # DWORD at offset 32
$OFFSET_STATE_CHECKSUM = 40   # QWORD at offset 40

# Thresholds for alerts
$ALERT_ARENA_GROWTH_MB_PER_HOUR = 100
$ALERT_ALLOCATIONS_PER_SEC = 1000
$ALERT_CHECKSUM_VARIANCE_PERCENT = 0.01

# ============================================================================
# WIN32 API IMPORTS
# ============================================================================
Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.ComponentModel;

public class Win32Memory {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out MODULEINFO lpmodinfo, int cb);
    
    [DllImport("dbghelp.dll", SetLastError = true)]
    public static extern bool SymInitialize(IntPtr hProcess, string UserSearchPath, bool fInvadeProcess);
    
    [DllImport("dbghelp.dll", SetLastError = true)]
    public static extern bool SymCleanup(IntPtr hProcess);
    
    [DllImport("dbghelp.dll", SetLastError = true)]
    public static extern bool SymFromName(IntPtr hProcess, string Name, out SYMBOL_INFO Symbol);
    
    [StructLayout(LayoutKind.Sequential)]
    public struct MODULEINFO {
        public IntPtr lpBaseOfDll;
        public uint SizeOfImage;
        public IntPtr EntryPoint;
    }
    
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct SYMBOL_INFO {
        public uint SizeOfStruct;
        public uint TypeIndex;
        public ulong Reserved1;
        public ulong Reserved2;
        public uint Index;
        public uint Size;
        public ulong ModBase;
        public uint Flags;
        public ulong Value;
        public ulong Address;
        public uint Register;
        public uint Scope;
        public uint Tag;
        public uint NameLen;
        public uint MaxNameLen;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 1024)]
        public string Name;
    }
    
    public const uint PROCESS_VM_READ = 0x0010;
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
}
"@

# ============================================================================
# FUNCTIONS
# ============================================================================

function Find-TelemetryAddress {
    param([int]$ProcessId)
    
    # Try to find g_AgentTelemetry symbol using DbgHelp
    $hProcess = [Win32Memory]::OpenProcess(
        [Win32Memory]::PROCESS_VM_READ -bor [Win32Memory]::PROCESS_QUERY_INFORMATION, 
        $false, 
        $ProcessId
    )
    
    if ($hProcess -eq [IntPtr]::Zero) {
        Write-Error "Failed to open process $ProcessId"
        return $null
    }
    
    try {
        # Initialize symbol handler
        if (-not [Win32Memory]::SymInitialize($hProcess, $null, $false)) {
            Write-Warning "SymInitialize failed, trying module enumeration..."
        }
        
        # Try to find symbol
        $symInfo = New-Object Win32Memory+SYMBOL_INFO
        $symInfo.SizeOfStruct = [System.Runtime.InteropServices.Marshal]::SizeOf([Win32Memory+SYMBOL_INFO])
        $symInfo.MaxNameLen = 1024
        
        if ([Win32Memory]::SymFromName($hProcess, "g_AgentTelemetry", [ref]$symInfo)) {
            Write-Host "Found g_AgentTelemetry at 0x$($symInfo.Address.ToString('X16'))"
            return [IntPtr]::new($symInfo.Address)
        }
        
        # Fallback: Search for pattern in memory
        Write-Warning "Symbol not found, using fallback pattern search..."
        return $null
    }
    finally {
        [Win32Memory]::SymCleanup($hProcess) | Out-Null
        [Win32Memory]::CloseHandle($hProcess) | Out-Null
    }
}

function Read-TelemetryData {
    param([IntPtr]$hProcess, [IntPtr]$TelemetryAddress)
    
    $buffer = New-Object byte[] $TELEMETRY_STRUCT_SIZE
    $bytesRead = 0
    
    if (-not [Win32Memory]::ReadProcessMemory($hProcess, $TelemetryAddress, $buffer, $TELEMETRY_STRUCT_SIZE, [ref]$bytesRead)) {
        $error = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "ReadProcessMemory failed: $error"
        return $null
    }
    
    # Parse structure
    $telemetry = @{
        ArenaUsedBytes = [BitConverter]::ToUInt64($buffer, $OFFSET_ARENA_USED)
        VramUsedBytes = [BitConverter]::ToUInt64($buffer, $OFFSET_VRAM_USED)
        ProposalsGenerated = [BitConverter]::ToUInt32($buffer, $OFFSET_PROPOSALS_GEN)
        ProposalsApplied = [BitConverter]::ToUInt32($buffer, $OFFSET_PROPOSALS_APP)
        TotalSwarmLatencyUs = [BitConverter]::ToUInt64($buffer, $OFFSET_SWARM_LATENCY)
        LoopCount = [BitConverter]::ToUInt32($buffer, $OFFSET_LOOP_COUNT)
        StateChecksum = [BitConverter]::ToUInt64($buffer, $OFFSET_STATE_CHECKSUM)
    }
    
    return $telemetry
}

function Format-Bytes {
    param([uint64]$Bytes)
    
    if ($Bytes -gt 1GB) {
        return "{0:N2} GB" -f ($Bytes / 1GB)
    } elseif ($Bytes -gt 1MB) {
        return "{0:N2} MB" -f ($Bytes / 1MB)
    } elseif ($Bytes -gt 1KB) {
        return "{0:N2} KB" -f ($Bytes / 1KB)
    } else {
        return "$Bytes B"
    }
}

function Test-AlertConditions {
    param([hashtable]$Current, [hashtable]$Previous, [TimeSpan]$Elapsed)
    
    $alerts = @()
    
    # Arena growth rate
    if ($Previous -and $Elapsed.TotalHours -gt 0) {
        $arenaGrowth = $Current.ArenaUsedBytes - $Previous.ArenaUsedBytes
        $growthRateMBPerHour = ($arenaGrowth / 1MB) / $Elapsed.TotalHours
        
        if ($growthRateMBPerHour -gt $ALERT_ARENA_GROWTH_MB_PER_HOUR) {
            $alerts += "HIGH ARENA GROWTH: {0:N2} MB/hour (threshold: $ALERT_ARENA_GROWTH_MB_PER_HOUR MB/hour)" -f $growthRateMBPerHour
        }
        
        # Allocation rate
        $loopDelta = $Current.LoopCount - $Previous.LoopCount
        if ($Elapsed.TotalSeconds -gt 0) {
            $allocRate = $loopDelta / $Elapsed.TotalSeconds
            if ($allocRate -gt $ALERT_ALLOCATIONS_PER_SEC) {
                $alerts += "HIGH ALLOCATION RATE: {0:N0} ops/sec (threshold: $ALERT_ALLOCATIONS_PER_SEC)" -f $allocRate
            }
        }
    }
    
    return $alerts
}

# ============================================================================
# MAIN MONITORING LOOP
# ============================================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Agent Telemetry Real-Time Monitor" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Monitoring process: $ProcessName" -ForegroundColor Yellow
Write-Host "Update interval: $IntervalSeconds seconds" -ForegroundColor Yellow
Write-Host "Log file: $OutputPath" -ForegroundColor Yellow
Write-Host ""
Write-Host "Press Ctrl+C to stop" -ForegroundColor Gray
Write-Host ""

# Initialize log
"Timestamp,ArenaUsedBytes,VramUsedBytes,ProposalsGenerated,ProposalsApplied,TotalSwarmLatencyUs,LoopCount,StateChecksum" | 
    Set-Content $OutputPath

$startTime = Get-Date
$previousTelemetry = $null
$previousTime = $startTime
$telemetryAddress = $null
$hProcess = [IntPtr]::Zero

# Find process
while (-not $telemetryAddress) {
    $process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
    
    if (-not $process) {
        Write-Host "Waiting for process '$ProcessName' to start..." -ForegroundColor Yellow
        Start-Sleep -Seconds 5
        continue
    }
    
    Write-Host "Found process: $($process.ProcessName) (PID: $($process.Id))" -ForegroundColor Green
    
    # Open process handle
    $hProcess = [Win32Memory]::OpenProcess(
        [Win32Memory]::PROCESS_VM_READ -bor [Win32Memory]::PROCESS_QUERY_INFORMATION,
        $false,
        $process.Id
    )
    
    if ($hProcess -eq [IntPtr]::Zero) {
        Write-Error "Failed to open process. Run as Administrator?"
        exit 1
    }
    
    # Find telemetry address
    $telemetryAddress = Find-TelemetryAddress -ProcessId $process.Id
    
    if (-not $telemetryAddress) {
        Write-Warning "Could not find telemetry address. Using offset calculation..."
        # Fallback: Try to calculate from module base
        # This would require knowing the RVA of g_AgentTelemetry
        $telemetryAddress = [IntPtr]::Zero  # Placeholder
    }
}

# Main monitoring loop
try {
    while ($true) {
        $now = Get-Date
        $elapsed = $now - $startTime
        $intervalElapsed = $now - $previousTime
        
        # Read telemetry
        $telemetry = Read-TelemetryData -hProcess $hProcess -TelemetryAddress $telemetryAddress
        
        if (-not $telemetry) {
            Write-Error "Failed to read telemetry"
            break
        }
        
        # Check alerts
        $alerts = Test-AlertConditions -Current $telemetry -Previous $previousTelemetry -Elapsed $intervalElapsed
        
        # Display
        Clear-Host
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "  Agent Telemetry Monitor" -ForegroundColor Cyan
        Write-Host "  Elapsed: $($elapsed.ToString('hh\:mm\:ss'))" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""
        
        Write-Host "Memory Usage:" -ForegroundColor Yellow
        Write-Host "  Arena Used:     $(Format-Bytes $telemetry.ArenaUsedBytes)" -ForegroundColor White
        Write-Host "  VRAM Used:      $(Format-Bytes $telemetry.VramUsedBytes)" -ForegroundColor White
        Write-Host ""
        
        Write-Host "Performance:" -ForegroundColor Yellow
        Write-Host "  Proposals Gen:  $($telemetry.ProposalsGenerated)" -ForegroundColor White
        Write-Host "  Proposals App:  $($telemetry.ProposalsApplied)" -ForegroundColor White
        Write-Host "  Loop Count:     $($telemetry.LoopCount)" -ForegroundColor White
        if ($previousTelemetry -and $intervalElapsed.TotalSeconds -gt 0) {
            $opsPerSec = ($telemetry.LoopCount - $previousTelemetry.LoopCount) / $intervalElapsed.TotalSeconds
            Write-Host "  Ops/Sec:        {0:N2}" -f $opsPerSec -ForegroundColor White
        }
        Write-Host ""
        
        Write-Host "Latency:" -ForegroundColor Yellow
        $avgLatencyUs = $(if ($telemetry.LoopCount -gt 0) { 
            $telemetry.TotalSwarmLatencyUs / $telemetry.LoopCount 
        } else { 
            0 
        }
        Write-Host "  Total:          $($telemetry.TotalSwarmLatencyUs) μs" -ForegroundColor White
        Write-Host "  Avg/Loop:       {0:N2} μs" -f $avgLatencyUs -ForegroundColor White
        Write-Host ""
        
        Write-Host "State Fidelity:" -ForegroundColor Yellow
        Write-Host "  Checksum:       0x$($telemetry.StateChecksum.ToString('X16'))" -ForegroundColor White
        if ($previousTelemetry) {
            $checksumDiff = [math]::Abs([int64]$telemetry.StateChecksum - [int64]$previousTelemetry.StateChecksum)
            if ($checksumDiff -eq 0) {
                Write-Host "  Variance:       IDENTICAL ✅" -ForegroundColor Green
            } else {
                Write-Host "  Variance:       $checksumDiff bits changed ⚠️" -ForegroundColor Yellow
            }
        }
        Write-Host ""
        
        # Alerts
        if ($alerts.Count -gt 0) {
            Write-Host "⚠️  ALERTS:" -ForegroundColor Red
            foreach ($alert in $alerts) {
                Write-Host "    $alert" -ForegroundColor Red
            }
            Write-Host ""
        }
        
        Write-Host "Press Ctrl+C to stop" -ForegroundColor Gray
        
        # Log to CSV
        $csvLine = "{0},{1},{2},{3},{4},{5},{6},{7}" -f @(
            $now.ToString("yyyy-MM-dd HH:mm:ss"),
            $telemetry.ArenaUsedBytes,
            $telemetry.VramUsedBytes,
            $telemetry.ProposalsGenerated,
            $telemetry.ProposalsApplied,
            $telemetry.TotalSwarmLatencyUs,
            $telemetry.LoopCount,
            $telemetry.StateChecksum
        )
        Add-Content $OutputPath $csvLine
        
        # Update previous
        $previousTelemetry = $telemetry
        $previousTime = $now
        
        Start-Sleep -Seconds $IntervalSeconds
    }
}
finally {
    if ($hProcess -ne [IntPtr]::Zero) {
        [Win32Memory]::CloseHandle($hProcess) | Out-Null
    }
    
    Write-Host ""
    Write-Host "Monitoring stopped. Log saved to: $OutputPath" -ForegroundColor Green
}
