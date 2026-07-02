# Sovereign Shared Memory Chat Client
# Communicates with SovereignOrchestrator via shared memory beacon

param(
    [string]$Prompt = "Hello, how are you?",
    [int]$MaxTokens = 50,
    [int]$TimeoutMs = 30000
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class SovereignClient {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenFileMapping(uint dwDesiredAccess, bool bInheritHandle, string lpName);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject, uint dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, uint dwNumberOfBytesToMap);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
    
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr OpenEvent(uint dwDesiredAccess, bool bInheritHandle, string lpName);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetEvent(IntPtr hEvent);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ResetEvent(IntPtr hEvent);
    
    public const uint FILE_MAP_READ = 0x0004;
    public const uint FILE_MAP_WRITE = 0x0002;
    public const uint FILE_MAP_ALL_ACCESS = 0xF001F;
    public const uint EVENT_MODIFY_STATE = 0x0002;
    public const uint SYNCHRONIZE = 0x00100000;
    public const uint INFINITE = 0xFFFFFFFF;
    public const uint WAIT_OBJECT_0 = 0;
    public const uint WAIT_TIMEOUT = 0x102;
    
    // Beacon structure (must match SovereignOrchestrator)
    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct SovereignBeacon {
        public uint magic;           // 'SOV1'
        public uint version;
        public uint flags;
        public uint cmd_len;
        public uint resp_len;
        public uint status;
        public ulong timestamp;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4096)]
        public byte[] cmd_buffer;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16384)]
        public byte[] resp_buffer;
    }
}
"@

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SOVEREIGN SHARED MEMORY CHAT CLIENT" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if orchestrator is running
$orchProcess = Get-Process -Name "SovereignOrchestrator" -ErrorAction SilentlyContinue
if (-not $orchProcess) {
    Write-Host "❌ SovereignOrchestrator is not running!" -ForegroundColor Red
    Write-Host "   Start it first with:" -ForegroundColor Yellow
    Write-Host "   .\Launch-Sovereign-Complete.ps1" -ForegroundColor White
    exit 1
}

Write-Host "✅ SovereignOrchestrator is running (PID: $($orchProcess.Id))" -ForegroundColor Green
Write-Host ""

# Open shared memory
$mapName = "SOVEREIGN_BEACON_V1"
$cmdEventName = "SOVEREIGN_CMD_EVENT"
$respEventName = "SOVEREIGN_RESP_EVENT"

Write-Host "Opening shared memory: $mapName" -ForegroundColor Yellow

$hMap = [SovereignClient]::OpenFileMapping([SovereignClient]::FILE_MAP_ALL_ACCESS, $false, $mapName)
if ($hMap -eq [IntPtr]::Zero) {
    Write-Host "❌ Failed to open shared memory!" -ForegroundColor Red
    Write-Host "   Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Shared memory opened" -ForegroundColor Green

# Map view
$pMap = [SovereignClient]::MapViewOfFile($hMap, [SovereignClient]::FILE_MAP_ALL_ACCESS, 0, 0, 0)
if ($pMap -eq [IntPtr]::Zero) {
    Write-Host "❌ Failed to map view!" -ForegroundColor Red
    [SovereignClient]::CloseHandle($hMap) | Out-Null
    exit 1
}

Write-Host "✅ Memory mapped at address: $pMap" -ForegroundColor Green

# Open events
$hCmdEvent = [SovereignClient]::OpenEvent([SovereignClient]::EVENT_MODIFY_STATE -bor [SovereignClient]::SYNCHRONIZE, $false, $cmdEventName)
$hRespEvent = [SovereignClient]::OpenEvent([SovereignClient]::EVENT_MODIFY_STATE -bor [SovereignClient]::SYNCHRONIZE, $false, $respEventName)

if ($hCmdEvent -eq [IntPtr]::Zero -or $hRespEvent -eq [IntPtr]::Zero) {
    Write-Host "❌ Failed to open events!" -ForegroundColor Red
    [SovereignClient]::UnmapViewOfFile($pMap) | Out-Null
    [SovereignClient]::CloseHandle($hMap) | Out-Null
    exit 1
}

Write-Host "✅ Events opened" -ForegroundColor Green
Write-Host ""

# Build command
$cmd = @{
    action = "generate"
    prompt = $Prompt
    max_tokens = $MaxTokens
    temperature = 0.7
} | ConvertTo-Json -Compress

Write-Host "Command: $cmd" -ForegroundColor Gray
Write-Host ""

# Write command to shared memory
$cmdBytes = [System.Text.Encoding]::UTF8.GetBytes($cmd)

# Offsets per SovereignOrchestrator_Hardened.asm:
# OFF_STATE = 0x00, OFF_CMD_ID = 0x04, OFF_CMD_TYPE = 0x08, OFF_PAYLOAD_LEN = 0x0C
# OFF_RESP_STATUS = 0x10, OFF_RESP_LEN = 0x14, OFF_CMD_PAYLOAD = 0x18

# Set state to READY (1)
[System.Runtime.InteropServices.Marshal]::WriteInt32($pMap, 0x00, 1)

# Set command type to CMD_INFER (0x3003)
[System.Runtime.InteropServices.Marshal]::WriteInt32($pMap, 0x08, 0x3003)

# Set payload length
[System.Runtime.InteropServices.Marshal]::WriteInt32($pMap, 0x0C, $cmdBytes.Length)

# Write payload at offset 0x18
[System.Runtime.InteropServices.Marshal]::Copy($cmdBytes, 0, [IntPtr]($pMap.ToInt64() + 0x18), [Math]::Min($cmdBytes.Length, 4096))

# Set magic cookie at offset 0xFFF0
[System.Runtime.InteropServices.Marshal]::WriteInt64($pMap, 0xFFF0, 0xDEADBEEFCAFEBABE)

Write-Host "📤 Command written to shared memory" -ForegroundColor Yellow

# Signal command event
[SovereignClient]::SetEvent($hCmdEvent) | Out-Null
Write-Host "📡 Command event signaled" -ForegroundColor Yellow
Write-Host ""

# Wait for response
Write-Host "⏳ Waiting for response (timeout: $($TimeoutMs)ms)..." -ForegroundColor Yellow
$result = [SovereignClient]::WaitForSingleObject($hRespEvent, $TimeoutMs)

if ($result -eq [SovereignClient]::WAIT_TIMEOUT) {
    Write-Host "❌ Timeout waiting for response!" -ForegroundColor Red
} elseif ($result -eq [SovereignClient]::WAIT_OBJECT_0) {
    Write-Host "✅ Response received!" -ForegroundColor Green
    Write-Host ""
    
    # Read response from shared memory
    # OFF_RESP_STATUS = 0x10, OFF_RESP_LEN = 0x14, OFF_RESP_PAYLOAD = 0x1018
    $respStatus = [System.Runtime.InteropServices.Marshal]::ReadInt32($pMap, 0x10)
    $respLen = [System.Runtime.InteropServices.Marshal]::ReadInt32($pMap, 0x14)
    Write-Host "Response status: $respStatus, length: $respLen bytes" -ForegroundColor Gray
    
    # Read response from offset 0x1018 (OFF_RESP_PAYLOAD)
    $respBytes = New-Object byte[] $respLen
    [System.Runtime.InteropServices.Marshal]::Copy([IntPtr]($pMap.ToInt64() + 0x1018), $respBytes, 0, $respLen)
    $response = [System.Text.Encoding]::UTF8.GetString($respBytes)
    
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  RESPONSE" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Try to parse as JSON
    try {
        $respObj = $response | ConvertFrom-Json
        if ($respObj.text) {
            Write-Host $respObj.text -ForegroundColor Green
        } else {
            Write-Host ($respObj | ConvertTo-Json -Depth 4) -ForegroundColor Green
        }
    } catch {
        Write-Host $response -ForegroundColor Green
    }
} else {
    Write-Host "❌ Wait failed with code: $result" -ForegroundColor Red
}

Write-Host ""

# Cleanup
[SovereignClient]::UnmapViewOfFile($pMap) | Out-Null
[SovereignClient]::CloseHandle($hMap) | Out-Null
if ($hCmdEvent -ne [IntPtr]::Zero) { [SovereignClient]::CloseHandle($hCmdEvent) | Out-Null }
if ($hRespEvent -ne [IntPtr]::Zero) { [SovereignClient]::CloseHandle($hRespEvent) | Out-Null }

Write-Host "✅ Cleanup complete" -ForegroundColor Green
