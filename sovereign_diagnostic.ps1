# Sovereign Diagnostic — Minimal Model Load Test
param(
    [string]$ModelPath = "F:\OllamaModels\Phi-3-mini-4k-instruct-q8_0.gguf",
    [string]$ExePath = "d:\rawrxd-ci-bootstrap\SovereignOrchestrator.exe"
)

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class NativeMethods {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenEventA(uint dwDesiredAccess, bool bInheritHandle, string lpName);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenFileMappingA(uint dwDesiredAccess, bool bInheritHandle, string lpName);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject, uint dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, UIntPtr dwNumberOfBytesToMap);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetEvent(IntPtr hEvent);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    public const uint EVENT_MODIFY_STATE = 0x0002;
    public const uint SYNCHRONIZE = 0x00100000;
    public const uint FILE_MAP_ALL_ACCESS = 0xF001F;
    public const uint WAIT_OBJECT_0 = 0;
    public const uint WAIT_TIMEOUT = 0x102;
}
"@

function Read-U32($base, $offset) {
    $buf = New-Object byte[] 4
    [System.Runtime.InteropServices.Marshal]::Copy([IntPtr]::Add($base, $offset), $buf, 0, 4)
    return [BitConverter]::ToUInt32($buf, 0)
}
function Write-U32($base, $offset, $value) {
    $buf = [BitConverter]::GetBytes([uint32]$value)
    [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, [IntPtr]::Add($base, $offset), 4)
}
function Write-Bytes($base, $offset, $bytes) {
    [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, [IntPtr]::Add($base, $offset), $bytes.Length)
}

$OFF_STATE       = 0x00
$OFF_CMD_TYPE    = 0x08
$OFF_PAYLOAD_LEN = 0x0C
$OFF_RESP_STATUS = 0x10
$OFF_RESP_LEN    = 0x14
$OFF_CMD_PAYLOAD = 0x18
$OFF_MAGIC_COOKIE= 0xFFF0

$BEACON_READY    = 0x01
$CMD_LOAD_MODEL  = 0x2000
$CMD_STATUS      = 0x1002
$CMD_SHUTDOWN    = 0x1003

$RESP_OK         = 0
$RESP_BUSY       = 7

Write-Host "[DIAG] Killing any existing SovereignOrchestrator processes..."
Get-Process | Where-Object { $_.ProcessName -like "*SovereignOrchestrator*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

Write-Host "[DIAG] Starting orchestrator..."
$proc = Start-Process -FilePath $ExePath -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 3

Write-Host "[DIAG] Opening MMF..."
$hMap = [NativeMethods]::OpenFileMappingA([NativeMethods]::FILE_MAP_ALL_ACCESS, $false, "SOVEREIGN_BEACON_V1")
if ($hMap -eq [IntPtr]::Zero) {
    Write-Error "Failed to open MMF"
    $proc | Stop-Process -Force
    exit 1
}

$pMap = [NativeMethods]::MapViewOfFile($hMap, [NativeMethods]::FILE_MAP_ALL_ACCESS, 0, 0, [UIntPtr]::new(65536))
if ($pMap -eq [IntPtr]::Zero) {
    Write-Error "Failed to map view"
    [NativeMethods]::CloseHandle($hMap) | Out-Null
    $proc | Stop-Process -Force
    exit 1
}

$hCmdEvent  = [NativeMethods]::OpenEventA(([NativeMethods]::EVENT_MODIFY_STATE -bor [NativeMethods]::SYNCHRONIZE), $false, "SOVEREIGN_CMD_EVENT")
$hRespEvent = [NativeMethods]::OpenEventA(([NativeMethods]::EVENT_MODIFY_STATE -bor [NativeMethods]::SYNCHRONIZE), $false, "SOVEREIGN_RESP_EVENT")

$cookie = Read-U32 $pMap $OFF_MAGIC_COOKIE
Write-Host "[DIAG] Magic cookie: 0x$($cookie.ToString('X8'))"

$state = Read-U32 $pMap $OFF_STATE
Write-Host "[DIAG] Initial state: $state"

# Test 1: STATUS command
Write-Host "`n[TEST 1] Sending STATUS command..."
Write-U32 $pMap $OFF_CMD_TYPE $CMD_STATUS
Write-U32 $pMap $OFF_STATE $BEACON_READY
[NativeMethods]::SetEvent($hCmdEvent) | Out-Null
$r = [NativeMethods]::WaitForSingleObject($hRespEvent, 5000)
if ($r -eq [NativeMethods]::WAIT_TIMEOUT) {
    Write-Error "STATUS timeout"
} else {
    $status = Read-U32 $pMap $OFF_RESP_STATUS
    $len = Read-U32 $pMap $OFF_RESP_LEN
    Write-Host "[TEST 1] STATUS response: status=$status len=$len"
    
    $buf = New-Object byte[] $len
    [System.Runtime.InteropServices.Marshal]::Copy([IntPtr]::Add($pMap, $OFF_CMD_PAYLOAD), $buf, 0, $len)
    $json = [System.Text.Encoding]::ASCII.GetString($buf)
    Write-Host "[TEST 1] Response JSON: $json"
}

# Test 2: LOAD MODEL command
Write-Host "`n[TEST 2] Sending LOAD MODEL command..."
Write-Host "[TEST 2] Model path: $ModelPath"
$modelBytes = [System.Text.Encoding]::ASCII.GetBytes($ModelPath)
Write-U32 $pMap $OFF_CMD_TYPE $CMD_LOAD_MODEL
Write-U32 $pMap $OFF_PAYLOAD_LEN $modelBytes.Length
Write-Bytes $pMap $OFF_CMD_PAYLOAD $modelBytes
Write-U32 $pMap $OFF_STATE $BEACON_READY
[NativeMethods]::SetEvent($hCmdEvent) | Out-Null

$r = [NativeMethods]::WaitForSingleObject($hRespEvent, 30000)
if ($r -eq [NativeMethods]::WAIT_TIMEOUT) {
    Write-Error "LOAD MODEL timeout"
} else {
    $status = Read-U32 $pMap $OFF_RESP_STATUS
    $len = Read-U32 $pMap $OFF_RESP_LEN
    Write-Host "[TEST 2] LOAD response: status=$status len=$len"
    
    if ($status -eq $RESP_OK) {
        $buf = New-Object byte[] $len
        [System.Runtime.InteropServices.Marshal]::Copy([IntPtr]::Add($pMap, $OFF_CMD_PAYLOAD), $buf, 0, $len)
        $json = [System.Text.Encoding]::ASCII.GetString($buf)
        Write-Host "[TEST 2] Response JSON: $json"
        Write-Host "[TEST 2] ✅ Model loaded successfully"
    } elseif ($status -eq $RESP_BUSY) {
        Write-Host "[TEST 2] ❌ Model load returned BUSY (state not UNLOADED)"
        $state2 = Read-U32 $pMap $OFF_STATE
        Write-Host "[TEST 2] Current MMF state: $state2"
    } else {
        Write-Host "[TEST 2] ❌ Model load failed with status $status"
    }
}

# Shutdown
Write-Host "`n[DIAG] Sending SHUTDOWN..."
Write-U32 $pMap $OFF_CMD_TYPE $CMD_SHUTDOWN
Write-U32 $pMap $OFF_STATE $BEACON_READY
[NativeMethods]::SetEvent($hCmdEvent) | Out-Null
Start-Sleep -Seconds 2

# Cleanup
[NativeMethods]::UnmapViewOfFile($pMap) | Out-Null
[NativeMethods]::CloseHandle($hMap) | Out-Null
$proc | Stop-Process -Force -ErrorAction SilentlyContinue
Write-Host "`n[DIAG] Done."
