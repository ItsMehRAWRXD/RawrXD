# Sovereign Diagnostic v2 — Trace Inference Flow
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
$OFF_TELEM_TOKENS= 0x2020
$OFF_TELEM_PROGRESS = 0x2028
$OFF_MODEL_STATE   = 0x2030
$OFF_MAGIC_COOKIE= 0xFFF0

$BEACON_READY    = 0x01
$CMD_LOAD_MODEL  = 0x2000
$CMD_INFER       = 0x3003
$CMD_STATUS      = 0x1002
$CMD_SHUTDOWN    = 0x1003

$RESP_OK         = 0
$RESP_BUSY       = 7

Write-Host "[DIAG] Killing stale processes..."
Get-Process | Where-Object { $_.ProcessName -like "*SovereignOrchestrator*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

Write-Host "[DIAG] Starting orchestrator..."
$proc = Start-Process -FilePath $ExePath -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 3

$hMap = [NativeMethods]::OpenFileMappingA([NativeMethods]::FILE_MAP_ALL_ACCESS, $false, "SOVEREIGN_BEACON_V1")
$pMap = [NativeMethods]::MapViewOfFile($hMap, [NativeMethods]::FILE_MAP_ALL_ACCESS, 0, 0, [UIntPtr]::new(65536))
$hCmdEvent  = [NativeMethods]::OpenEventA(([NativeMethods]::EVENT_MODIFY_STATE -bor [NativeMethods]::SYNCHRONIZE), $false, "SOVEREIGN_CMD_EVENT")
$hRespEvent = [NativeMethods]::OpenEventA(([NativeMethods]::EVENT_MODIFY_STATE -bor [NativeMethods]::SYNCHRONIZE), $false, "SOVEREIGN_RESP_EVENT")

# Load model
Write-Host "`n[TEST] Loading model..."
$modelBytes = [System.Text.Encoding]::ASCII.GetBytes($ModelPath)
Write-U32 $pMap $OFF_CMD_TYPE $CMD_LOAD_MODEL
Write-U32 $pMap $OFF_PAYLOAD_LEN $modelBytes.Length
Write-Bytes $pMap $OFF_CMD_PAYLOAD $modelBytes
Write-U32 $pMap $OFF_STATE $BEACON_READY
[NativeMethods]::SetEvent($hCmdEvent) | Out-Null
$r = [NativeMethods]::WaitForSingleObject($hRespEvent, 30000)
$loadStatus = Read-U32 $pMap $OFF_RESP_STATUS
Write-Host "[TEST] Load status: $loadStatus (0=OK, 7=BUSY)"

# Check state after load
Start-Sleep -Milliseconds 500
$stateAfterLoad = Read-U32 $pMap $OFF_STATE
Write-Host "[TEST] State after load: $stateAfterLoad (0=UNLOADED, 2=READY)"

# Send inference
Write-Host "`n[TEST] Sending inference..."
$prompt = "Hello"
$promptBytes = [System.Text.Encoding]::ASCII.GetBytes($prompt)
Write-U32 $pMap $OFF_CMD_TYPE $CMD_INFER
Write-U32 $pMap $OFF_PAYLOAD_LEN $promptBytes.Length
Write-Bytes $pMap $OFF_CMD_PAYLOAD $promptBytes
Write-U32 $pMap $OFF_STATE $BEACON_READY
[NativeMethods]::SetEvent($hCmdEvent) | Out-Null

# Wait for response (should be immediate non-blocking handoff)
$r = [NativeMethods]::WaitForSingleObject($hRespEvent, 5000)
if ($r -eq [NativeMethods]::WAIT_TIMEOUT) {
    Write-Host "[TEST] ❌ INFER timeout (no response event)"
} else {
    $inferStatus = Read-U32 $pMap $OFF_RESP_STATUS
    Write-Host "[TEST] INFER response status: $inferStatus (0=OK, 7=BUSY)"
    
    if ($inferStatus -eq $RESP_OK) {
        Write-Host "[TEST] ✅ Handoff accepted"
        
        # Poll for completion (read model state from MMF)
        Write-Host "[TEST] Polling for inference completion..."
        for ($i = 0; $i -lt 50; $i++) {
            Start-Sleep -Milliseconds 100
            $modelState = Read-U32 $pMap $OFF_MODEL_STATE
            $tokens = Read-U32 $pMap $OFF_TELEM_TOKENS
            $progress = Read-U32 $pMap $OFF_TELEM_PROGRESS
            Write-Host "  [$i] modelState=$modelState tokens=$tokens progress=$progress%"
            
            if ($modelState -eq 2) {  # MODEL_STATE_READY = 2
                Write-Host "[TEST] ✅ Inference complete"
                break
            }
        }
        
        if ($modelState -ne 2) {
            Write-Host "[TEST] ❌ Inference did not complete within 5s"
        }
    } else {
        Write-Host "[TEST] ❌ INFER rejected with status $inferStatus"
    }
}

# Shutdown
Write-Host "`n[DIAG] Shutdown..."
Write-U32 $pMap $OFF_CMD_TYPE $CMD_SHUTDOWN
Write-U32 $pMap $OFF_STATE $BEACON_READY
[NativeMethods]::SetEvent($hCmdEvent) | Out-Null
Start-Sleep -Seconds 2

[NativeMethods]::UnmapViewOfFile($pMap) | Out-Null
[NativeMethods]::CloseHandle($hMap) | Out-Null
$proc | Stop-Process -Force -ErrorAction SilentlyContinue
Write-Host "[DIAG] Done."
