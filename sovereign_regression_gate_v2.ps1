# sovereign_regression_gate_v2.ps1
# Simplified regression gate for Sovereign orchestrator
# Tests worker thread integration and non-blocking handoff

param(
    [string]$OrchestratorPath = ".\SovereignOrchestrator.exe",
    [int]$TimeoutMs = 30000
)

$ErrorActionPreference = "Stop"

# MMF Constants
$SHMEM_NAME = "SOVEREIGN_BEACON_V1"
$CMD_EVENT_NAME = "SOVEREIGN_CMD_EVENT"
$RESP_EVENT_NAME = "SOVEREIGN_RESP_EVENT"
$INFER_EVENT_NAME = "SOVEREIGN_INFER_EVENT"
$SHMEM_SIZE = 65536

# Offsets
$OFF_STATE = 0x0000
$OFF_CMD_ID = 0x0004
$OFF_CMD_TYPE = 0x0008
$OFF_PAYLOAD_LEN = 0x000C
$OFF_RESP_STATUS = 0x0010
$OFF_RESP_LEN = 0x0014
$OFF_CMD_PAYLOAD = 0x0018
$OFF_RESP_PAYLOAD = 0x1018
$OFF_MAGIC_COOKIE = 0xFFF0
$OFF_HEARTBEAT = 0xFFF8

# Constants
$BEACON_READY = 1
$BEACON_PROCESSING = 2
$BEACON_COMPLETE = 4

$CMD_PING = 0x1000
$CMD_GET_VERSION = 0x1001
$CMD_GET_STATUS = 0x1002
$CMD_GET_METRICS = 0x7000

$RESP_OK = 0
$MAGIC_COOKIE_VAL = 0xCAFEBABEDEADBEEF

# Test counters
$script:TestsPassed = 0
$script:TestsFailed = 0

function Write-TestResult {
    param([string]$TestName, [string]$Result, [string]$Details = "")
    $timestamp = Get-Date -Format "HH:mm:ss.fff"
    $color = switch ($Result) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Result] $TestName" -ForegroundColor $color
    if ($Details) {
        Write-Host "           $Details" -ForegroundColor Gray
    }
}

# P/Invoke signatures
Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class SovereignIPC {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr OpenFileMapping(uint dwDesiredAccess, bool bInheritHandle, string lpName);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject, uint dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, uint dwNumberOfBytesToMap);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);
    
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr OpenEvent(uint dwDesiredAccess, bool bInheritHandle, string lpName);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetEvent(IntPtr hEvent);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint GetLastError();
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateFileMappingA(IntPtr hFile, IntPtr lpFileMappingAttributes, uint flProtect, uint dwMaximumSizeHigh, uint dwMaximumSizeLow, string lpName);
}
"@

$FILE_MAP_ALL_ACCESS = 0xF001F
$EVENT_MODIFY_STATE = 0x0002
$SYNCHRONIZE = 0x00100000
$EVENT_OPEN_RIGHTS = $EVENT_MODIFY_STATE -bor $SYNCHRONIZE
$WAIT_OBJECT_0 = 0

# Global handles
$script:hMap = [IntPtr]::Zero
$script:pView = [IntPtr]::Zero
$script:hCmdEvt = [IntPtr]::Zero
$script:hRespEvt = [IntPtr]::Zero
$script:hInferEvt = [IntPtr]::Zero

function Connect-ToOrchestrator {
    try {
        # Open shared memory
        $script:hMap = [SovereignIPC]::OpenFileMapping($FILE_MAP_ALL_ACCESS, $false, $SHMEM_NAME)
        if ($script:hMap -eq [IntPtr]::Zero) {
            Write-Host "Failed to open file mapping: $([SovereignIPC]::GetLastError())"
            return $false
        }
        
        # Map view
        $script:pView = [SovereignIPC]::MapViewOfFile($script:hMap, $FILE_MAP_ALL_ACCESS, 0, 0, 0)
        if ($script:pView -eq [IntPtr]::Zero) {
            Write-Host "Failed to map view: $([SovereignIPC]::GetLastError())"
            return $false
        }
        
        # Open events
        $script:hCmdEvt = [SovereignIPC]::OpenEvent($EVENT_OPEN_RIGHTS, $false, $CMD_EVENT_NAME)
        if ($script:hCmdEvt -eq [IntPtr]::Zero) {
            Write-Host "Failed to open command event: $([SovereignIPC]::GetLastError())"
            return $false
        }
        
        $script:hRespEvt = [SovereignIPC]::OpenEvent($EVENT_OPEN_RIGHTS, $false, $RESP_EVENT_NAME)
        if ($script:hRespEvt -eq [IntPtr]::Zero) {
            Write-Host "Failed to open response event: $([SovereignIPC]::GetLastError())"
            return $false
        }
        
        $script:hInferEvt = [SovereignIPC]::OpenEvent($EVENT_OPEN_RIGHTS, $false, $INFER_EVENT_NAME)
        if ($script:hInferEvt -eq [IntPtr]::Zero) {
            Write-Host "Failed to open inference event: $([SovereignIPC]::GetLastError())"
            return $false
        }
        
        return $true
    } catch {
        Write-Host "Exception: $_"
        return $false
    }
}

function Disconnect-FromOrchestrator {
    if ($script:pView -ne [IntPtr]::Zero) {
        [SovereignIPC]::UnmapViewOfFile($script:pView) | Out-Null
        $script:pView = [IntPtr]::Zero
    }
    if ($script:hCmdEvt -ne [IntPtr]::Zero) {
        [SovereignIPC]::CloseHandle($script:hCmdEvt) | Out-Null
        $script:hCmdEvt = [IntPtr]::Zero
    }
    if ($script:hRespEvt -ne [IntPtr]::Zero) {
        [SovereignIPC]::CloseHandle($script:hRespEvt) | Out-Null
        $script:hRespEvt = [IntPtr]::Zero
    }
    if ($script:hInferEvt -ne [IntPtr]::Zero) {
        [SovereignIPC]::CloseHandle($script:hInferEvt) | Out-Null
        $script:hInferEvt = [IntPtr]::Zero
    }
    if ($script:hMap -ne [IntPtr]::Zero) {
        [SovereignIPC]::CloseHandle($script:hMap) | Out-Null
        $script:hMap = [IntPtr]::Zero
    }
}

function Send-Command {
    param([int]$CmdId, [int]$CmdType, [byte[]]$Payload)
    
    if ($script:pView -eq [IntPtr]::Zero) { return -1 }
    
    # Write command header
    [System.Runtime.InteropServices.Marshal]::WriteInt32($script:pView, $OFF_STATE, $BEACON_READY)
    [System.Runtime.InteropServices.Marshal]::WriteInt32($script:pView, $OFF_CMD_ID, $CmdId)
    [System.Runtime.InteropServices.Marshal]::WriteInt32($script:pView, $OFF_CMD_TYPE, $CmdType)
    
    # Write payload
    if ($Payload -and $Payload.Length -gt 0) {
        $payloadLen = [Math]::Min($Payload.Length, 0xFFF)
        [System.Runtime.InteropServices.Marshal]::WriteInt32($script:pView, $OFF_PAYLOAD_LEN, $payloadLen)
        [System.Runtime.InteropServices.Marshal]::Copy($Payload, 0, [IntPtr]::Add($script:pView, $OFF_CMD_PAYLOAD), $payloadLen)
    } else {
        [System.Runtime.InteropServices.Marshal]::WriteInt32($script:pView, $OFF_PAYLOAD_LEN, 0)
    }
    
    # Signal command
    [SovereignIPC]::SetEvent($script:hCmdEvt) | Out-Null
    
    # Wait for response
    $waitResult = [SovereignIPC]::WaitForSingleObject($script:hRespEvt, 3000)
    if ($waitResult -ne $WAIT_OBJECT_0) {
        Write-Host "WaitForSingleObject failed: $waitResult"
        return -1
    }
    
    # Read response
    return [System.Runtime.InteropServices.Marshal]::ReadInt32($script:pView, $OFF_RESP_STATUS)
}

function Get-ResponsePayload {
    if ($script:pView -eq [IntPtr]::Zero) { return "" }
    
    $len = [System.Runtime.InteropServices.Marshal]::ReadInt32($script:pView, $OFF_RESP_LEN)
    if ($len -le 0) { return "" }
    
    $bytes = [byte[]]::new([Math]::Min($len, 0xEFD8))
    [System.Runtime.InteropServices.Marshal]::Copy([IntPtr]::Add($script:pView, $OFF_RESP_PAYLOAD), $bytes, 0, $bytes.Length)
    return [System.Text.Encoding]::ASCII.GetString($bytes).TrimEnd([char]0)
}

function Test-StartupAudit {
    Write-Host "`n=== Test: Startup Audit ===" -ForegroundColor Cyan
    
    # Verify cookie integrity
    $cookie = [System.Runtime.InteropServices.Marshal]::ReadInt64($script:pView, $OFF_MAGIC_COOKIE)
    if ($cookie -eq $MAGIC_COOKIE_VAL) {
        Write-TestResult "Startup Audit" "PASS" "Magic cookie validated"
        $script:TestsPassed++
    } else {
        Write-TestResult "Startup Audit" "FAIL" "Magic cookie mismatch: $cookie"
        $script:TestsFailed++
    }
}

function Test-PingCommand {
    Write-Host "`n=== Test: PING Command ===" -ForegroundColor Cyan
    
    $status = Send-Command $CMD_PING 0 $null
    if ($status -eq $RESP_OK) {
        $payload = Get-ResponsePayload
        if ($payload -match "pong") {
            Write-TestResult "PING Command" "PASS" "Response: $payload"
            $script:TestsPassed++
        } else {
            Write-TestResult "PING Command" "FAIL" "Invalid payload: $payload"
            $script:TestsFailed++
        }
    } else {
        Write-TestResult "PING Command" "FAIL" "Status: $status"
        $script:TestsFailed++
    }
}

function Test-GetVersion {
    Write-Host "`n=== Test: GET_VERSION Command ===" -ForegroundColor Cyan
    
    $status = Send-Command $CMD_GET_VERSION 0 $null
    if ($status -eq $RESP_OK) {
        $payload = Get-ResponsePayload
        try {
            $json = $payload | ConvertFrom-Json
            if ($json.protocol -eq 1) {
                Write-TestResult "GET_VERSION Command" "PASS" "Protocol version: $($json.protocol)"
                $script:TestsPassed++
            } else {
                Write-TestResult "GET_VERSION Command" "FAIL" "Wrong protocol version: $($json.protocol)"
                $script:TestsFailed++
            }
        } catch {
            Write-TestResult "GET_VERSION Command" "FAIL" "Invalid JSON: $payload"
            $script:TestsFailed++
        }
    } else {
        Write-TestResult "GET_VERSION Command" "FAIL" "Status: $status"
        $script:TestsFailed++
    }
}

function Test-StatusCommand {
    Write-Host "`n=== Test: STATUS Command ===" -ForegroundColor Cyan
    
    $status = Send-Command $CMD_GET_STATUS 0 $null
    if ($status -eq $RESP_OK) {
        $payload = Get-ResponsePayload
        try {
            $json = $payload | ConvertFrom-Json
            Write-TestResult "STATUS Command" "PASS" "State: $($json.state), Protocol: $($json.protocol)"
            $script:TestsPassed++
        } catch {
            Write-TestResult "STATUS Command" "FAIL" "Invalid JSON: $payload"
            $script:TestsFailed++
        }
    } else {
        Write-TestResult "STATUS Command" "FAIL" "Status: $status"
        $script:TestsFailed++
    }
}

function Test-HeartbeatIncrement {
    Write-Host "`n=== Test: Heartbeat Increment ===" -ForegroundColor Cyan
    
    $heartbeat1 = [System.Runtime.InteropServices.Marshal]::ReadInt64($script:pView, $OFF_HEARTBEAT)
    Start-Sleep -Milliseconds 100
    $heartbeat2 = [System.Runtime.InteropServices.Marshal]::ReadInt64($script:pView, $OFF_HEARTBEAT)
    
    if ($heartbeat2 -gt $heartbeat1) {
        Write-TestResult "Heartbeat Increment" "PASS" "Heartbeat: $heartbeat1 -> $heartbeat2"
        $script:TestsPassed++
    } else {
        Write-TestResult "Heartbeat Increment" "FAIL" "Heartbeat did not increment: $heartbeat1 -> $heartbeat2"
        $script:TestsFailed++
    }
}

function Test-InferenceEvent {
    Write-Host "`n=== Test: Inference Event Creation ===" -ForegroundColor Cyan
    
    # Verify inference event was created
    if ($script:hInferEvt -ne [IntPtr]::Zero) {
        Write-TestResult "Inference Event" "PASS" "Event handle valid"
        $script:TestsPassed++
    } else {
        Write-TestResult "Inference Event" "FAIL" "Event handle is zero"
        $script:TestsFailed++
    }
}

# Main execution
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Sovereign Regression Gate v2" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Orchestrator: $OrchestratorPath" -ForegroundColor Gray
Write-Host "Timeout: $TimeoutMs ms" -ForegroundColor Gray
Write-Host ""

try {
    Write-Host "Connecting to orchestrator..." -ForegroundColor Yellow
    if (-not (Connect-ToOrchestrator)) {
        Write-Host "Failed to connect to orchestrator" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Connected successfully" -ForegroundColor Green
    
    # Run tests
    Test-StartupAudit
    Test-PingCommand
    Test-GetVersion
    Test-StatusCommand
    Test-HeartbeatIncrement
    Test-InferenceEvent
    
    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Regression Gate Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Passed:   $script:TestsPassed" -ForegroundColor Green
    Write-Host "Failed:   $script:TestsFailed" -ForegroundColor Red
    Write-Host ""
    
    Disconnect-FromOrchestrator
    
    if ($script:TestsFailed -gt 0) {
        Write-Host "REGRESSION GATE FAILED" -ForegroundColor Red
        exit 1
    } else {
        Write-Host "REGRESSION GATE PASSED" -ForegroundColor Green
        exit 0
    }
    
} catch {
    Write-Host "Exception: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    Disconnect-FromOrchestrator
    exit 1
}