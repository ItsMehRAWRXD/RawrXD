# sovereign_regression_gate.ps1
# Comprehensive regression gate for Sovereign orchestrator
# Tests LOAD_MODEL, METRICS, INFER paths (happy and negative paths)
# Validates non-blocking handoff pattern for inference

param(
    [string]$OrchestratorPath = ".\SovereignOrchestrator_Hardened.exe",
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
$BEACON_SHUTDOWN = 0xFF

$CMD_PING = 0x1000
$CMD_GET_VERSION = 0x1001
$CMD_GET_STATUS = 0x1002
$CMD_SHUTDOWN = 0x1003
$CMD_GET_HEARTBEAT = 0x1005

$CMD_LOAD_MODEL = 0x2000
$CMD_UNLOAD_MODEL = 0x2001
$CMD_GET_MODEL_INFO = 0x2003

$CMD_INFER = 0x3003
$CMD_CANCEL_INFER = 0x3005

$CMD_GET_METRICS = 0x7000

$RESP_OK = 0
$RESP_UNKNOWN_CMD = 1
$RESP_INVALID_PAYLOAD = 2
$RESP_TIMEOUT = 3
$RESP_INTERNAL_ERROR = 4
$RESP_NOT_READY = 5
$RESP_MODEL_NOT_LOADED = 6
$RESP_BUSY = 7

$MODEL_STATE_UNLOADED = 0
$MODEL_STATE_LOADING = 1
$MODEL_STATE_READY = 2
$MODEL_STATE_INFERENCE_ACTIVE = 3

$MAGIC_COOKIE_VAL = 0xCAFEBABEDEADBEEF

# Test counters
$script:TestsPassed = 0
$script:TestsFailed = 0
$script:TestsSkipped = 0

function Write-TestResult {
    param([string]$TestName, [string]$Result, [string]$Details = "")
    $timestamp = Get-Date -Format "HH:mm:ss.fff"
    $color = switch ($Result) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "SKIP" { "Yellow" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Result] $TestName" -ForegroundColor $color
    if ($Details) {
        Write-Host "           $Details" -ForegroundColor Gray
    }
}

function Test-JsonValid {
    param([string]$JsonStr)
    try {
        $null = ConvertFrom-Json $JsonStr -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Get-StateName {
    param([int]$State)
    switch ($State) {
        $MODEL_STATE_UNLOADED { "UNLOADED" }
        $MODEL_STATE_LOADING { "LOADING" }
        $MODEL_STATE_READY { "READY" }
        $MODEL_STATE_INFERENCE_ACTIVE { "INFERENCE_ACTIVE" }
        default { "UNKNOWN($State)" }
    }
}

# P/Invoke signatures
Add-Type @"
using System;
using System.Runtime.InteropServices;

public class SovereignIPC {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenFileMapping(uint dwDesiredAccess, bool bInheritHandle, string lpName);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject, uint dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, uint dwNumberOfBytesToMap);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenEvent(uint dwDesiredAccess, bool bInheritHandle, string lpName);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetEvent(IntPtr hEvent);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint GetLastError();
}
"@

$FILE_MAP_ALL_ACCESS = 0xF001F
$EVENT_MODIFY_STATE = 0x0002
$SYNCHRONIZE = 0x00100000
$EVENT_OPEN_RIGHTS = $EVENT_MODIFY_STATE -bor $SYNCHRONIZE
$WAIT_OBJECT_0 = 0
$WAIT_TIMEOUT = 0x102

class SovereignClient : IDisposable {
    [IntPtr]$hMap
    [IntPtr]$pView
    [IntPtr]$hCmdEvt
    [IntPtr]$hRespEvt
    [IntPtr]$hInferEvt
    [bool]$Connected
    
    SovereignClient() {
        $this.Connected = $false
    }
    
    [bool] Connect() {
        # Open shared memory
        $this.hMap = [SovereignIPC]::OpenFileMapping($FILE_MAP_ALL_ACCESS, $false, $SHMEM_NAME)
        if ($this.hMap -eq [IntPtr]::Zero) {
            Write-Host "Failed to open file mapping: $([SovereignIPC]::GetLastError())"
            return $false
        }
        
        # Map view
        $this.pView = [SovereignIPC]::MapViewOfFile($this.hMap, $FILE_MAP_ALL_ACCESS, 0, 0, 0)
        if ($this.pView -eq [IntPtr]::Zero) {
            Write-Host "Failed to map view: $([SovereignIPC]::GetLastError())"
            return $false
        }
        
        # Open events
        $this.hCmdEvt = [SovereignIPC]::OpenEvent($EVENT_OPEN_RIGHTS, $false, $CMD_EVENT_NAME)
        if ($this.hCmdEvt -eq [IntPtr]::Zero) {
            Write-Host "Failed to open command event: $([SovereignIPC]::GetLastError())"
            return $false
        }
        
        $this.hRespEvt = [SovereignIPC]::OpenEvent($EVENT_OPEN_RIGHTS, $false, $RESP_EVENT_NAME)
        if ($this.hRespEvt -eq [IntPtr]::Zero) {
            Write-Host "Failed to open response event: $([SovereignIPC]::GetLastError())"
            return $false
        }
        
        $this.hInferEvt = [SovereignIPC]::OpenEvent($EVENT_OPEN_RIGHTS, $false, $INFER_EVENT_NAME)
        if ($this.hInferEvt -eq [IntPtr]::Zero) {
            Write-Host "Failed to open inference event: $([SovereignIPC]::GetLastError())"
            return $false
        }
        
        $this.Connected = $true
        return $true
    }
    
    [int] SendCommand([int]$CmdId, [int]$CmdType, [byte[]]$Payload) {
        if (-not $this.Connected) { return -1 }
        
        # Write command header
        [System.Runtime.InteropServices.Marshal]::WriteInt32($this.pView, $OFF_STATE, $BEACON_READY)
        [System.Runtime.InteropServices.Marshal]::WriteInt32($this.pView, $OFF_CMD_ID, $CmdId)
        [System.Runtime.InteropServices.Marshal]::WriteInt32($this.pView, $OFF_CMD_TYPE, $CmdType)
        
        # Write payload
        if ($Payload -and $Payload.Length -gt 0) {
            $payloadLen = [Math]::Min($Payload.Length, 0xFFF)
            [System.Runtime.InteropServices.Marshal]::WriteInt32($this.pView, $OFF_PAYLOAD_LEN, $payloadLen)
            [System.Runtime.InteropServices.Marshal]::Copy($Payload, 0, [IntPtr]::Add($this.pView, $OFF_CMD_PAYLOAD), $payloadLen)
        } else {
            [System.Runtime.InteropServices.Marshal]::WriteInt32($this.pView, $OFF_PAYLOAD_LEN, 0)
        }
        
        # Signal command
        $null = [SovereignIPC]::SetEvent($this.hCmdEvt)
        
        # Wait for response
        $waitResult = [SovereignIPC]::WaitForSingleObject($this.hRespEvt, 3000)
        if ($waitResult -ne $WAIT_OBJECT_0) {
            Write-Host "WaitForSingleObject failed: $waitResult"
            return -1
        }
        
        # Read response
        $status = [System.Runtime.InteropServices.Marshal]::ReadInt32($this.pView, $OFF_RESP_STATUS)
        return $status
    }
    
    [int] GetResponseStatus() {
        return [System.Runtime.InteropServices.Marshal]::ReadInt32($this.pView, $OFF_RESP_STATUS)
    }
    
    [int] GetResponseLength() {
        return [System.Runtime.InteropServices.Marshal]::ReadInt32($this.pView, $OFF_RESP_LEN)
    }
    
    [string] GetResponsePayload() {
        $len = $this.GetResponseLength()
        if ($len -le 0) { return "" }
        
        $bytes = [byte[]]::new([Math]::Min($len, 0xEFD8))
        [System.Runtime.InteropServices.Marshal]::Copy([IntPtr]::Add($this.pView, $OFF_RESP_PAYLOAD), $bytes, 0, $bytes.Length)
        return [System.Text.Encoding]::ASCII.GetString($bytes).TrimEnd([char]0)
    }
    
    [long] GetHeartbeat() {
        return [System.Runtime.InteropServices.Marshal]::ReadInt64($this.pView, $OFF_HEARTBEAT)
    }
    
    [bool] ValidateCookie() {
        $cookie = [System.Runtime.InteropServices.Marshal]::ReadInt64($this.pView, $OFF_MAGIC_COOKIE)
        return $cookie -eq $MAGIC_COOKIE_VAL
    }
    
    [void] Dispose() {
        if ($this.pView -ne [IntPtr]::Zero) {
            $null = [SovereignIPC]::UnmapViewOfFile($this.pView)
            $this.pView = [IntPtr]::Zero
        }
        if ($this.hCmdEvt -ne [IntPtr]::Zero) {
            $null = [SovereignIPC]::CloseHandle($this.hCmdEvt)
            $this.hCmdEvt = [IntPtr]::Zero
        }
        if ($this.hRespEvt -ne [IntPtr]::Zero) {
            $null = [SovereignIPC]::CloseHandle($this.hRespEvt)
            $this.hRespEvt = [IntPtr]::Zero
        }
        if ($this.hInferEvt -ne [IntPtr]::Zero) {
            $null = [SovereignIPC]::CloseHandle($this.hInferEvt)
            $this.hInferEvt = [IntPtr]::Zero
        }
        if ($this.hMap -ne [IntPtr]::Zero) {
            $null = [SovereignIPC]::CloseHandle($this.hMap)
            $this.hMap = [IntPtr]::Zero
        }
        $this.Connected = $false
    }
}

# Test functions
function Test-StartupAudit {
    param([SovereignClient]$Client)
    
    Write-Host "`n=== Test: Startup Audit ===" -ForegroundColor Cyan
    
    # Verify cookie integrity
    if ($Client.ValidateCookie()) {
        Write-TestResult "Startup Audit" "PASS" "Magic cookie validated"
        $script:TestsPassed++
    } else {
        Write-TestResult "Startup Audit" "FAIL" "Magic cookie mismatch"
        $script:TestsFailed++
    }
}

function Test-PingCommand {
    param([SovereignClient]$Client)
    
    Write-Host "`n=== Test: PING Command ===" -ForegroundColor Cyan
    
    $status = $Client.SendCommand($CMD_PING, 0, $null)
    if ($status -eq $RESP_OK) {
        $payload = $Client.GetResponsePayload()
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
    param([SovereignClient]$Client)
    
    Write-Host "`n=== Test: GET_VERSION Command ===" -ForegroundColor Cyan
    
    $status = $Client.SendCommand($CMD_GET_VERSION, 0, $null)
    if ($status -eq $RESP_OK) {
        $payload = $Client.GetResponsePayload()
        if (Test-JsonValid $payload) {
            $json = $payload | ConvertFrom-Json
            if ($json.protocol -eq 1) {
                Write-TestResult "GET_VERSION Command" "PASS" "Protocol version: $($json.protocol)"
                $script:TestsPassed++
            } else {
                Write-TestResult "GET_VERSION Command" "FAIL" "Wrong protocol version: $($json.protocol)"
                $script:TestsFailed++
            }
        } else {
            Write-TestResult "GET_VERSION Command" "FAIL" "Invalid JSON: $payload"
            $script:TestsFailed++
        }
    } else {
        Write-TestResult "GET_VERSION Command" "FAIL" "Status: $status"
        $script:TestsFailed++
    }
}

function Test-StatusCommand {
    param([SovereignClient]$Client)
    
    Write-Host "`n=== Test: STATUS Command ===" -ForegroundColor Cyan
    
    $status = $Client.SendCommand($CMD_GET_STATUS, 0, $null)
    if ($status -eq $RESP_OK) {
        $payload = $Client.GetResponsePayload()
        if (Test-JsonValid $payload) {
            $json = $payload | ConvertFrom-Json
            $stateName = $json.state
            Write-TestResult "STATUS Command" "PASS" "State: $stateName, Protocol: $($json.protocol)"
            $script:TestsPassed++
        } else {
            Write-TestResult "STATUS Command" "FAIL" "Invalid JSON: $payload"
            $script:TestsFailed++
        }
    } else {
        Write-TestResult "STATUS Command" "FAIL" "Status: $status"
        $script:TestsFailed++
    }
}

function Test-MetricsCommand {
    param([SovereignClient]$Client)
    
    Write-Host "`n=== Test: METRICS Command ===" -ForegroundColor Cyan
    
    $status = $Client.SendCommand($CMD_GET_METRICS, 0, $null)
    if ($status -eq $RESP_OK) {
        $payload = $Client.GetResponsePayload()
        if (Test-JsonValid $payload) {
            $json = $payload | ConvertFrom-Json
            Write-TestResult "METRICS Command" "PASS" "State: $($json.state), Heartbeat: $($json.heartbeat_hex)"
            $script:TestsPassed++
        } else {
            Write-TestResult "METRICS Command" "FAIL" "Invalid JSON: $payload"
            $script:TestsFailed++
        }
    } else {
        Write-TestResult "METRICS Command" "FAIL" "Status: $status"
        $script:TestsFailed++
    }
}

function Test-LoadModelHappyPath {
    param([SovereignClient]$Client)
    
    Write-Host "`n=== Test: LOAD_MODEL Happy Path ===" -ForegroundColor Cyan
    
    # First ensure we're in UNLOADED state
    $status = $Client.SendCommand($CMD_GET_STATUS, 0, $null)
    $payload = $Client.GetResponsePayload()
    $json = $payload | ConvertFrom-Json
    
    if ($json.state -ne "UNLOADED") {
        Write-TestResult "LOAD_MODEL Happy Path" "SKIP" "Model already loaded (state: $($json.state))"
        $script:TestsSkipped++
        return
    }
    
    # Send LOAD_MODEL with valid path
    $modelPath = "test_model.gguf"
    $pathBytes = [System.Text.Encoding]::ASCII.GetBytes($modelPath)
    
    $status = $Client.SendCommand($CMD_LOAD_MODEL, 0, $pathBytes)
    if ($status -eq $RESP_OK) {
        $payload = $Client.GetResponsePayload()
        if (Test-JsonValid $payload) {
            $json = $payload | ConvertFrom-Json
            if ($json.status -eq "ready") {
                Write-TestResult "LOAD_MODEL Happy Path" "PASS" "Model loaded successfully"
                $script:TestsPassed++
            } else {
                Write-TestResult "LOAD_MODEL Happy Path" "FAIL" "Unexpected status: $($json.status)"
                $script:TestsFailed++
            }
        } else {
            Write-TestResult "LOAD_MODEL Happy Path" "FAIL" "Invalid JSON: $payload"
            $script:TestsFailed++
        }
    } else {
        Write-TestResult "LOAD_MODEL Happy Path" "FAIL" "Status: $status"
        $script:TestsFailed++
    }
}

function Test-LoadModelNegativePath {
    param([SovereignClient]$Client)
    
    Write-Host "`n=== Test: LOAD_MODEL Negative Paths ===" -ForegroundColor Cyan
    
    # Test 1: Zero-length payload
    $status = $Client.SendCommand($CMD_LOAD_MODEL, 0, $null)
    if ($status -eq $RESP_INVALID_PAYLOAD) {
        Write-TestResult "LOAD_MODEL Zero Payload" "PASS" "Correctly rejected zero-length payload"
        $script:TestsPassed++
    } else {
        Write-TestResult "LOAD_MODEL Zero Payload" "FAIL" "Expected INVALID_PAYLOAD, got: $status"
        $script:TestsFailed++
    }
    
    # Test 2: Load when already loaded (BUSY)
    # First check current state
    $status = $Client.SendCommand($CMD_GET_STATUS, 0, $null)
    $payload = $Client.GetResponsePayload()
    $json = $payload | ConvertFrom-Json
    
    if ($json.state -eq "READY" -or $json.state -eq "INFERENCE_ACTIVE") {
        $modelPath = "test_model.gguf"
        $pathBytes = [System.Text.Encoding]::ASCII.GetBytes($modelPath)
        $status = $Client.SendCommand($CMD_LOAD_MODEL, 0, $pathBytes)
        if ($status -eq $RESP_BUSY) {
            Write-TestResult "LOAD_MODEL Double Load" "PASS" "Correctly rejected double load (BUSY)"
            $script:TestsPassed++
        } else {
            Write-TestResult "LOAD_MODEL Double Load" "FAIL" "Expected BUSY, got: $status"
            $script:TestsFailed++
        }
    } else {
        Write-TestResult "LOAD_MODEL Double Load" "SKIP" "Model not loaded, cannot test double load"
        $script:TestsSkipped++
    }
}

function Test-InferHappyPath {
    param([SovereignClient]$Client)
    
    Write-Host "`n=== Test: INFER Happy Path (Non-Blocking Handoff) ===" -ForegroundColor Cyan
    
    # Ensure model is loaded
    $status = $Client.SendCommand($CMD_GET_STATUS, 0, $null)
    $payload = $Client.GetResponsePayload()
    $json = $payload | ConvertFrom-Json
    
    if ($json.state -ne "READY") {
        Write-TestResult "INFER Happy Path" "SKIP" "Model not ready (state: $($json.state))"
        $script:TestsSkipped++
        return
    }
    
    # Send inference request
    $prompt = "Hello, world!"
    $promptBytes = [System.Text.Encoding]::ASCII.GetBytes($prompt)
    
    $status = $Client.SendCommand($CMD_INFER, 0, $promptBytes)
    if ($status -eq $RESP_OK) {
        $payload = $Client.GetResponsePayload()
        if (Test-JsonValid $payload) {
            $json = $payload | ConvertFrom-Json
            if ($json.status -eq "ready") {
                Write-TestResult "INFER Happy Path" "PASS" "Non-blocking handoff successful"
                $script:TestsPassed++
            } else {
                Write-TestResult "INFER Happy Path" "FAIL" "Unexpected status: $($json.status)"
                $script:TestsFailed++
            }
        } else {
            Write-TestResult "INFER Happy Path" "FAIL" "Invalid JSON: $payload"
            $script:TestsFailed++
        }
    } else {
        Write-TestResult "INFER Happy Path" "FAIL" "Status: $status"
        $script:TestsFailed++
    }
}

function Test-InferNegativePath {
    param([SovereignClient]$Client)
    
    Write-Host "`n=== Test: INFER Negative Paths ===" -ForegroundColor Cyan
    
    # Test 1: INFER when UNLOADED
    # First unload model
    $status = $Client.SendCommand($CMD_UNLOAD_MODEL, 0, $null)
    Start-Sleep -Milliseconds 100
    
    $status = $Client.SendCommand($CMD_GET_STATUS, 0, $null)
    $payload = $Client.GetResponsePayload()
    $json = $payload | ConvertFrom-Json
    
    if ($json.state -eq "UNLOADED") {
        $prompt = "Test prompt"
        $promptBytes = [System.Text.Encoding]::ASCII.GetBytes($prompt)
        $status = $Client.SendCommand($CMD_INFER, 0, $promptBytes)
        if ($status -eq $RESP_MODEL_NOT_LOADED) {
            Write-TestResult "INFER Unloaded State" "PASS" "Correctly rejected INFER when UNLOADED"
            $script:TestsPassed++
        } else {
            Write-TestResult "INFER Unloaded State" "FAIL" "Expected MODEL_NOT_LOADED, got: $status"
            $script:TestsFailed++
        }
    } else {
        Write-TestResult "INFER Unloaded State" "SKIP" "Could not unload model"
        $script:TestsSkipped++
    }
    
    # Test 2: INFER with zero-length payload
    $status = $Client.SendCommand($CMD_INFER, 0, $null)
    if ($status -eq $RESP_INVALID_PAYLOAD -or $status -eq $RESP_MODEL_NOT_LOADED) {
        Write-TestResult "INFER Zero Payload" "PASS" "Correctly rejected zero-length payload"
        $script:TestsPassed++
    } else {
        Write-TestResult "INFER Zero Payload" "FAIL" "Expected rejection, got: $status"
        $script:TestsFailed++
    }
}

function Test-HeartbeatIncrement {
    param([SovereignClient]$Client)
    
    Write-Host "`n=== Test: Heartbeat Increment ===" -ForegroundColor Cyan
    
    $heartbeat1 = $Client.GetHeartbeat()
    Start-Sleep -Milliseconds 100
    $heartbeat2 = $Client.GetHeartbeat()
    
    if ($heartbeat2 -gt $heartbeat1) {
        Write-TestResult "Heartbeat Increment" "PASS" "Heartbeat: $heartbeat1 -> $heartbeat2"
        $script:TestsPassed++
    } else {
        Write-TestResult "Heartbeat Increment" "FAIL" "Heartbeat did not increment: $heartbeat1 -> $heartbeat2"
        $script:TestsFailed++
    }
}

function Test-PayloadBounds {
    param([SovereignClient]$Client)
    
    Write-Host "`n=== Test: Payload Bounds Validation ===" -ForegroundColor Cyan
    
    # Test oversized payload (should be clamped)
    $oversizedPayload = [byte[]]::new(0x2000)  # 8KB, exceeds CMD_PAYLOAD_MAX
    for ($i = 0; $i -lt $oversizedPayload.Length; $i++) {
        $oversizedPayload[$i] = 0x41  # 'A'
    }
    
    $status = $Client.SendCommand($CMD_PING, 0, $oversizedPayload)
    if ($status -eq $RESP_OK) {
        Write-TestResult "Payload Bounds" "PASS" "Oversized payload handled correctly"
        $script:TestsPassed++
    } else {
        Write-TestResult "Payload Bounds" "FAIL" "Status: $status"
        $script:TestsFailed++
    }
}

# Main execution
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Sovereign Regression Gate" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Orchestrator: $OrchestratorPath" -ForegroundColor Gray
Write-Host "Timeout: $TimeoutMs ms" -ForegroundColor Gray
Write-Host ""

try {
    $client = [SovereignClient]::new()
    
    Write-Host "Connecting to orchestrator..." -ForegroundColor Yellow
    if (-not $client.Connect()) {
        Write-Host "Failed to connect to orchestrator" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Connected successfully" -ForegroundColor Green
    
    # Run tests
    Test-StartupAudit $client
    Test-PingCommand $client
    Test-GetVersion $client
    Test-StatusCommand $client
    Test-MetricsCommand $client
    Test-HeartbeatIncrement $client
    Test-PayloadBounds $client
    Test-LoadModelHappyPath $client
    Test-LoadModelNegativePath $client
    Test-InferHappyPath $client
    Test-InferNegativePath $client
    
    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Regression Gate Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Passed:   $script:TestsPassed" -ForegroundColor Green
    Write-Host "Failed:   $script:TestsFailed" -ForegroundColor Red
    Write-Host "Skipped:  $script:TestsSkipped" -ForegroundColor Yellow
    Write-Host ""
    
    $client.Dispose()
    
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
    exit 1
}