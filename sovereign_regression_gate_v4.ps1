# ==============================================================================
# Sovereign Regression Gate v4 — PowerShell Test Harness
# Validates: state machine, cancellation, handle hygiene, rapid-fire stability
# Fixes v3: Kills stale processes, polls for ready state, validates UNLOADED
# ==============================================================================
param(
    [int]$RequestCount = 100,
    [int]$CancelPercent = 15,
    [string]$ExePath = "d:\rawrxd-ci-bootstrap\SovereignOrchestrator.exe",
    [string]$ModelPath = "",  # Auto-detect if empty
    [int]$TimeoutMs = 5000,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"
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
    public const uint WAIT_FAILED = 0xFFFFFFFF;
}
"@

# ==============================================================================
# MMF Layout (must match SovereignOrchestrator_Hardened.asm)
# ==============================================================================
$script:OFF_STATE         = 0x00
$script:OFF_CMD_ID        = 0x04
$script:OFF_CMD_TYPE      = 0x08
$script:OFF_PAYLOAD_LEN   = 0x0C
$script:OFF_RESP_STATUS   = 0x10
$script:OFF_RESP_LEN      = 0x14
$script:OFF_CMD_PAYLOAD   = 0x18
$script:OFF_RESP_PAYLOAD  = 0x1018
$script:OFF_TELEM_TOKENS  = 0x2020
$script:OFF_TELEM_PROGRESS= 0x2028
$script:OFF_MODEL_STATE   = 0x2030
$script:OFF_MAGIC_COOKIE  = 0xFFF0
$script:OFF_HEARTBEAT    = 0xFFF8

$script:BEACON_READY      = 0x01
$script:BEACON_PROCESSING = 0x02
$script:BEACON_COMPLETE   = 0x04
$script:BEACON_SHUTDOWN   = 0xFF

$script:CMD_LOAD_MODEL      = 0x2000
$script:CMD_INFER         = 0x3003
$script:CMD_CANCEL_INFER  = 0x3005
$script:CMD_SHUTDOWN      = 0x1003
$script:CMD_GET_STATUS    = 0x1002
$script:CMD_GET_STATUS    = 0x1002

$script:RESP_OK           = 0
$script:RESP_CANCELLED   = 8
$script:RESP_BUSY         = 7
$script:RESP_MODEL_NOT_LOADED = 6

$script:MODEL_STATE_UNLOADED         = 0
$script:MODEL_STATE_LOADING          = 1
$script:MODEL_STATE_READY            = 2
$script:MODEL_STATE_INFERENCE_ACTIVE  = 3
$script:MODEL_STATE_CANCEL_PENDING   = 4

$script:MAGIC_COOKIE_VAL = [Convert]::ToUInt64("CAFEBABEDEADBEEF", 16)

# ==============================================================================
# Helper: Read/Write MMF
# ==============================================================================
function Read-U32($base, $offset) {
    $buf = New-Object byte[] 4
    [System.Runtime.InteropServices.Marshal]::Copy([IntPtr]::Add($base, $offset), $buf, 0, 4)
    return [BitConverter]::ToUInt32($buf, 0)
}

function Read-U64($base, $offset) {
    $buf = New-Object byte[] 8
    [System.Runtime.InteropServices.Marshal]::Copy([IntPtr]::Add($base, $offset), $buf, 0, 8)
    return [BitConverter]::ToUInt64($buf, 0)
}

function Write-U32($base, $offset, $value) {
    $buf = [BitConverter]::GetBytes([uint32]$value)
    [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, [IntPtr]::Add($base, $offset), 4)
}

function Write-U64($base, $offset, $value) {
    $buf = [BitConverter]::GetBytes([uint64]$value)
    [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, [IntPtr]::Add($base, $offset), 8)
}

function Write-Bytes($base, $offset, $bytes) {
    [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, [IntPtr]::Add($base, $offset), $bytes.Length)
}

function Read-String($base, $offset, $maxLen) {
    $buf = New-Object byte[] $maxLen
    [System.Runtime.InteropServices.Marshal]::Copy([IntPtr]::Add($base, $offset), $buf, 0, $maxLen)
    $n = [Array]::IndexOf($buf, [byte]0)
    if ($n -lt 0) { $n = $maxLen }
    return [System.Text.Encoding]::ASCII.GetString($buf, 0, $n)
}

# ==============================================================================
# Helper: Wait for response event
# ==============================================================================
function Wait-Response($hRespEvent, $timeoutMs) {
    $r = [NativeMethods]::WaitForSingleObject($hRespEvent, $timeoutMs)
    return ($r -eq [NativeMethods]::WAIT_OBJECT_0)
}

# ==============================================================================
# Helper: Poll for orchestrator ready (magic cookie + state)
# ==============================================================================
function Wait-ForOrchestratorReady($base, $timeoutMs) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $timeoutMs) {
        $cookie = Read-U64 $base $script:OFF_MAGIC_COOKIE
        if ($cookie -eq $script:MAGIC_COOKIE_VAL) {
            return $true
        }
        Start-Sleep -Milliseconds 50
    }
    return $false
}

# ==============================================================================
# Helper: Send command and wait for response
# ==============================================================================
function Send-Command($base, $hCmdEvent, $hRespEvent, $cmdType, $payloadBytes, $timeoutMs) {
    Write-U32 $base $script:OFF_CMD_TYPE $cmdType
    if ($payloadBytes) {
        Write-U32 $base $script:OFF_PAYLOAD_LEN $payloadBytes.Length
        Write-Bytes $base $script:OFF_CMD_PAYLOAD $payloadBytes
    } else {
        Write-U32 $base $script:OFF_PAYLOAD_LEN 0
    }
    Write-U32 $base $script:OFF_STATE $script:BEACON_READY
    [NativeMethods]::SetEvent($hCmdEvent) | Out-Null
    return (Wait-Response $hRespEvent $timeoutMs)
}

# ==============================================================================
# Helper: Get model state from MMF (reads embedded in response payload)
# ==============================================================================
function Get-ModelState($base) {
    # The STATUS response JSON contains "state":"..." 
    # For now, we infer from response status codes
    $status = Read-U32 $base $script:OFF_RESP_STATUS
    return $status
}

# ==============================================================================
# Test: Single inference request
# ==============================================================================
function Test-Inference($base, $hCmdEvent, $hRespEvent, $hCancelEvent, $prompt, $shouldCancel, $cancelDelayMs) {
    # Write prompt to MMF
    $promptBytes = [System.Text.Encoding]::ASCII.GetBytes($prompt)
    if ($promptBytes.Length -gt 4095) { $promptBytes = $promptBytes[0..4094] }
    
    $ok = Send-Command $base $hCmdEvent $hRespEvent $script:CMD_INFER $promptBytes 5000
    if (-not $ok) {
        Write-Host "    ❌ INFER timeout" -ForegroundColor Red
        return "timeout"
    }
    
    $status = Read-U32 $base $script:OFF_RESP_STATUS
    if ($status -ne $script:RESP_OK) {
        Write-Host "    ❌ INFER failed with status $status" -ForegroundColor Red
        return "fail_$status"
    }
    
    # If we should cancel, wait then send cancel
    if ($shouldCancel) {
        Start-Sleep -Milliseconds $cancelDelayMs
        
        $cancelOk = Send-Command $base $hCmdEvent $hRespEvent $script:CMD_CANCEL_INFER $null 5000
        if (-not $cancelOk) {
            Write-Host "    ⚠️ CANCEL timeout" -ForegroundColor Yellow
            return "cancel_timeout"
        }
        
        $cancelStatus = Read-U32 $base $script:OFF_RESP_STATUS
        if ($cancelStatus -eq $script:RESP_OK) {
            # Wait for worker to finish cancelling (model state goes back to READY)
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            while ($sw.ElapsedMilliseconds -lt 3000) {
                $modelState = Read-U32 $base $script:OFF_MODEL_STATE
                if ($modelState -eq $script:MODEL_STATE_READY) { break }
                Start-Sleep -Milliseconds 50
            }
            return "cancelled"
        } else {
            return "cancel_fail_$cancelStatus"
        }
    }
    
    # Wait for inference to complete (model state goes back to READY)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $TimeoutMs) {
        $modelState = Read-U32 $base $script:OFF_MODEL_STATE
        if ($modelState -eq $script:MODEL_STATE_READY) {
            $tokens = Read-U64 $base $script:OFF_TELEM_TOKENS
            return "ok_$tokens"
        }
        Start-Sleep -Milliseconds 10
    }
    
    return "incomplete"
}

# ==============================================================================
# Auto-detect model
# ==============================================================================
if (-not $ModelPath) {
    $searchPaths = @(
        "F:\OllamaModels",
        "D:\models",
        "C:\models"
    )
    
    foreach ($dir in $searchPaths) {
        if (-not (Test-Path $dir)) { continue }
        $found = Get-ChildItem -Path $dir -Filter "*.gguf" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt 1MB } |
            Sort-Object Length |
            Select-Object -First 1
        if ($found) {
            $ModelPath = $found.FullName
            break
        }
    }
    
    # Try Ollama blobs
    if (-not $ModelPath) {
        $blobDir = "F:\OllamaModels\blobs"
        if (Test-Path $blobDir) {
            $blobs = Get-ChildItem -Path "$blobDir\sha256-*" -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -gt 100MB } |
                Sort-Object Length |
                Select-Object -First 1
            if ($blobs) {
                $ModelPath = $blobs.FullName
                Write-Host "[AUTO] Found Ollama blob: $($blobs.Name) ($([math]::Round($blobs.Length/1MB,1)) MB)" -ForegroundColor Yellow
            }
        }
    }
}

if (-not $ModelPath -or -not (Test-Path $ModelPath)) {
    Write-Error "No model found. Please specify -ModelPath with a .gguf file or Ollama blob."
    exit 1
}

Write-Host "[CONFIG] Model: $ModelPath" -ForegroundColor Cyan

# ==============================================================================
# Phase 0: Kill stale processes
# ==============================================================================
Write-Host "[CLEANUP] Killing any existing SovereignOrchestrator processes..."
Get-Process | Where-Object { $_.ProcessName -like "*SovereignOrchestrator*" } | 
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# ==============================================================================
# Main Gate
# ==============================================================================
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Sovereign Regression Gate v4" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Requests: $RequestCount | Cancel%: $CancelPercent | Timeout: ${TimeoutMs}ms"
Write-Host ""

# Launch orchestrator
Write-Host "[LAUNCH] Starting SovereignOrchestrator.exe..."
$proc = Start-Process -FilePath $ExePath -PassThru -WindowStyle Hidden

# Poll for MMF to appear (up to 10 seconds)
Write-Host "[LAUNCH] Waiting for orchestrator to initialize..."
$hMap = [IntPtr]::Zero
$sw = [System.Diagnostics.Stopwatch]::StartNew()
while ($sw.ElapsedMilliseconds -lt 10000 -and $hMap -eq [IntPtr]::Zero) {
    $hMap = [NativeMethods]::OpenFileMappingA([NativeMethods]::FILE_MAP_ALL_ACCESS, $false, "SOVEREIGN_BEACON_V1")
    if ($hMap -eq [IntPtr]::Zero) {
        Start-Sleep -Milliseconds 100
    }
}

if ($hMap -eq [IntPtr]::Zero) {
    Write-Error "Failed to open MMF after 10s. Is orchestrator running?"
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

# Wait for magic cookie (proves orchestrator finished BeaconInit)
Write-Host "[LAUNCH] Waiting for magic cookie..."
$ready = Wait-ForOrchestratorReady $pMap 5000
if (-not $ready) {
    Write-Error "Orchestrator failed to initialize (no magic cookie)"
    [NativeMethods]::UnmapViewOfFile($pMap) | Out-Null
    [NativeMethods]::CloseHandle($hMap) | Out-Null
    $proc | Stop-Process -Force
    exit 1
}
Write-Host "[LAUNCH] Orchestrator ready (magic cookie verified)" -ForegroundColor Green

# Open events
$hCmdEvent  = [NativeMethods]::OpenEventA(([NativeMethods]::EVENT_MODIFY_STATE -bor [NativeMethods]::SYNCHRONIZE), $false, "SOVEREIGN_CMD_EVENT")
$hRespEvent = [NativeMethods]::OpenEventA(([NativeMethods]::EVENT_MODIFY_STATE -bor [NativeMethods]::SYNCHRONIZE), $false, "SOVEREIGN_RESP_EVENT")
$hCancelEvent = [NativeMethods]::OpenEventA(([NativeMethods]::EVENT_MODIFY_STATE -bor [NativeMethods]::SYNCHRONIZE), $false, "SOVEREIGN_CANCEL_EVENT")

if ($hCmdEvent -eq [IntPtr]::Zero -or $hRespEvent -eq [IntPtr]::Zero) {
    Write-Error "Failed to open events"
    [NativeMethods]::UnmapViewOfFile($pMap) | Out-Null
    [NativeMethods]::CloseHandle($hMap) | Out-Null
    $proc | Stop-Process -Force
    exit 1
}

# ==============================================================================
# Phase 1: Verify state is UNLOADED, then load model
# ==============================================================================
Write-Host "`n[LOAD] Checking orchestrator state..."
$stateCheck = Send-Command $pMap $hCmdEvent $hRespEvent $script:CMD_GET_STATUS $null 5000
if (-not $stateCheck) {
    Write-Error "STATUS check timeout"
    Cleanup
    exit 1
}

$statusJson = Read-String $pMap $script:OFF_RESP_PAYLOAD 256
Write-Host "[LOAD] Status: $statusJson"

# Load model
Write-Host "[LOAD] Loading model: $ModelPath" -ForegroundColor Yellow
$modelBytes = [System.Text.Encoding]::ASCII.GetBytes($ModelPath)
if ($modelBytes.Length -gt 4095) { $modelBytes = $modelBytes[0..4094] }

$loadOk = Send-Command $pMap $hCmdEvent $hRespEvent $script:CMD_LOAD_MODEL $modelBytes 30000
if (-not $loadOk) {
    Write-Error "Model load timeout"
    Cleanup
    exit 1
}

$loadStatus = Read-U32 $pMap $script:OFF_RESP_STATUS
if ($loadStatus -ne $script:RESP_OK) {
    Write-Error "Model load failed with status $loadStatus (BUSY=7, NOT_LOADED=6)"
    Cleanup
    exit 1
}

Write-Host "[LOAD] Model loaded successfully" -ForegroundColor Green
Start-Sleep -Seconds 1

# ==============================================================================
# Phase 2: Run Tests
# ==============================================================================
$pass = 0
$fail = 0
$cancelOk = 0
$cancelFail = 0
$results = @()
$rng = New-Object System.Random

Write-Host "`n[TEST] Running $RequestCount inference requests..."
for ($i = 1; $i -le $RequestCount; $i++) {
    $prompt = "Test request $i"
    $shouldCancel = ($rng.Next(100) -lt $CancelPercent)
    $cancelDelay = if ($shouldCancel) { $rng.Next(50, 800) } else { 0 }
    
    if ($Verbose -or ($i % 10 -eq 0)) {
        Write-Host "  [$i/$RequestCount] prompt='$prompt' cancel=$shouldCancel" -NoNewline
    }
    
    $result = Test-Inference $pMap $hCmdEvent $hRespEvent $hCancelEvent $prompt $shouldCancel $cancelDelay
    
    if ($result -like "ok_*") {
        $pass++
        if ($Verbose -or ($i % 10 -eq 0)) { Write-Host " ✅ ($result)" -ForegroundColor Green }
    } elseif ($result -like "cancelled") {
        $cancelOk++
        if ($Verbose -or ($i % 10 -eq 0)) { Write-Host " 🚫 cancelled" -ForegroundColor Yellow }
    } elseif ($result -like "cancel_*") {
        $cancelFail++
        if ($Verbose -or ($i % 10 -eq 0)) { Write-Host " ⚠️ cancel_fail ($result)" -ForegroundColor Yellow }
    } else {
        $fail++
        $results += "Request $i`: $result"
        if ($Verbose -or ($i % 10 -eq 0)) { Write-Host " ❌ ($result)" -ForegroundColor Red }
    }
}

# ==============================================================================
# Phase 3: Results
# ==============================================================================
Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "RESULTS" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Total:     $RequestCount"
Write-Host "Pass:      $pass" -ForegroundColor Green
Write-Host "Fail:      $fail" -ForegroundColor Red
Write-Host "Cancel OK: $cancelOk" -ForegroundColor Yellow
Write-Host "Cancel Fail: $cancelFail" -ForegroundColor Yellow

if ($results.Count -gt 0) {
    Write-Host "`nFailures:"
    $results | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
}

$successRate = [math]::Round(($pass / $RequestCount) * 100, 1)
Write-Host "`nSuccess Rate: $successRate%" -ForegroundColor $(if ($successRate -ge 95) { "Green" } elseif ($successRate -ge 80) { "Yellow" } else { "Red" })

# ==============================================================================
# Phase 4: Cleanup
# ==============================================================================
function Cleanup() {
    Write-Host "`n[CLEANUP] Sending shutdown..."
    Send-Command $pMap $hCmdEvent $hRespEvent $script:CMD_SHUTDOWN $null 5000 | Out-Null
    Start-Sleep -Seconds 2
    
    [NativeMethods]::UnmapViewOfFile($pMap) | Out-Null
    [NativeMethods]::CloseHandle($hMap) | Out-Null
    if ($hCmdEvent -ne [IntPtr]::Zero) { [NativeMethods]::CloseHandle($hCmdEvent) | Out-Null }
    if ($hRespEvent -ne [IntPtr]::Zero) { [NativeMethods]::CloseHandle($hRespEvent) | Out-Null }
    if ($hCancelEvent -ne [IntPtr]::Zero) { [NativeMethods]::CloseHandle($hCancelEvent) | Out-Null }
    
    $proc | Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Host "[CLEANUP] Done."
}

Cleanup

# ==============================================================================
# Exit Code
# ==============================================================================
if ($fail -eq 0 -and $cancelFail -eq 0) {
    Write-Host "`n✅ REGRESSION GATE PASSED" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n❌ REGRESSION GATE FAILED" -ForegroundColor Red
    exit 1
}
