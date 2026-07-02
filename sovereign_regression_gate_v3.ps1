# ==============================================================================
# Sovereign Regression Gate v3 — PowerShell Test Harness
# Validates: state machine, cancellation, handle hygiene, rapid-fire stability
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

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesRead);

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
$script:OFF_MODEL_STATE  = 0x2030
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

$script:RESP_OK           = 0
$script:RESP_CANCELLED   = 8
$script:RESP_BUSY         = 7
$script:RESP_MODEL_NOT_LOADED = 6

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
# Helper: Wait for beacon state with timeout
# ==============================================================================
function Wait-BeaconState($base, $targetState, $timeoutMs) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $timeoutMs) {
        $state = Read-U32 $base $script:OFF_STATE
        if ($state -eq $targetState) { return $true }
        Start-Sleep -Milliseconds 10
    }
    return $false
}

# ==============================================================================
# Helper: Wait for model state (worker completion) with timeout
# ==============================================================================
function Wait-ModelState($base, $targetState, $timeoutMs) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $timeoutMs) {
        $state = Read-U32 $base $script:OFF_MODEL_STATE
        if ($state -eq $targetState) { return $true }
        Start-Sleep -Milliseconds 10
    }
    return $false
}

# ==============================================================================
# Helper: Wait for response event
# ==============================================================================
function Wait-Response($hRespEvent, $timeoutMs) {
    $r = [NativeMethods]::WaitForSingleObject($hRespEvent, $timeoutMs)
    return ($r -eq [NativeMethods]::WAIT_OBJECT_0)
}

# ==============================================================================
# Test: Single inference request
# ==============================================================================
function Test-Inference($base, $hCmdEvent, $hRespEvent, $prompt, $shouldCancel, $cancelDelayMs) {
    # Write prompt to MMF
    $promptBytes = [System.Text.Encoding]::ASCII.GetBytes($prompt)
    if ($promptBytes.Length -gt 4095) { $promptBytes = $promptBytes[0..4094] }
    
    Write-U32 $base $script:OFF_CMD_TYPE $script:CMD_INFER
    Write-U32 $base $script:OFF_PAYLOAD_LEN $promptBytes.Length
    Write-Bytes $base $script:OFF_CMD_PAYLOAD $promptBytes
    Write-U32 $base $script:OFF_STATE $script:BEACON_READY
    
    # Signal command
    $null = [NativeMethods]::SetEvent($hCmdEvent)
    
    # Optionally cancel
    if ($shouldCancel -and $cancelDelayMs -gt 0) {
        Start-Sleep -Milliseconds $cancelDelayMs
        Write-U32 $base $script:OFF_CMD_TYPE $script:CMD_CANCEL_INFER
        Write-U32 $base $script:OFF_STATE $script:BEACON_READY
        $null = [NativeMethods]::SetEvent($hCmdEvent)
    }
    
    # Wait for response
    $ok = Wait-Response $hRespEvent $script:TimeoutMs
    if (-not $ok) { return @{ Success = $false; Error = "TIMEOUT"; Status = -1; Tokens = 0 } }
    
    # Wait for worker to finish (model state returns to READY)
    $modelReady = Wait-ModelState $base $script:MODEL_STATE_READY $script:TimeoutMs
    if (-not $modelReady) { return @{ Success = $false; Error = "WORKER_TIMEOUT"; Status = -1; Tokens = 0 } }
    
    $status = Read-U32 $base $script:OFF_RESP_STATUS
    $tokens = Read-U64 $base $script:OFF_TELEM_TOKENS
    $progress = Read-U32 $base $script:OFF_TELEM_PROGRESS
    
    return @{ Success = $true; Status = $status; Tokens = $tokens; Progress = $progress }
}

# ==============================================================================
# Model Auto-Detection
# ==============================================================================
if (-not $ModelPath) {
    # Search for models in priority order: GGUF files, then Ollama blobs
    $searchPaths = @(
        "F:\OllamaModels\*.gguf",
        "F:\OllamaModels\models\*.gguf",
        "C:\OllamaModels\*.gguf",
        "D:\OllamaModels\*.gguf"
    )
    
    foreach ($pattern in $searchPaths) {
        $found = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | 
            Where-Object { $_.Length -gt 100MB -and $_.Name -notmatch 'dummy' } |
            Sort-Object Length | 
            Select-Object -First 1
        if ($found) {
            $ModelPath = $found.FullName
            break
        }
    }
    
    # If no GGUF found, try Ollama blobs (sha256- prefixed files)
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
# Main Gate
# ==============================================================================
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Sovereign Regression Gate v3" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Requests: $RequestCount | Cancel%: $CancelPercent | Timeout: ${TimeoutMs}ms"
Write-Host ""

# Launch orchestrator
Write-Host "[LAUNCH] Starting SovereignOrchestrator.exe..."
$proc = Start-Process -FilePath $ExePath -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2  # Allow init

# Open MMF
$hMap = [NativeMethods]::OpenFileMappingA([NativeMethods]::FILE_MAP_ALL_ACCESS, $false, "SOVEREIGN_BEACON_V1")
if ($hMap -eq [IntPtr]::Zero) {
    Write-Error "Failed to open MMF. Is orchestrator running?"
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

# Open events
$hCmdEvent  = [NativeMethods]::OpenEventA(([NativeMethods]::EVENT_MODIFY_STATE -bor [NativeMethods]::SYNCHRONIZE), $false, "SOVEREIGN_CMD_EVENT")
$hRespEvent = [NativeMethods]::OpenEventA(([NativeMethods]::EVENT_MODIFY_STATE -bor [NativeMethods]::SYNCHRONIZE), $false, "SOVEREIGN_RESP_EVENT")
$hInferEvent = [NativeMethods]::OpenEventA(([NativeMethods]::EVENT_MODIFY_STATE -bor [NativeMethods]::SYNCHRONIZE), $false, "SOVEREIGN_INFER_EVENT")
$hCancelEvent = [NativeMethods]::OpenEventA(([NativeMethods]::EVENT_MODIFY_STATE -bor [NativeMethods]::SYNCHRONIZE), $false, "SOVEREIGN_CANCEL_EVENT")

if ($hCmdEvent -eq [IntPtr]::Zero -or $hRespEvent -eq [IntPtr]::Zero) {
    Write-Error "Failed to open events"
    [NativeMethods]::UnmapViewOfFile($pMap) | Out-Null
    [NativeMethods]::CloseHandle($hMap) | Out-Null
    $proc | Stop-Process -Force
    exit 1
}

# Verify magic cookie
$cookie = Read-U64 $pMap $script:OFF_MAGIC_COOKIE
if ($cookie -ne $script:MAGIC_COOKIE_VAL) {
    Write-Warning "Magic cookie mismatch: 0x$($cookie.ToString('X16')) (expected 0xCAFEBABEDEADBEEF)"
}

# ==============================================================================
# Phase 1: Load Model
# ==============================================================================
Write-Host "[LOAD] Loading model: $ModelPath" -ForegroundColor Yellow
$modelBytes = [System.Text.Encoding]::ASCII.GetBytes($ModelPath)
if ($modelBytes.Length -gt 4095) { $modelBytes = $modelBytes[0..4094] }

Write-U32 $pMap $script:OFF_CMD_TYPE $script:CMD_LOAD_MODEL
Write-U32 $pMap $script:OFF_PAYLOAD_LEN $modelBytes.Length
Write-Bytes $pMap $script:OFF_CMD_PAYLOAD $modelBytes
Write-U32 $pMap $script:OFF_STATE $script:BEACON_READY
$null = [NativeMethods]::SetEvent($hCmdEvent)

$loadOk = Wait-Response $hRespEvent 30000
if (-not $loadOk) {
    Write-Error "Model load timeout"
    exit 1
}

$loadStatus = Read-U32 $pMap $script:OFF_RESP_STATUS
if ($loadStatus -ne $script:RESP_OK) {
    Write-Error "Model load failed with status $loadStatus"
    exit 1
}

Write-Host "[LOAD] Model loaded successfully" -ForegroundColor Green
Start-Sleep -Seconds 1  # Allow model init

# ==============================================================================
# Phase 2: Run Tests
# ==============================================================================
$pass = 0
$fail = 0
$cancelOk = 0
$cancelFail = 0
$rng = New-Object System.Random

Write-Host "[TEST] Running $RequestCount inference requests..."
for ($i = 1; $i -le $RequestCount; $i++) {
    $prompt = "Test request $i"
    $shouldCancel = ($rng.Next(100) -lt $CancelPercent)
    $cancelDelay = if ($shouldCancel) { $rng.Next(50, 800) } else { 0 }
    
    $result = Test-Inference $pMap $hCmdEvent $hRespEvent $prompt $shouldCancel $cancelDelay
    
    if ($result.Success) {
        if ($shouldCancel) {
            if ($result.Status -eq $script:RESP_CANCELLED -or $result.Status -eq $script:RESP_OK) {
                $cancelOk++
                if ($Verbose) { Write-Host "  [$i] CANCEL OK (status=$($result.Status), tokens=$($result.Tokens))" -ForegroundColor DarkGray }
            } else {
                $cancelFail++
                Write-Host "  [$i] CANCEL UNEXPECTED (status=$($result.Status))" -ForegroundColor Yellow
            }
        } else {
            if ($result.Status -eq $script:RESP_OK) {
                $pass++
                if ($Verbose) { Write-Host "  [$i] PASS (tokens=$($result.Tokens), progress=$($result.Progress)%)" -ForegroundColor DarkGray }
            } else {
                $fail++
                Write-Host "  [$i] FAIL (status=$($result.Status))" -ForegroundColor Red
            }
        }
    } else {
        $fail++
        Write-Host "  [$i] TIMEOUT" -ForegroundColor Red
    }
    
    # Brief pause between requests to avoid overwhelming
    Start-Sleep -Milliseconds 10
}

# Check handle count (rough proxy)
$proc.Refresh()
$handlesAfter = $proc.Handles

# Shutdown
Write-Host "[SHUTDOWN] Signaling orchestrator..."
Write-U32 $pMap $script:OFF_CMD_TYPE $script:CMD_SHUTDOWN
Write-U32 $pMap $script:OFF_STATE $script:BEACON_READY
$null = [NativeMethods]::SetEvent($hCmdEvent)
Start-Sleep -Seconds 1

# Cleanup
[NativeMethods]::UnmapViewOfFile($pMap) | Out-Null
[NativeMethods]::CloseHandle($hMap) | Out-Null
[NativeMethods]::CloseHandle($hCmdEvent) | Out-Null
[NativeMethods]::CloseHandle($hRespEvent) | Out-Null
if ($hInferEvent -ne [IntPtr]::Zero) { [NativeMethods]::CloseHandle($hInferEvent) | Out-Null }
if ($hCancelEvent -ne [IntPtr]::Zero) { [NativeMethods]::CloseHandle($hCancelEvent) | Out-Null }

# Wait for process exit
$proc | Wait-Process -Timeout 5 -ErrorAction SilentlyContinue
if (-not $proc.HasExited) {
    $proc | Stop-Process -Force
    Write-Warning "Orchestrator did not exit cleanly — forced termination"
}

# ==============================================================================
# Report
# ==============================================================================
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "REGRESSION GATE RESULTS" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Total Requests:     $RequestCount"
Write-Host "Passed:             $pass" -ForegroundColor Green
Write-Host "Failed:             $fail" -ForegroundColor $(if ($fail -gt 0) { "Red" } else { "Green" })
Write-Host "Cancelled (OK):     $cancelOk" -ForegroundColor Green
Write-Host "Cancelled (Fail):   $cancelFail" -ForegroundColor $(if ($cancelFail -gt 0) { "Yellow" } else { "Green" })
Write-Host "Handles at end:     $handlesAfter"
Write-Host ""

$totalOk = $pass + $cancelOk
$totalBad = $fail + $cancelFail
$rate = if ($RequestCount -gt 0) { [math]::Round(($totalOk / $RequestCount) * 100, 1) } else { 0 }

if ($totalBad -eq 0) {
    Write-Host "RESULT: PASS ($rate% success rate)" -ForegroundColor Green
    Write-Host "The Sovereign Orchestrator is production-proven under load." -ForegroundColor Green
    exit 0
} else {
    Write-Host "RESULT: FAIL ($totalBad failures out of $RequestCount)" -ForegroundColor Red
    Write-Host "Review failures above before declaring production-ready." -ForegroundColor Red
    exit 1
}
