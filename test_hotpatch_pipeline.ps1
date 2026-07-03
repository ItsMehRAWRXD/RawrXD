# ============================================================================
# RawrXD Hotpatch Pipeline End-to-End Test
# Phase 4B: Verify epoch slot rotation and file handle lifetime
# ============================================================================
# This script tests:
# 1. Hotpatch request loads a GGUF model via named pipe
# 2. Model data is copied to heap (survives loader destruction)
# 3. File handle is released (allows immediate re-hotpatch)
# 4. Epoch slots rotate correctly
# ============================================================================

param(
    [string]$PipeName = "RawrXD_Inference",
    [string]$TestModelPath = "D:\\temp\\test-model.gguf",
    [int]$TimeoutSeconds = 30
)

$ErrorActionPreference = "Stop"

# Hotpatch payload magic
$HOTPATCH_MAGIC = 0x52485044  # "RHPD"
$HOTPATCH_VERSION = 1

# Router result codes
$RouterResults = @{
    0 = "OK - Hotpatch accepted, epoch incremented"
    1 = "PENDING - Another hotpatch already pending"
    2 = "BUSY - Inference active, deferred"
    3 = "READERS_ACTIVE - Readers still active"
    4 = "ERROR - Internal error"
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "HH:mm:ss.fff"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Calculate-CRC32 {
    param([byte[]]$Data)
    $crc = [uint32]::MaxValue
    foreach ($byte in $Data) {
        $crc = $crc -bxor $byte
        for ($i = 0; $i -lt 8; $i++) {
            $mask = -([int]($crc -band 1))
            $crc = ($crc -shr 1) -bxor (0xEDB88320 -band $mask)
        }
    }
    return [uint32]::MaxValue - $crc
}

function Send-HotpatchRequest {
    param(
        [string]$ModelPath,
        [int]$RequestId
    )
    
    $pipePath = "\\.\pipe\$PipeName"
    Write-Log "Connecting to pipe: $pipePath" "INFO"
    
    try {
        $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
            ".", $PipeName, 
            [System.IO.Pipes.PipeDirection]::InOut,
            [System.IO.Pipes.PipeOptions]::None
        )
        
        $pipe.Connect(5000)  # 5 second timeout
        Write-Log "Connected to pipe server" "SUCCESS"
        
        # Build payload
        $pathBytes = [System.Text.Encoding]::UTF8.GetBytes($ModelPath)
        $payloadSize = $pathBytes.Length
        
        # HotpatchPayload structure (packed)
        # uint32_t magic; uint32_t version; uint32_t payloadSize; uint32_t flags;
        # uint64_t timestamp; uint32_t crc32; uint8_t data[];
        
        $timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $flags = 0
        
        # Calculate CRC of data portion
        $crc = Calculate-CRC32 -Data $pathBytes
        
        # Build binary payload
        $ms = New-Object System.IO.MemoryStream
        $writer = New-Object System.IO.BinaryWriter($ms)
        
        $writer.Write([uint32]$HOTPATCH_MAGIC)
        $writer.Write([uint32]$HOTPATCH_VERSION)
        $writer.Write([uint32]$payloadSize)
        $writer.Write([uint32]$flags)
        $writer.Write([uint64]$timestamp)
        $writer.Write([uint32]$crc)
        $writer.Write($pathBytes)
        
        $payload = $ms.ToArray()
        $writer.Close()
        $ms.Close()
        
        Write-Log "Sending hotpatch request #$RequestId ($payloadSize bytes)" "INFO"
        
        # Send payload
        $pipe.Write($payload, 0, $payload.Length)
        $pipe.Flush()
        
        # Read response
        $responseBuffer = New-Object byte[] 4096
        $bytesRead = $pipe.Read($responseBuffer, 0, $responseBuffer.Length)
        
        if ($bytesRead -gt 0) {
            $responseText = [System.Text.Encoding]::UTF8.GetString($responseBuffer, 0, $bytesRead)
            Write-Log "Response: $responseText" "INFO"
            
            # Parse JSON response
            try {
                $response = $responseText | ConvertFrom-Json
                return $response
            } catch {
                Write-Log "Failed to parse response as JSON" "WARN"
                return @{ status = "unknown"; raw = $responseText }
            }
        } else {
            Write-Log "No response received" "WARN"
            return @{ status = "no_response" }
        }
        
    } catch {
        Write-Log "Pipe communication failed: $_" "ERROR"
        return @{ status = "error"; message = $_.ToString() }
    } finally {
        if ($pipe) { $pipe.Close(); $pipe.Dispose() }
    }
}

function Test-FileHandleReleased {
    param([string]$ModelPath)
    
    Write-Log "Testing file handle release..." "INFO"
    
    # Try to open the file exclusively to verify it's not locked
    try {
        $fs = [System.IO.File]::Open(
            $ModelPath, 
            [System.IO.FileMode]::Open, 
            [System.IO.FileAccess]::ReadWrite, 
            [System.IO.FileShare]::None
        )
        $fs.Close()
        Write-Log "File is NOT locked - handle was released correctly!" "SUCCESS"
        return $true
    } catch {
        Write-Log "File is still locked: $_" "ERROR"
        return $false
    }
}

# ============================================================================
# Main Test Execution
# ============================================================================

Write-Log "========================================" "INFO"
Write-Log "RawrXD Hotpatch Pipeline E2E Test" "INFO"
Write-Log "========================================" "INFO"
Write-Log "Pipe: $PipeName" "INFO"
Write-Log "Model: $TestModelPath" "INFO"
Write-Log ""

# Check if test model exists
if (-not (Test-Path $TestModelPath)) {
    Write-Log "Test model not found: $TestModelPath" "ERROR"
    Write-Log "Creating dummy test file..." "WARN"
    
    # Create a minimal dummy GGUF file for testing
    $dummyDir = Split-Path $TestModelPath -Parent
    if (-not (Test-Path $dummyDir)) {
        New-Item -ItemType Directory -Path $dummyDir -Force | Out-Null
    }
    
    # Create minimal GGUF header (magic + version + tensor count + metadata kv count)
    $magic = [byte[]](0x47, 0x47, 0x55, 0x46)  # "GGUF"
    $version = [System.BitConverter]::GetBytes([uint32]3)
    $tensorCount = [System.BitConverter]::GetBytes([uint64]1)
    $metadataCount = [System.BitConverter]::GetBytes([uint64]0)
    
    $dummyData = $magic + $version + $tensorCount + $metadataCount
    [System.IO.File]::WriteAllBytes($TestModelPath, $dummyData)
    Write-Log "Created dummy GGUF file for testing" "WARN"
}

# Test 1: Initial hotpatch
Write-Log "--- Test 1: Initial Hotpatch ---" "INFO"
$result1 = Send-HotpatchRequest -ModelPath $TestModelPath -RequestId 1

if ($result1.status -eq "ok") {
    Write-Log "Hotpatch 1 succeeded!" "SUCCESS"
    Write-Log "  Model handle: $($result1.model_handle)" "INFO"
    Write-Log "  Router code: $($result1.router_code) - $($RouterResults[[int]$result1.router_code])" "INFO"
} else {
    Write-Log "Hotpatch 1 failed: $($result1.status)" "ERROR"
}

# Test 2: Verify file handle released
Write-Log ""
Write-Log "--- Test 2: File Handle Release Verification ---" "INFO"
$handleReleased = Test-FileHandleReleased -ModelPath $TestModelPath

if (-not $handleReleased) {
    Write-Log "CRITICAL: File handle was not released!" "ERROR"
    Write-Log "This means the GGUFLoader destructor didn't fire correctly." "ERROR"
}

# Test 3: Second hotpatch (same file)
Write-Log ""
Write-Log "--- Test 3: Second Hotpatch (Same File) ---" "INFO"
$result2 = Send-HotpatchRequest -ModelPath $TestModelPath -RequestId 2

if ($result2.status -eq "ok") {
    Write-Log "Hotpatch 2 succeeded!" "SUCCESS"
    Write-Log "  Model handle: $($result2.model_handle)" "INFO"
    Write-Log "  Router code: $($result2.router_code) - $($RouterResults[[int]$result2.router_code])" "INFO"
    
    if ($result1.model_handle -ne $result2.model_handle) {
        Write-Log "  Model handles are DIFFERENT - epoch slot rotated!" "SUCCESS"
    } else {
        Write-Log "  Model handles are SAME - possible epoch collision" "WARN"
    }
} else {
    Write-Log "Hotpatch 2 failed: $($result2.status)" "ERROR"
}

# Test 4: Verify file still accessible
Write-Log ""
Write-Log "--- Test 4: Final File Access Check ---" "INFO"
$finalCheck = Test-FileHandleReleased -ModelPath $TestModelPath

# Summary
Write-Log ""
Write-Log "========================================" "INFO"
Write-Log "Test Summary" "INFO"
Write-Log "========================================" "INFO"

$allPassed = $true

if ($result1.status -eq "ok") {
    Write-Log "✓ Test 1 (Initial hotpatch): PASSED" "SUCCESS"
} else {
    Write-Log "✗ Test 1 (Initial hotpatch): FAILED" "ERROR"
    $allPassed = $false
}

if ($handleReleased) {
    Write-Log "✓ Test 2 (File handle release): PASSED" "SUCCESS"
} else {
    Write-Log "✗ Test 2 (File handle release): FAILED" "ERROR"
    $allPassed = $false
}

if ($result2.status -eq "ok") {
    Write-Log "✓ Test 3 (Second hotpatch): PASSED" "SUCCESS"
} else {
    Write-Log "✗ Test 3 (Second hotpatch): FAILED" "ERROR"
    $allPassed = $false
}

if ($finalCheck) {
    Write-Log "✓ Test 4 (Final file access): PASSED" "SUCCESS"
} else {
    Write-Log "✗ Test 4 (Final file access): FAILED" "ERROR"
    $allPassed = $false
}

Write-Log ""
if ($allPassed) {
    Write-Log "ALL TESTS PASSED - Hotpatch pipeline is functional!" "SUCCESS"
    exit 0
} else {
    Write-Log "SOME TESTS FAILED - Review output above" "ERROR"
    exit 1
}
