# =============================================================================
# sovereign_mock_server.ps1
# Mock Sovereign Engine Server for TC15_001 Testing
# =============================================================================

param(
    [int]$FirstTokenMin = 50,
    [int]$FirstTokenMax = 180,
    [int]$SubsequentMin = 30,
    [int]$SubsequentMax = 90
)

$ErrorActionPreference = "Stop"

Write-Host "=== Sovereign Mock Server ===" -ForegroundColor Green
Write-Host "Simulating 7B Q4_K model with MMAP optimization" -ForegroundColor Cyan
Write-Host "Target: First token <200ms, Subsequent <100ms" -ForegroundColor Cyan
Write-Host ""

# Simulated Fibonacci completion
$completionText = @"
acci sequence up to n terms
    std::vector<int> fibonacci(int n) {
        std::vector<int> result;
        if (n <= 0) return result;
        result.push_back(0);
        if (n == 1) return result;
        result.push_back(1);
        for (int i = 2; i < n; ++i) {
            result.push_back(result[i-1] + result[i-2]);
        }
        return result;
    }
"@

# Helper function to send messages
function Send-Message {
    param($Writer, [int]$Type, [int]$RequestId, [string]$Payload)
    
    $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($Payload)
    
    # Build header
    $header = New-Object byte[] 24
    [BitConverter]::GetBytes([uint32]0x534F5645).CopyTo($header, 0)   # magic
    [BitConverter]::GetBytes([uint32]1).CopyTo($header, 4)             # version
    [BitConverter]::GetBytes([uint32]$Type).CopyTo($header, 8)       # type
    [BitConverter]::GetBytes([uint32]$payloadBytes.Length).CopyTo($header, 12)  # payload size
    [BitConverter]::GetBytes([uint64]0).CopyTo($header, 16)          # timestamp
    [BitConverter]::GetBytes([uint32]$RequestId).CopyTo($header, 20) # request id
    
    $Writer.Write($header)
    $Writer.Write($payloadBytes)
    $Writer.Flush()
}

# Create pipe server
$pipeName = "SovereignIPC"

Write-Host "[MockServer] Creating named pipe: $pipeName" -ForegroundColor Yellow

try {
    $pipe = New-Object System.IO.Pipes.NamedPipeServerStream(
        $pipeName,
        [System.IO.Pipes.PipeDirection]::InOut,
        1,
        [System.IO.Pipes.PipeTransmissionMode]::Message,
        [System.IO.Pipes.PipeOptions]::None,
        4096,
        4096
    )
    
    Write-Host "[MockServer] Waiting for client connection..." -ForegroundColor Yellow
    $pipe.WaitForConnection()
    Write-Host "[MockServer] Client connected!" -ForegroundColor Green
    Write-Host ""
    
    $reader = New-Object System.IO.BinaryReader($pipe)
    $writer = New-Object System.IO.BinaryWriter($pipe)
    
    $requestCount = 0
    
    while ($pipe.IsConnected) {
        try {
            # Read header (24 bytes)
            $headerBytes = $reader.ReadBytes(24)
            if ($headerBytes.Length -ne 24) { continue }
            
            $magic = [BitConverter]::ToUInt32($headerBytes, 0)
            $version = [BitConverter]::ToUInt32($headerBytes, 4)
            $type = [BitConverter]::ToUInt32($headerBytes, 8)
            $payloadSize = [BitConverter]::ToUInt32($headerBytes, 12)
            $timestamp = [BitConverter]::ToUInt64($headerBytes, 16)
            $requestId = [BitConverter]::ToUInt32($headerBytes, 20)
            
            # Validate magic
            if ($magic -ne 0x534F5645) {  # 'SOVE'
                Write-Host "[MockServer] Invalid magic: $magic" -ForegroundColor Red
                continue
            }
            
            # Read payload
            $payload = ""
            if ($payloadSize -gt 0) {
                $payloadBytes = $reader.ReadBytes($payloadSize)
                $payload = [System.Text.Encoding]::UTF8.GetString($payloadBytes)
            }
            
            # Handle message
            switch ($type) {
                0x01 {  # COMPLETION_REQUEST
                    Write-Host "[MockServer] Request $requestId: COMPLETION_REQUEST" -ForegroundColor Cyan
                    
                    # Simulate first token latency
                    $firstLatency = Get-Random -Minimum $FirstTokenMin -Maximum $FirstTokenMax
                    Start-Sleep -Milliseconds $firstLatency
                    
                    # Send first token
                    $token1 = @{ token = "acci"; is_final = $false } | ConvertTo-Json -Compress
                    Send-Message -Writer $writer -Type 0x10 -RequestId $requestId -Payload $token1
                    
                    # Tokenize and send remaining tokens
                    $tokens = $completionText -split "\s+"
                    $tokenCount = 1
                    
                    foreach ($token in $tokens) {
                        if ($tokenCount -ge 50) { break }
                        
                        $subLatency = Get-Random -Minimum $SubsequentMin -Maximum $SubsequentMax
                        Start-Sleep -Milliseconds $subLatency
                        
                        $isFinal = ($tokenCount -eq $tokens.Length - 1)
                        $tokenObj = @{ token = "$token "; is_final = $isFinal } | ConvertTo-Json -Compress
                        Send-Message -Writer $writer -Type 0x10 -RequestId $requestId -Payload $tokenObj
                        
                        $tokenCount++
                    }
                    
                    # Send completion
                    $totalTime = $firstLatency + ($tokenCount * ($SubsequentMin + $SubsequentMax) / 2)
                    $completeObj = @{ 
                        total_tokens = $tokenCount
                        total_time_ms = $totalTime
                    } | ConvertTo-Json -Compress
                    
                    Send-Message -Writer $writer -Type 0x11 -RequestId $requestId -Payload $completeObj
                    
                    Write-Host "[MockServer] Request $requestId complete: $tokenCount tokens" -ForegroundColor Green
                    $requestCount++
                }
                
                0x02 {  # CANCEL_REQUEST
                    Write-Host "[MockServer] Request $requestId: CANCEL_REQUEST" -ForegroundColor Yellow
                }
                
                default {
                    Write-Host "[MockServer] Unknown type: $type" -ForegroundColor Red
                }
            }
        }
        catch {
            if ($_.Exception.Message -like "*broken pipe*" -or $_.Exception.Message -like "*disconnected*") {
                Write-Host "[MockServer] Client disconnected" -ForegroundColor Yellow
                break
            }
            Write-Host "[MockServer] Error: $_" -ForegroundColor Red
        }
    }
    
    Write-Host "[MockServer] Shut down. Handled $requestCount requests" -ForegroundColor Green
}
catch {
    Write-Host "[MockServer] Fatal error: $_" -ForegroundColor Red
    exit 1
}
finally {
    if ($pipe) { $pipe.Dispose() }
}

function Send-Message {
    param($Writer, [int]$Type, [int]$RequestId, [string]$Payload)
    
    $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($Payload)
    
    # Build header
    $header = New-Object byte[] 24
    [BitConverter]::GetBytes([uint32]0x534F5645).CopyTo($header, 0)   # magic
    [BitConverter]::GetBytes([uint32]1).CopyTo($header, 4)             # version
    [BitConverter]::GetBytes([uint32]$Type).CopyTo($header, 8)       # type
    [BitConverter]::GetBytes([uint32]$payloadBytes.Length).CopyTo($header, 12)  # payload size
    [BitConverter]::GetBytes([uint64]0).CopyTo($header, 16)          # timestamp
    [BitConverter]::GetBytes([uint32]$RequestId).CopyTo($header, 20) # request id
    
    $Writer.Write($header)
    $Writer.Write($payloadBytes)
    $Writer.Flush()
}
