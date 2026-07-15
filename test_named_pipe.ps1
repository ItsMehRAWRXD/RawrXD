# Named Pipe Test Script for RawrXD CLI
# Tests bytecode injection via \\.\pipe\RawrXD_Inference

param(
    [int]$TimeoutSeconds = 10
)

# === STALE BINARY GUARD ===
$exe = 'd:\rawrxd\build\bin\rawrxd-cli.exe'
$obj = 'd:\rawrxd\build\CMakeFiles\rawrxd.dir\src\cli\cli_main.cpp.obj'
if ((Test-Path $exe) -and (Test-Path $obj)) {
    if ((Get-Item $exe).LastWriteTime -lt (Get-Item $obj).LastWriteTime) {
        Write-Host "[FATAL] Stale binary — rebuild with: .\ninja-build.ps1 rawrxd" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[FATAL] Binary or object file missing — rebuild with: .\ninja-build.ps1 rawrxd" -ForegroundColor Red
    exit 1
}
# === END STALE BINARY GUARD ===

$pipeName = "RawrXD_Inference"
$pipePath = "\\.\pipe\$pipeName"

Write-Host "=========================================="
Write-Host "RawrXD Named Pipe IPC Test"
Write-Host "=========================================="
Write-Host ""

Write-Host "[INFO] Attempting to connect to pipe: $pipePath" -ForegroundColor Cyan

# Create test payload (simple JSON)
$testPayload = @{
    magic = 0x52485044  # "RHPD"
    version = 1
    payloadSize = 16
    flags = 0
    timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    crc32 = 0
    data = [byte[]](0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
                    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10)
}

Write-Host "[INFO] Connecting to pipe..." -ForegroundColor Cyan

try {
    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".", $pipeName, 
        [System.IO.Pipes.PipeDirection]::InOut, 
        [System.IO.Pipes.PipeOptions]::None)
    
    $pipe.Connect($TimeoutSeconds * 1000)
    Write-Host "[SUCCESS] Connected to pipe!" -ForegroundColor Green

    $pipe.ReadMode = [System.IO.Pipes.PipeTransmissionMode]::Byte
    
    # Send test data as raw bytes (avoid StreamWriter BOM/line buffering behavior)
    Write-Host "[INFO] Sending test payload..." -ForegroundColor Cyan
    $payloadText = '{"test": "hello from client"}' + "`n"
    $payloadBytes = [System.Text.Encoding]::ASCII.GetBytes($payloadText)
    $pipe.Write($payloadBytes, 0, $payloadBytes.Length)
    $pipe.Flush()
    
    # Read raw response bytes with BeginRead/EndRead so the timeout can expire cleanly.
    Write-Host "[INFO] Waiting for response..." -ForegroundColor Cyan
    $buffer = New-Object byte[] 256
    $bytesRead = 0
    $asyncResult = $pipe.BeginRead($buffer, 0, $buffer.Length, $null, $null)
    if (-not $asyncResult.AsyncWaitHandle.WaitOne($TimeoutSeconds * 1000)) {
        Write-Host "[WARNING] No response bytes received from server (timed out after ${TimeoutSeconds}s)" -ForegroundColor Yellow
    }
    else {
        $bytesRead = $pipe.EndRead($asyncResult)
    }
    if ($bytesRead -gt 0) {
        $response = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead).Trim([char]0, [char]10, [char]13)
        Write-Host "[SUCCESS] Response bytes: $bytesRead" -ForegroundColor Green
        Write-Host "[SUCCESS] Response received: $response" -ForegroundColor Green
    }
    else {
        Write-Host "[WARNING] No response bytes received from server (timed out after ${TimeoutSeconds}s)" -ForegroundColor Yellow
    }
    
    $pipe.Close()
    Write-Host "[SUCCESS] Pipe test completed!" -ForegroundColor Green
    exit 0
}
catch {
    Write-Host "[ERROR] Pipe test failed: $_" -ForegroundColor Red
    exit 1
}
