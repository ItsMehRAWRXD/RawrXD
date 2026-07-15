# RawrXD Named Pipe Bytecode Injection Test Script
# Tests the hotpatch router via named pipe IPC
# Usage: .\test_hotpatch_pipe.ps1

param(
    [string]$PipeName = "RawrXD_Inference",
    [int]$TimeoutMs = 5000,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

function Write-VerboseLog {
    param([string]$Message)
    if ($Verbose) {
        Write-Host "[TEST] $Message" -ForegroundColor Cyan
    }
}

function Test-NamedPipeConnection {
    param([string]$Pipe)
    
    $pipePath = "\\.\pipe\$Pipe"
    Write-VerboseLog "Testing connection to: $pipePath"
    
    try {
        $client = New-Object System.IO.Pipes.NamedPipeClientStream(
            ".", 
            $Pipe, 
            [System.IO.Pipes.PipeDirection]::InOut,
            [System.IO.Pipes.PipeOptions]::None
        )
        
        $client.Connect($TimeoutMs)
        Write-VerboseLog "Connected successfully to pipe"
        
        $writer = New-Object System.IO.StreamWriter($client)
        $reader = New-Object System.IO.StreamReader($client)
        $writer.AutoFlush = $true
        
        # Send test bytecode injection request
        $testRequest = @{
            opcode = "HOTPATCH_REQUEST"
            model_id = "test_model_v1"
            epoch = 1
            bytecode = @(0x48, 0x89, 0x5C, 0x24, 0x08)  # mov [rsp+8], rbx
        } | ConvertTo-Json -Compress
        
        Write-VerboseLog "Sending test request: $testRequest"
        $writer.WriteLine($testRequest)
        
        # Read response
        $response = $reader.ReadLine()
        Write-VerboseLog "Received response: $response"
        
        $client.Close()
        
        return $true
    }
    catch {
        Write-VerboseLog "Connection failed: $_"
        return $false
    }
}

function Start-RawrXDHeadless {
    param([string]$ExePath)
    
    if (-not (Test-Path $ExePath)) {
        throw "Executable not found: $ExePath"
    }
    
    Write-VerboseLog "Starting RawrXD headless mode: $ExePath"
    
    $process = Start-Process -FilePath $ExePath `
        -ArgumentList "--headless" `
        -PassThru `
        -WindowStyle Hidden
    
    Write-VerboseLog "Started process PID: $($process.Id)"
    
    # Wait for pipe to be ready
    Start-Sleep -Milliseconds 500
    
    return $process
}

# Main test execution
Write-Host "=== RawrXD Named Pipe Hotpatch Test ===" -ForegroundColor Green

$exePath = "..\build-ninja\bin\rawrxd-cli.exe"
$process = $null

try {
    # Start RawrXD in headless mode
    $process = Start-RawrXDHeadless -ExePath $exePath
    
    # Test pipe connection
    Write-Host "Testing named pipe connection..." -ForegroundColor Yellow
    $connected = Test-NamedPipeConnection -Pipe $PipeName
    
    if ($connected) {
        Write-Host "✓ Named pipe test PASSED" -ForegroundColor Green
    } else {
        Write-Host "✗ Named pipe test FAILED" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "=== Test Complete ===" -ForegroundColor Green
}
finally {
    if ($process -and -not $process.HasExited) {
        Write-VerboseLog "Terminating process $($process.Id)"
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    }
}