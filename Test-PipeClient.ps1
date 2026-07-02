# Sovereign Named Pipe Client Test
# Tests communication with running Sovereign Engine

param(
    [string]$Prompt = "Hello, I am testing the Sovereign Engine. Please respond with a short greeting.",
    [int]$MaxTokens = 50
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SOVEREIGN PIPE CLIENT TEST" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if pipe exists
$PipeName = "RawrXD_Sovereign"
$PipePath = "\\.\pipe\$PipeName"

Write-Host "Checking for named pipe: $PipePath" -ForegroundColor Yellow

try {
    $pipeExists = Test-Path $PipePath
    if (-not $pipeExists) {
        Write-Host "❌ Pipe not found! Is SovereignOrchestrator running?" -ForegroundColor Red
        Write-Host "   Launch with: .\Launch-Sovereign-Complete.ps1" -ForegroundColor Yellow
        exit 1
    }
    
    Write-Host "✅ Pipe found! Connecting..." -ForegroundColor Green
    Write-Host ""
    
    # Build JSON request
    $request = @{
        prompt = $Prompt
        max_tokens = $MaxTokens
        temperature = 0.7
        top_p = 0.9
    } | ConvertTo-Json -Compress
    
    Write-Host "Request:" -ForegroundColor Yellow
    Write-Host "  $request" -ForegroundColor Gray
    Write-Host ""
    
    # Connect to pipe
    $client = New-Object System.IO.Pipes.NamedPipeClientStream(".", $PipeName, [System.IO.Pipes.PipeDirection]::InOut)
    $client.Connect(5000)  # 5 second timeout
    
    Write-Host "✅ Connected to Sovereign Engine!" -ForegroundColor Green
    Write-Host ""
    
    # Send request
    $writer = New-Object System.IO.StreamWriter($client)
    $writer.AutoFlush = $true
    $writer.WriteLine($request)
    
    Write-Host "📤 Request sent, waiting for response..." -ForegroundColor Yellow
    Write-Host ""
    
    # Read response
    $reader = New-Object System.IO.StreamReader($client)
    $response = $reader.ReadLine()
    
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  RESPONSE FROM SOVEREIGN ENGINE" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Try to parse as JSON
    try {
        $responseObj = $response | ConvertFrom-Json
        Write-Host "Text: $($responseObj.text)" -ForegroundColor Green
        Write-Host "Tokens Generated: $($responseObj.tokens_generated)" -ForegroundColor Gray
        Write-Host "Time: $($responseObj.generation_time_ms) ms" -ForegroundColor Gray
    } catch {
        Write-Host "Raw Response:" -ForegroundColor Yellow
        Write-Host $response -ForegroundColor Green
    }
    
    # Cleanup
    $reader.Close()
    $writer.Close()
    $client.Close()
    
    Write-Host ""
    Write-Host "✅ Test complete!" -ForegroundColor Green
    
} catch {
    Write-Host "❌ Error: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  1. Is SovereignOrchestrator.exe running?" -ForegroundColor Gray
    Write-Host "  2. Check Task Manager for the process" -ForegroundColor Gray
    Write-Host "  3. Try restarting the engine" -ForegroundColor Gray
}
