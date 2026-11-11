# Sovereign Chat Test Client
# Communicates with running SovereignOrchestrator via Named Pipe

param(
    [string]$Prompt = "Hello, how are you?",
    [int]$MaxTokens = 50,
    [int]$TimeoutSeconds = 30
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SOVEREIGN CHAT TEST CLIENT" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if orchestrator is running
$orchProcess = Get-Process -Name "SovereignOrchestrator" -ErrorAction SilentlyContinue
if (-not $orchProcess) {
    Write-Host "❌ SovereignOrchestrator is not running!" -ForegroundColor Red
    Write-Host "   Start it first with:" -ForegroundColor Yellow
    Write-Host "   .\Launch-Sovereign-Complete.ps1" -ForegroundColor White
    exit 1
}

Write-Host "✅ SovereignOrchestrator is running (PID: $($orchProcess.Id))" -ForegroundColor Green
Write-Host ""

# Named pipe path
$pipeName = "RawrXD_Sovereign"
$pipePath = "\\.\pipe\$pipeName"

Write-Host "Connecting to: $pipePath" -ForegroundColor Yellow
Write-Host ""

try {
    # Create JSON request
    $request = @{
        prompt = $Prompt
        max_tokens = $MaxTokens
        temperature = 0.7
        stream = $true
    } | ConvertTo-Json -Compress
    
    Write-Host "Request: $request" -ForegroundColor Gray
    Write-Host ""
    
    # Connect to named pipe
    $client = New-Object System.IO.Pipes.NamedPipeClientStream(".", $pipeName, 
        [System.IO.Pipes.PipeDirection]::InOut)
    
    Write-Host "Connecting..." -ForegroundColor Yellow
    $client.Connect($TimeoutSeconds * 1000)
    Write-Host "✅ Connected!" -ForegroundColor Green
    Write-Host ""
    
    # Send request
    $writer = New-Object System.IO.StreamWriter($client)
    $writer.AutoFlush = $true
    $writer.WriteLine($request)
    Write-Host "📤 Request sent" -ForegroundColor Yellow
    Write-Host ""
    
    # Read response
    $reader = New-Object System.IO.StreamReader($client)
    $response = $reader.ReadLine()
    
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  RESPONSE" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Try to parse as JSON
    try {
        $responseObj = $response | ConvertFrom-Json
        if ($responseObj.text) {
            Write-Host $responseObj.text -ForegroundColor Green
        } else {
            Write-Host ($responseObj | ConvertTo-Json -Depth 4) -ForegroundColor Green
        }
    } catch {
        Write-Host $response -ForegroundColor Green
    }
    
    # Cleanup
    $reader.Close()
    $writer.Close()
    $client.Close()
    
    Write-Host ""
    Write-Host "✅ Chat complete!" -ForegroundColor Green
    
} catch {
    Write-Host ""
    Write-Host "❌ Error: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  1. Is SovereignOrchestrator.exe running?" -ForegroundColor Gray
    Write-Host "  2. Check if pipe exists:" -ForegroundColor Gray
    Write-Host "     [System.IO.Directory]::GetFiles('\\.\\pipe\\') | Select-String 'RawrXD'" -ForegroundColor Gray
    Write-Host "  3. Try restarting the orchestrator" -ForegroundColor Gray
}
