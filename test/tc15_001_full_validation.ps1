# =============================================================================
# tc15_001_full_validation.ps1
# Complete TC15_001 Test with Mock Server
# =============================================================================

param(
    [int]$Iterations = 100,
    [switch]$SkipAnalysis
)

$ErrorActionPreference = "Stop"

Write-Host "=== TC15_001 Full Validation ===" -ForegroundColor Green
Write-Host "Iterations: $Iterations" -ForegroundColor Cyan
Write-Host ""

# Start mock server in background
Write-Host "[Setup] Starting Sovereign Mock Server..." -ForegroundColor Yellow
$serverJob = Start-Job -ScriptBlock {
    param($path)
    & (Join-Path $path "test\sovereign_mock_server.ps1")
} -ArgumentList "D:\RawrXD"

# Wait for server to initialize
Write-Host "[Setup] Waiting for server to initialize..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

# Check if server is running
if ($serverJob.State -ne "Running") {
    Write-Host "[Setup] Failed to start mock server!" -ForegroundColor Red
    $jobOutput = Receive-Job -Job $serverJob
    Write-Host $jobOutput
    exit 1
}

Write-Host "[Setup] Mock server running (Job ID: $($serverJob.Id))" -ForegroundColor Green
Write-Host ""

# Run the test
try {
    Write-Host "[Test] Executing $Iterations iterations..." -ForegroundColor Yellow
    & "D:\RawrXD\test\tc15_001_runner.ps1" -Iterations $Iterations -Verbose
    
    if ($LASTEXITCODE -ne 0) {
        throw "Test runner failed with exit code $LASTEXITCODE"
    }
    
    Write-Host "[Test] Test execution complete!" -ForegroundColor Green
    Write-Host ""
    
    # Run analysis
    if (!$SkipAnalysis) {
        Write-Host "[Analysis] Running telemetry analysis..." -ForegroundColor Yellow
        & "D:\RawrXD\test\tc15_001_analyzer.ps1"
        
        # Display the analysis report
        $reportPath = "D:\RawrXD\logs\tc15_001_analysis.md"
        if (Test-Path $reportPath) {
            Write-Host "`n=== Analysis Report ===" -ForegroundColor Green
            Get-Content $reportPath -Raw | Write-Host
        }
    }
}
finally {
    # Cleanup
    Write-Host "`n[Cleanup] Stopping mock server..." -ForegroundColor Yellow
    Stop-Job $serverJob -ErrorAction SilentlyContinue
    Remove-Job $serverJob -ErrorAction SilentlyContinue
    Write-Host "[Cleanup] Complete" -ForegroundColor Green
}

Write-Host "`n=== TC15_001 Full Validation Complete ===" -ForegroundColor Green
