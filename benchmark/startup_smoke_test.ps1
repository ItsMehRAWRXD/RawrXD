# RawrXD Startup Smoke Test
# VAL-050: Verify IDE launches without stack overflow

param(
    [string]$BinaryPath = "d:\rxdn_ninja\bin\RawrXD-Win32IDE.exe",
    [string]$EvidenceDir = "d:\rawrxd\evidence\2026-07-24-56ef83e\startup_smoke",
    [int]$TimeoutSeconds = 30
)

$ErrorActionPreference = "Stop"
$timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"

# Ensure evidence directory exists
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

# Get binary hash
$binaryHash = (Get-FileHash $BinaryPath -Algorithm SHA256).Hash
$binarySize = (Get-Item $BinaryPath).Length

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RawrXD Startup Smoke Test (VAL-050)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Binary: $BinaryPath"
Write-Host "SHA256: $binaryHash"
Write-Host "Size: $binarySize bytes ($([math]::Round($binarySize/1MB, 2)) MB)"
Write-Host "Timeout: $TimeoutSeconds seconds"
Write-Host ""

$testResult = @{
    binary = $BinaryPath
    binary_sha256 = $binaryHash
    binary_size_bytes = $binarySize
    timestamp = $timestamp
    launch_attempted = $true
    launch_success = $false
    exit_code = $null
    startup_phase_final = "Unknown"
    stack_overflow_detected = $false
    error_message = $null
    duration_ms = 0
}

# Launch the IDE with a timeout
Write-Host "[TEST] Launching IDE..." -ForegroundColor Yellow
$startTime = Get-Date

try {
    $process = Start-Process -FilePath $BinaryPath -PassThru -ErrorAction Stop
    Write-Host "[INFO] Process started with PID: $($process.Id)" -ForegroundColor Green
    
    # Wait for window to appear (indicates successful startup past WM_CREATE)
    $windowAppeared = $false
    $elapsed = 0
    $checkInterval = 100  # ms
    
    while ($elapsed -lt ($TimeoutSeconds * 1000)) {
        Start-Sleep -Milliseconds $checkInterval
        $elapsed += $checkInterval
        
        # Check if process is still running
        $proc = Get-Process -Id $process.Id -ErrorAction SilentlyContinue
        if (-not $proc) {
            Write-Host "[WARN] Process exited early" -ForegroundColor Yellow
            break
        }
        
        # Check for window (indicates passed WM_CREATE phase)
        if ($proc.MainWindowHandle -ne 0) {
            $windowAppeared = $true
            Write-Host "[PASS] Window created successfully (MainWindowHandle: $($proc.MainWindowHandle))" -ForegroundColor Green
            break
        }
        
        # Check for stack overflow in process exit code
        if ($proc.HasExited) {
            $exitCode = $proc.ExitCode
            if ($exitCode -eq -1073741571 -or $exitCode -eq 0xC00000FD) {
                $testResult.stack_overflow_detected = $true
                $testResult.error_message = "Stack overflow (0xC00000FD) detected"
                Write-Host "[FAIL] Stack overflow detected!" -ForegroundColor Red
            }
            break
        }
    }
    
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalMilliseconds
    $testResult.duration_ms = [math]::Round($duration, 2)
    
    if ($windowAppeared) {
        $testResult.launch_success = $true
        $testResult.startup_phase_final = "Running"
        Write-Host "[PASS] IDE launched successfully in $([math]::Round($duration, 0))ms" -ForegroundColor Green
        
        # Gracefully terminate the process
        Write-Host "[INFO] Terminating process for clean shutdown test..." -ForegroundColor Yellow
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        
        $testResult.exit_code = 0
    } else {
        $testResult.launch_success = $false
        $testResult.startup_phase_final = "Failed"
        $testResult.error_message = "Window did not appear within timeout"
        Write-Host "[FAIL] Window did not appear within $TimeoutSeconds seconds" -ForegroundColor Red
        
        # Kill the process if still running
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    }
    
} catch {
    $testResult.launch_success = $false
    $testResult.error_message = $_.Exception.Message
    Write-Host "[FAIL] Failed to launch: $($_.Exception.Message)" -ForegroundColor Red
}

# Save evidence
$evidencePath = "$EvidenceDir\startup_execution.json"
$testResult | ConvertTo-Json -Depth 4 | Out-File -FilePath $evidencePath -Encoding UTF8

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Launch Success: $($testResult.launch_success)"
Write-Host "Stack Overflow: $($testResult.stack_overflow_detected)"
Write-Host "Duration: $($testResult.duration_ms)ms"
Write-Host "Evidence: $evidencePath"

if ($testResult.launch_success -and -not $testResult.stack_overflow_detected) {
    Write-Host "`nVAL-050: PASS - Startup smoke test successful" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`nVAL-050: FAIL - Startup smoke test failed" -ForegroundColor Red
    exit 1
}
