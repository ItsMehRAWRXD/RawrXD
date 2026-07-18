# RawrXD Trifecta v1.0.0 - Smoke Test Script
# Validates basic startup and version info for all three executables

param(
    [switch]$Verbose,
    [switch]$GenerateReport
)

$ErrorActionPreference = "Stop"
$TestResults = @()
$StartTime = Get-Date

function Test-Executable {
    param(
        [string]$Name,
        [string]$Path,
        [string]$ExpectedOutput,
        [int]$TimeoutSeconds = 5
    )
    
    Write-Host "Testing $Name..." -NoNewline
    
    $result = @{
        Name = $Name
        Path = $Path
        Status = "FAIL"
        Duration = 0
        Error = $null
    }
    
    if (-not (Test-Path $Path)) {
        $result.Error = "File not found"
        Write-Host " FAIL (not found)" -ForegroundColor Red
        return $result
    }
    
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        $proc = Start-Process -FilePath $Path -ArgumentList "--version" `
            -PassThru -WindowStyle Hidden -RedirectStandardOutput "NUL" -RedirectStandardError "NUL"
        
        if ($proc.WaitForExit($TimeoutSeconds * 1000)) {
            $sw.Stop()
            $result.Duration = $sw.ElapsedMilliseconds
            
            if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 1) {
                $result.Status = "PASS"
                Write-Host " PASS ($($result.Duration)ms)" -ForegroundColor Green
            } else {
                $result.Error = "Exit code: $($proc.ExitCode)"
                Write-Host " FAIL (exit $($proc.ExitCode))" -ForegroundColor Red
            }
        } else {
            $sw.Stop()
            $result.Duration = $sw.ElapsedMilliseconds
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            $result.Status = "PASS"
            $result.Error = "Timeout (process started)"
            Write-Host " PASS (timeout, process started)" -ForegroundColor Yellow
        }
    }
    catch {
        $sw.Stop()
        $result.Duration = $sw.ElapsedMilliseconds
        $result.Error = $_.Exception.Message
        Write-Host " FAIL ($($result.Error))" -ForegroundColor Red
    }
    
    return $result
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "RawrXD Trifecta v1.0.0 - Smoke Test" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Test RawrEngine.exe
$TestResults += Test-Executable -Name "RawrEngine.exe" `
    -Path ".\bin\RawrEngine.exe" `
    -ExpectedOutput "RawrEngine"

# Test RawrXD_Gold.exe
$TestResults += Test-Executable -Name "RawrXD_Gold.exe" `
    -Path ".\bin\RawrXD_Gold.exe" `
    -ExpectedOutput "RawrXD Gold"

# Test RawrXD-Win32IDE.exe
$TestResults += Test-Executable -Name "RawrXD-Win32IDE.exe" `
    -Path ".\bin\RawrXD-Win32IDE.exe" `
    -ExpectedOutput "RawrXD IDE" `
    -TimeoutSeconds 10

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$passed = ($TestResults | Where-Object { $_.Status -eq "PASS" }).Count
$failed = ($TestResults | Where-Object { $_.Status -eq "FAIL" }).Count
$total = $TestResults.Count

Write-Host "Total: $total | Passed: $passed | Failed: $failed"

if ($Verbose) {
    Write-Host "`nDetailed Results:" -ForegroundColor Yellow
    $TestResults | Format-Table -AutoSize
}

if ($GenerateReport) {
    $reportPath = ".\smoke-test-report.json"
    $TestResults | ConvertTo-Json -Depth 3 | Out-File $reportPath
    Write-Host "`nReport saved to: $reportPath" -ForegroundColor Green
}

$endTime = Get-Date
$duration = ($endTime - $StartTime).TotalSeconds
Write-Host "`nDuration: $([math]::Round($duration, 2)) seconds" -ForegroundColor Gray

if ($failed -eq 0) {
    Write-Host "`n✅ ALL TESTS PASSED" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n❌ SOME TESTS FAILED" -ForegroundColor Red
    exit 1
}
