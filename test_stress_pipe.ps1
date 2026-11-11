# test_stress_pipe.ps1 - Stress test for RawrXD Named Pipe Server
# Phase 2 Stabilization: Verify DisconnectNamedPipe -> ConnectNamedPipe cycle
# Usage: .\test_stress_pipe.ps1 [-Iterations 100] [-TimeoutMs 1000]

param(
    [int]$Iterations = 100,
    [int]$TimeoutMs = 1000,
    [switch]$Verbose = $false
)

$ErrorActionPreference = "Stop"
$pipeName = "RawrXD_Inference"
$pipePath = "\\.\pipe\$pipeName"

Write-Host "=========================================="
Write-Host "RawrXD Pipe Stress Test"
Write-Host "Iterations: $Iterations"
Write-Host "Timeout: ${TimeoutMs}ms"
Write-Host "=========================================="
Write-Host ""

# Stale binary guard
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

$passCount = 0
$failCount = 0
$failures = @()
$startTime = Get-Date

for ($i = 1; $i -le $Iterations; $i++) {
    $iterationStart = Get-Date
    $success = $false
    $errorMsg = ""

    try {
        $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".", $pipeName,
            [System.IO.Pipes.PipeDirection]::InOut,
            [System.IO.Pipes.PipeOptions]::None)

        $pipe.Connect($TimeoutMs)

        # Send minimal payload
        $payload = '{"test": "iteration_' + $i + '"}' + "`n"
        $payloadBytes = [System.Text.Encoding]::ASCII.GetBytes($payload)
        $pipe.Write($payloadBytes, 0, $payloadBytes.Length)
        $pipe.Flush()

        # Try to read response (may timeout, that's ok)
        $buffer = New-Object byte[] 256
        $asyncResult = $pipe.BeginRead($buffer, 0, $buffer.Length, $null, $null)
        if ($asyncResult.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            $bytesRead = $pipe.EndRead($asyncResult)
            if ($bytesRead -gt 0) {
                $success = $true
            }
        }

        $pipe.Close()
        if (-not $success) {
            # Connection succeeded but no response - still counts as partial success
            $success = $true
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        $success = $false
    }

    $iterationTime = ((Get-Date) - $iterationStart).TotalMilliseconds

    if ($success) {
        $passCount++
        if ($Verbose -or $i % 10 -eq 0) {
            Write-Host "[$i/$Iterations] PASS (${iterationTime}ms)" -ForegroundColor Green
        }
    } else {
        $failCount++
        $failures += "Iteration $i`: $errorMsg"
        Write-Host "[$i/$Iterations] FAIL: $errorMsg" -ForegroundColor Red
    }
}

$totalTime = (Get-Date) - $startTime

Write-Host ""
Write-Host "=========================================="
Write-Host "Stress Test Results"
Write-Host "=========================================="
Write-Host "Total:    $Iterations" -ForegroundColor White
Write-Host "Passed:   $passCount" -ForegroundColor Green
Write-Host "Failed:   $failCount" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Green" })
Write-Host "Duration: $($totalTime.ToString('mm\:ss\.fff'))" -ForegroundColor White
Write-Host "Avg/conn: $([math]::Round($totalTime.TotalMilliseconds / $Iterations, 2))ms" -ForegroundColor White

if ($failCount -gt 0) {
    Write-Host ""
    Write-Host "First 10 failures:" -ForegroundColor Red
    $failures | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
}

Write-Host ""
if ($failCount -eq 0) {
    Write-Host "[SUCCESS] All $Iterations connections succeeded!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "[FAILURE] $failCount of $Iterations connections failed" -ForegroundColor Red
    exit 1
}
