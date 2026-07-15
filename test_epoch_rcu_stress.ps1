# ============================================================================
# RawrXD Epoch-RCU Stress Test
# ============================================================================
# Phase 4C: Concurrent inference + hotpatch stress test
# Tests the lock-free Epoch-RCU state machine under heavy contention
# ============================================================================

param(
    [int]$DurationSeconds = 10,
    [int]$NumWorkers = 4,
    [int]$HotpatchIntervalMs = 500
)

$ErrorActionPreference = "Stop"
${script:ServerProcess} = $null
${script:TestPassed} = $false
${script:TotalRequests} = 0
${script:TotalHotpatches} = 0
${script:Errors} = 0

function Write-Header($text) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host $text -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
}

function Start-Server() {
    Write-Host "[INFO] Starting rawrxd-cli server for stress test..."
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "d:\rawrxd\build\bin\rawrxd-cli.exe"
    $pinfo.Arguments = "--pipe-server"
    $pinfo.UseShellExecute = $false
    $pinfo.RedirectStandardOutput = $true
    $pinfo.RedirectStandardError = $true
    $pinfo.CreateNoWindow = $true
    
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $pinfo
    $process.Start() | Out-Null
    
    ${script:ServerProcess} = $process
    
    # Wait for server to initialize
    Start-Sleep -Milliseconds 500
    
    if ($process.HasExited) {
        throw "Server process exited immediately"
    }
    
    Write-Host "[OK] Server started (PID: $($process.Id))"
    return $process
}

function Stop-Server() {
    if (${script:ServerProcess} -and !${script:ServerProcess}.HasExited) {
        Write-Host "[INFO] Stopping server (PID: $(${script:ServerProcess}.Id))..."
        ${script:ServerProcess}.Kill()
        ${script:ServerProcess}.WaitForExit(5000) | Out-Null
        ${script:ServerProcess} = $null
    }
}

function Send-PipeCommand($command) {
    try {
        $pipeName = "RawrXD_Inference"
        $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".", $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
        $pipe.Connect(1000)
        
        $writer = New-Object System.IO.StreamWriter($pipe)
        $reader = New-Object System.IO.StreamReader($pipe)
        $writer.AutoFlush = $true
        
        $writer.WriteLine($command)
        $response = $reader.ReadLine()
        
        $writer.Close()
        $reader.Close()
        $pipe.Close()
        
        return $response
    }
    catch {
        return $null
    }
}

function Test-InferenceWorker($workerId, $durationSeconds) {
    $requests = 0
    $localErrors = 0
    $startTime = Get-Date
    
    while (((Get-Date) - $startTime).TotalSeconds -lt $durationSeconds) {
        # Send status command as inference request
        $response = Send-PipeCommand '{"cmd":"status"}'
        
        if ($response) {
            $requests++
        } else {
            $localErrors++
        }
        
        # Small delay to prevent overwhelming
        if ($requests % 10 -eq 0) {
            Start-Sleep -Milliseconds 1
        }
    }
    
    return @{
        WorkerId = $workerId
        Requests = $requests
        Errors = $localErrors
    }
}

function Test-HotpatchThread($durationSeconds, $intervalMs) {
    $hotpatches = 0
    $startTime = Get-Date
    
    while (((Get-Date) - $startTime).TotalSeconds -lt $durationSeconds) {
        Start-Sleep -Milliseconds $intervalMs
        
        # Send hotpatch command with dummy model
        $response = Send-PipeCommand '{"cmd":"hotpatch","model_path":"test_model.gguf"}'
        
        if ($response) {
            $hotpatches++
        }
    }
    
    return $hotpatches
}

# ============================================================================
# Main Test
# ============================================================================

try {
    Write-Header "Epoch-RCU Stress Test"
    Write-Host "Duration: $DurationSeconds seconds"
    Write-Host "Workers: $NumWorkers"
    Write-Host "Hotpatch Interval: $HotpatchIntervalMs ms"
    
    # Start server
    Start-Server
    
    # Give server time to fully initialize
    Start-Sleep -Milliseconds 500
    
    Write-Header "Starting Stress Test"
    
    # Create runspace pool for parallel workers
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $NumWorkers + 1)
    $runspacePool.Open()
    $runspaces = @()
    
    # Start inference workers
    for ($i = 0; $i -lt $NumWorkers; $i++) {
        $powershell = [powershell]::Create().AddScript({
            param($workerId, $duration)
            
            # Import functions
            function Send-PipeCommand($command) {
                try {
                    $pipeName = "RawrXD_Inference"
                    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".", $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
                    $pipe.Connect(1000)
                    
                    $writer = New-Object System.IO.StreamWriter($pipe)
                    $reader = New-Object System.IO.StreamReader($pipe)
                    $writer.AutoFlush = $true
                    
                    $writer.WriteLine($command)
                    $response = $reader.ReadLine()
                    
                    $writer.Close()
                    $reader.Close()
                    $pipe.Close()
                    
                    return $response
                }
                catch {
                    return $null
                }
            }
            
            $requests = 0
            $localErrors = 0
            $startTime = Get-Date
            
            while (((Get-Date) - $startTime).TotalSeconds -lt $duration) {
                $response = Send-PipeCommand '{"cmd":"status"}'
                
                if ($response) {
                    $requests++
                } else {
                    $localErrors++
                }
                
                if ($requests % 10 -eq 0) {
                    Start-Sleep -Milliseconds 1
                }
            }
            
            return @{
                WorkerId = $workerId
                Requests = $requests
                Errors = $localErrors
            }
        }).AddArgument($i).AddArgument($DurationSeconds)
        
        $powershell.RunspacePool = $runspacePool
        $runspaces += @{
            Pipe = $powershell
            Status = $powershell.BeginInvoke()
            Type = "Worker"
        }
    }
    
    # Start hotpatch thread
    $hotpatchPowerShell = [powershell]::Create().AddScript({
        param($duration, $interval)
        
        function Send-PipeCommand($command) {
            try {
                $pipeName = "RawrXD_Inference"
                $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".", $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
                $pipe.Connect(1000)
                
                $writer = New-Object System.IO.StreamWriter($pipe)
                $reader = New-Object System.IO.StreamReader($pipe)
                $writer.AutoFlush = $true
                
                $writer.WriteLine($command)
                $response = $reader.ReadLine()
                
                $writer.Close()
                $reader.Close()
                $pipe.Close()
                
                return $response
            }
            catch {
                return $null
            }
        }
        
        $hotpatches = 0
        $startTime = Get-Date
        
        while (((Get-Date) - $startTime).TotalSeconds -lt $duration) {
            Start-Sleep -Milliseconds $interval
            
            $response = Send-PipeCommand '{"cmd":"hotpatch","model_path":"test_model.gguf"}'
            
            if ($response) {
                $hotpatches++
            }
        }
        
        return $hotpatches
    }).AddArgument($DurationSeconds).AddArgument($HotpatchIntervalMs)
    
    $hotpatchPowerShell.RunspacePool = $runspacePool
    $runspaces += @{
        Pipe = $hotpatchPowerShell
        Status = $hotpatchPowerShell.BeginInvoke()
        Type = "Hotpatch"
    }
    
    # Wait for completion
    Write-Host "[INFO] Running stress test for $DurationSeconds seconds..."
    Write-Host ""
    
    $progress = 0
    $lastProgress = 0
    $startTime = Get-Date
    
    while ($runspaces | Where-Object { !$_.Status.IsCompleted }) {
        Start-Sleep -Milliseconds 100
        
        $elapsed = ((Get-Date) - $startTime).TotalSeconds
        $progress = [math]::Min(100, [math]::Floor(($elapsed / $DurationSeconds) * 100))
        
        if ($progress -ne $lastProgress -and $progress % 10 -eq 0) {
            Write-Host "Progress: $progress%" -ForegroundColor Yellow
            $lastProgress = $progress
        }
    }
    
    # Collect results
    $totalRequests = 0
    $totalErrors = 0
    $totalHotpatches = 0
    
    foreach ($rs in $runspaces) {
        $result = $rs.Pipe.EndInvoke($rs.Status)
        
        if ($rs.Type -eq "Worker") {
            $totalRequests += $result[0].Requests
            $totalErrors += $result[0].Errors
        } else {
            $totalHotpatches = $result[0]
        }
        
        $rs.Pipe.Dispose()
    }
    
    $runspacePool.Close()
    $runspacePool.Dispose()
    
    # Print results
    Write-Header "Stress Test Results"
    Write-Host "Total Inference Requests: $totalRequests" -ForegroundColor Green
    Write-Host "Total Hotpatches: $totalHotpatches" -ForegroundColor Green
    Write-Host "Total Errors: $totalErrors" -ForegroundColor $(if ($totalErrors -eq 0) { "Green" } else { "Red" })
    Write-Host "Success Rate: $([math]::Round(100 * ($totalRequests - $totalErrors) / [math]::Max(1, $totalRequests), 2))%" -ForegroundColor Green
    Write-Host ""
    Write-Host "Requests/Second: $([math]::Round($totalRequests / $DurationSeconds, 2))" -ForegroundColor Green
    Write-Host "Hotpatches/Second: $([math]::Round($totalHotpatches / $DurationSeconds, 2))" -ForegroundColor Green
    
    # Determine pass/fail
    if ($totalErrors -eq 0 -and $totalRequests -gt 0) {
        ${script:TestPassed} = $true
        Write-Host "`n[PASS] Epoch-RCU stress test completed successfully!" -ForegroundColor Green
    } else {
        ${script:TestPassed} = $false
        Write-Host "`n[FAIL] Epoch-RCU stress test failed with errors!" -ForegroundColor Red
    }
}
catch {
    Write-Host "`n[ERROR] $_" -ForegroundColor Red
    ${script:TestPassed} = $false
}
finally {
    Stop-Server
}

# Return exit code
if (${script:TestPassed}) {
    exit 0
} else {
    exit 1
}
