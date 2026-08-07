# RawrXD Validation Watcher
# Continuously monitors validation results and provides real-time feedback

param(
    [Parameter(Mandatory=$false)]
    [string]$ValidationOutputPath = "validation_output",
    
    [Parameter(Mandatory=$false)]
    [int]$RefreshIntervalSeconds = 5,
    
    [Parameter(Mandatory=$false)]
    [switch]$AlertOnCompletion,
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowProgress,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportOnCompletion
)

$ErrorActionPreference = "Stop"

function Clear-Screen {
    $host.ui.RawUI.ClearScreen()
}

function Show-Header {
    param($title)
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  $title" -ForegroundColor Cyan -NoNewline
    Write-Host "$(' ' * (59 - $title.Length))║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Show-ProgressBar {
    param($percent, $width = 50)
    $filled = [math]::Floor($width * ($percent / 100))
    $empty = $width - $filled
    $bar = "█" * $filled + "░" * $empty
    Write-Host "  [$bar] $([math]::Round($percent, 1))%" -ForegroundColor Gray
}

function Get-LatestValidationRun {
    param($basePath)
    
    if (-not (Test-Path $basePath)) {
        return $null
    }
    
    $runs = Get-ChildItem -Directory -Path $basePath -Filter "run_*" | Sort-Object LastWriteTime -Descending
    if ($runs.Count -eq 0) {
        return $null
    }
    
    return $runs[0].FullName
}

function Get-ValidationStatus {
    param($runPath)
    
    $reportPath = Join-Path $runPath "final_validation_report.json"
    $summaryPath = Join-Path $runPath "validation_summary.json"
    
    $status = @{
        Exists = $false
        Complete = $false
        Report = $null
        Summary = $null
    }
    
    if (Test-Path $reportPath) {
        $status.Exists = $true
        $status.Report = Get-Content $reportPath | ConvertFrom-Json
        $status.Complete = $true
    }
    
    if (Test-Path $summaryPath) {
        $status.Summary = Get-Content $summaryPath | ConvertFrom-Json
    }
    
    return $status
}

function Show-CurrentStatus {
    param($status)
    
    if (-not $status.Exists) {
        Write-Host "  Waiting for validation to start..." -ForegroundColor Yellow
        return
    }
    
    if ($status.Summary) {
        $summary = $status.Summary
        
        Write-Host "  Validation Status" -ForegroundColor Cyan
        Write-Host "  ─────────────────" -ForegroundColor Cyan
        
        if ($summary.boot_phase) {
            $bootStatus = if ($summary.boot_phase.complete) { "✅ Complete" } else { "⏳ In Progress" }
            Write-Host "    Boot Phase: $bootStatus" -ForegroundColor $(if ($summary.boot_phase.complete) { "Green" } else { "Yellow" })
            if ($summary.boot_phase.duration_ms) {
                Write-Host "      Duration: $($summary.boot_phase.duration_ms)ms" -ForegroundColor Gray
            }
        }
        
        if ($summary.gateway_phase) {
            $gatewayStatus = if ($summary.gateway_phase.complete) { "✅ Complete" } else { "⏳ In Progress" }
            Write-Host "    Gateway Phase: $gatewayStatus" -ForegroundColor $(if ($summary.gateway_phase.complete) { "Green" } else { "Yellow" })
        }
        
        if ($summary.inference_phase) {
            $inferenceStatus = if ($summary.inference_phase.complete) { "✅ Complete" } else { "⏳ In Progress" }
            Write-Host "    Inference Phase: $inferenceStatus" -ForegroundColor $(if ($summary.inference_phase.complete) { "Green" } else { "Yellow" })
            if ($summary.inference_phase.iterations) {
                $progress = ($summary.inference_phase.iterations / $summary.inference_phase.total_iterations) * 100
                Show-ProgressBar $progress
            }
        }
        
        if ($summary.hardware_phase) {
            $hwStatus = if ($summary.hardware_phase.complete) { "✅ Complete" } else { "⏳ In Progress" }
            Write-Host "    Hardware Phase: $hwStatus" -ForegroundColor $(if ($summary.hardware_phase.complete) { "Green" } else { "Yellow" })
        }
    }
    
    if ($status.Complete -and $status.Report) {
        $report = $status.Report
        
        Write-Host ""
        Write-Host "  Results" -ForegroundColor Cyan
        Write-Host "  ────────" -ForegroundColor Cyan
        
        if ($report.certification) {
            $certStatus = if ($report.certification.all_passed) { "✅ PASSED" } else { "❌ FAILED" }
            Write-Host "    Certification: $certStatus" -ForegroundColor $(if ($report.certification.all_passed) { "Green" } else { "Red" })
        }
        
        if ($report.inference) {
            Write-Host "    TPS: $([math]::Round($report.inference.avg_tps, 1))" -ForegroundColor Gray
            Write-Host "    Latency: $([math]::Round($report.inference.avg_latency_ms, 0))ms" -ForegroundColor Gray
            Write-Host "    TTFT: $([math]::Round($report.inference.avg_ttft_ms, 0))ms" -ForegroundColor Gray
            Write-Host "    Success Rate: $([math]::Round($report.inference.success_rate * 100, 1))%" -ForegroundColor Gray
        }
        
        if ($report.hardware) {
            Write-Host "    GPUs Detected: $($report.hardware.gpu_count)" -ForegroundColor Gray
            if ($report.hardware.multi_gpu_ready) {
                Write-Host "    Multi-GPU: ✅ Ready" -ForegroundColor Green
            }
        }
    }
}

function Send-CompletionAlert {
    param($status, $runPath)
    
    if (-not $status.Complete) {
        return
    }
    
    $report = $status.Report
    $passed = $report.certification.all_passed
    
    # Windows notification
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $icon = if ($passed) { [System.Windows.Forms.ToolTipIcon]::Info } else { [System.Windows.Forms.ToolTipIcon]::Error }
        $title = if ($passed) { "RawrXD Validation Passed" } else { "RawrXD Validation Failed" }
        $text = if ($passed) { 
            "TPS: $([math]::Round($report.inference.avg_tps, 1)) | Latency: $([math]::Round($report.inference.avg_latency_ms, 0))ms" 
        } else { 
            "Some certification criteria not met. Check logs." 
        }
        
        $notification = New-Object System.Windows.Forms.NotifyIcon
        $notification.Icon = [System.Drawing.SystemIcons]::Information
        $notification.BalloonTipIcon = $icon
        $notification.BalloonTipTitle = $title
        $notification.BalloonTipText = $text
        $notification.Visible = $true
        $notification.ShowBalloonTip(5000)
    } catch {
        # Notification not available, use console beep
        if ($passed) {
            [console]::beep(800, 200)
            [console]::beep(1000, 200)
        } else {
            [console]::beep(400, 500)
        }
    }
    
    Write-Host ""
    Write-Host "  🔔 Validation complete!" -ForegroundColor Cyan
}

function Export-Results {
    param($status, $runPath)
    
    if (-not $status.Complete) {
        return
    }
    
    $exportDir = "validation_exports"
    if (-not (Test-Path $exportDir)) {
        New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $exportPath = Join-Path $exportDir "validation_$timestamp"
    
    Copy-Item -Path $runPath -Destination $exportPath -Recurse
    
    Write-Host ""
    Write-Host "  📁 Results exported to: $exportPath" -ForegroundColor Green
}

# ============================================================================
# Main Execution
# ============================================================================

Clear-Screen
Show-Header "RawrXD Validation Watcher"

Write-Host "  Monitoring: $ValidationOutputPath" -ForegroundColor Gray
Write-Host "  Refresh Interval: $RefreshIntervalSeconds seconds" -ForegroundColor Gray
Write-Host ""
Write-Host "  Press Ctrl+C to stop watching" -ForegroundColor Yellow
Write-Host ""

$lastStatus = $null
$completionAlerted = $false
$completionExported = $false

try {
    while ($true) {
        $latestRun = Get-LatestValidationRun -basePath $ValidationOutputPath
        
        if ($latestRun) {
            $status = Get-ValidationStatus -runPath $latestRun
            
            Clear-Screen
            Show-Header "RawrXD Validation Watcher"
            Show-CurrentStatus -status $status
            
            # Check for completion
            if ($status.Complete -and -not $completionAlerted) {
                if ($AlertOnCompletion) {
                    Send-CompletionAlert -status $status -runPath $latestRun
                }
                $completionAlerted = $true
                
                if ($ExportOnCompletion -and -not $completionExported) {
                    Export-Results -status $status -runPath $latestRun
                    $completionExported = $true
                }
                
                # Keep showing results but stop refreshing as frequently
                Write-Host ""
                Write-Host "  Validation complete. Press Ctrl+C to exit." -ForegroundColor Green
                
                while ($true) {
                    Start-Sleep -Seconds 1
                }
            }
            
            $lastStatus = $status
        } else {
            Clear-Screen
            Show-Header "RawrXD Validation Watcher"
            Write-Host "  Waiting for validation to start..." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  No validation runs found in: $ValidationOutputPath" -ForegroundColor Gray
        }
        
        Start-Sleep -Seconds $RefreshIntervalSeconds
    }
} catch {
    if ($_.Exception.Message -notlike "*Pipeline*") {
        Write-Error $_
    }
} finally {
    Write-Host ""
    Write-Host "  Stopped watching." -ForegroundColor Gray
}
