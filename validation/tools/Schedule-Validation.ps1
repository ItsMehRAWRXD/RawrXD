# RawrXD Validation Scheduler
# Schedule periodic validation runs for continuous monitoring

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Hourly", "Daily", "Weekly", "Custom")]
    [string]$Schedule = "Daily",
    
    [Parameter(Mandatory=$false)]
    [int]$IntervalMinutes = 60,
    
    [Parameter(Mandatory=$false)]
    [string]$TargetUrl = "http://127.0.0.1:8080",
    
    [Parameter(Mandatory=$false)]
    [int]$BenchmarkRuns = 50,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputDirectory = "validation_output\scheduled",
    
    [Parameter(Mandatory=$false)]
    [switch]$EnableRetention,
    
    [Parameter(Mandatory=$false)]
    [int]$RetentionDays = 30,
    
    [Parameter(Mandatory=$false)]
    [switch]$Install,
    
    [Parameter(Mandatory=$false)]
    [switch]$Uninstall,
    
    [Parameter(Mandatory=$false)]
    [switch]$RunNow,
    
    [Parameter(Mandatory=$false)]
    [switch]$ListJobs,
    
    [Parameter(Mandatory=$false)]
    [string]$JobName = "RawrXD_Validation"
)

$ErrorActionPreference = "Stop"

function Show-Header {
    Write-Host @"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║           RawrXD Validation Scheduler                      ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
    Write-Host ""
}

function Test-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-ScheduledJob {
    param($schedule, $interval)
    
    if (-not (Test-Admin)) {
        throw "Administrator privileges required to install scheduled jobs. Run as Administrator."
    }
    
    $action = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-ExecutionPolicy Bypass -File `"$PSScriptRoot\..\Validate-Production.ps1`" -TargetUrl `"$TargetUrl`" -BenchmarkRuns $BenchmarkRuns -OutputPath `"$OutputDirectory\$(Get-Date -Format 'yyyyMMdd_HHmmss')`""
    
    $trigger = switch ($schedule) {
        "Hourly" { New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1) }
        "Daily" { New-ScheduledTaskTrigger -Daily -At "02:00" }
        "Weekly" { New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At "02:00" }
        "Custom" { New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $interval) }
    }
    
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -RunOnlyIfNetworkAvailable
    
    $principal = New-ScheduledTaskPrincipal `
        -UserId "$env:USERDOMAIN\$env:USERNAME" `
        -LogonType Interactive
    
    try {
        Register-ScheduledTask `
            -TaskName $JobName `
            -Action $action `
            -Trigger $trigger `
            -Settings $settings `
            -Principal $principal `
            -Force
        
        Write-Host "✅ Scheduled job '$JobName' installed successfully" -ForegroundColor Green
        Write-Host "   Schedule: $schedule" -ForegroundColor Gray
        if ($schedule -eq "Custom") {
            Write-Host "   Interval: $interval minutes" -ForegroundColor Gray
        }
        Write-Host "   Target: $TargetUrl" -ForegroundColor Gray
        Write-Host "   Output: $OutputDirectory" -ForegroundColor Gray
    } catch {
        throw "Failed to install scheduled job: $_"
    }
}

function Uninstall-ScheduledJob {
    if (-not (Test-Admin)) {
        throw "Administrator privileges required to uninstall scheduled jobs. Run as Administrator."
    }
    
    try {
        Unregister-ScheduledTask -TaskName $JobName -Confirm:$false
        Write-Host "✅ Scheduled job '$JobName' uninstalled successfully" -ForegroundColor Green
    } catch {
        if ($_.Exception.Message -like "*The system cannot find the file specified*") {
            Write-Host "⚠️ Job '$JobName' not found" -ForegroundColor Yellow
        } else {
            throw "Failed to uninstall scheduled job: $_"
        }
    }
}

function Get-ScheduledJobs {
    $jobs = Get-ScheduledTask | Where-Object { $_.TaskName -like "*RawrXD*" }
    
    if ($jobs.Count -eq 0) {
        Write-Host "No RawrXD validation jobs found" -ForegroundColor Yellow
        return
    }
    
    Write-Host "Scheduled Jobs:" -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($job in $jobs) {
        $info = Get-ScheduledTaskInfo -TaskName $job.TaskName
        Write-Host "  $($job.TaskName)" -ForegroundColor White
        Write-Host "    State: $($job.State)" -ForegroundColor Gray
        Write-Host "    Last Run: $($info.LastRunTime)" -ForegroundColor Gray
        Write-Host "    Next Run: $($info.NextRunTime)" -ForegroundColor Gray
        Write-Host ""
    }
}

function Invoke-ValidationRun {
    Write-Host "Running validation..." -ForegroundColor Cyan
    Write-Host ""
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputPath = Join-Path $OutputDirectory $timestamp
    
    & "$PSScriptRoot\..\Validate-Production.ps1" `
        -TargetUrl $TargetUrl `
        -BenchmarkRuns $BenchmarkRuns `
        -OutputPath $outputPath
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "✅ Validation completed successfully" -ForegroundColor Green
        Write-Host "   Output: $outputPath" -ForegroundColor Gray
        
        # Generate report
        & "$PSScriptRoot\Generate-ValidationReport.ps1" `
            -ValidationOutputPath $outputPath `
            -ReportType CI
    } else {
        Write-Host ""
        Write-Host "❌ Validation failed" -ForegroundColor Red
    }
    
    # Cleanup old runs if retention enabled
    if ($EnableRetention) {
        Remove-OldRuns
    }
}

function Remove-OldRuns {
    if (-not (Test-Path $OutputDirectory)) {
        return
    }
    
    $cutoff = (Get-Date).AddDays(-$RetentionDays)
    $oldRuns = Get-ChildItem -Directory -Path $OutputDirectory | Where-Object { $_.LastWriteTime -lt $cutoff }
    
    if ($oldRuns.Count -gt 0) {
        Write-Host ""
        Write-Host "Cleaning up old runs (retention: $RetentionDays days)..." -ForegroundColor Gray
        
        foreach ($run in $oldRuns) {
            Remove-Item -Path $run.FullName -Recurse -Force
            Write-Host "  Removed: $($run.Name)" -ForegroundColor Gray
        }
        
        Write-Host "  Cleaned up $($oldRuns.Count) old runs" -ForegroundColor Green
    }
}

function Show-Status {
    Write-Host "Current Configuration:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Schedule: $Schedule" -ForegroundColor White
    if ($Schedule -eq "Custom") {
        Write-Host "  Interval: $IntervalMinutes minutes" -ForegroundColor White
    }
    Write-Host "  Target URL: $TargetUrl" -ForegroundColor White
    Write-Host "  Benchmark Runs: $BenchmarkRuns" -ForegroundColor White
    Write-Host "  Output Directory: $OutputDirectory" -ForegroundColor White
    Write-Host "  Retention: $(if ($EnableRetention) { "$RetentionDays days" } else { "Disabled" })" -ForegroundColor White
    Write-Host "  Job Name: $JobName" -ForegroundColor White
    Write-Host ""
}

# ============================================================================
# Main Execution
# ============================================================================

Show-Header

if ($ListJobs) {
    Get-ScheduledJobs
    exit 0
}

if ($Uninstall) {
    Uninstall-ScheduledJob
    exit 0
}

if ($Install) {
    Show-Status
    Install-ScheduledJob -schedule $Schedule -interval $IntervalMinutes
    exit 0
}

if ($RunNow) {
    Invoke-ValidationRun
    exit 0
}

# Default: show status and usage
Show-Status

Write-Host "Usage:" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Install scheduled validation:" -ForegroundColor Gray
Write-Host "    .\Schedule-Validation.ps1 -Install -Schedule Daily" -ForegroundColor White
Write-Host ""
Write-Host "  Install with custom interval:" -ForegroundColor Gray
Write-Host "    .\Schedule-Validation.ps1 -Install -Schedule Custom -IntervalMinutes 30" -ForegroundColor White
Write-Host ""
Write-Host "  Run validation now:" -ForegroundColor Gray
Write-Host "    .\Schedule-Validation.ps1 -RunNow" -ForegroundColor White
Write-Host ""
Write-Host "  List scheduled jobs:" -ForegroundColor Gray
Write-Host "    .\Schedule-Validation.ps1 -ListJobs" -ForegroundColor White
Write-Host ""
Write-Host "  Uninstall scheduled job:" -ForegroundColor Gray
Write-Host "    .\Schedule-Validation.ps1 -Uninstall" -ForegroundColor White
Write-Host ""
Write-Host "Options:" -ForegroundColor Cyan
Write-Host "  -Schedule Hourly|Daily|Weekly|Custom    Schedule type" -ForegroundColor Gray
Write-Host "  -IntervalMinutes <minutes>              Custom interval" -ForegroundColor Gray
Write-Host "  -TargetUrl <url>                        RawrXD endpoint" -ForegroundColor Gray
Write-Host "  -BenchmarkRuns <count>                  Iterations per run" -ForegroundColor Gray
Write-Host "  -EnableRetention                        Enable cleanup" -ForegroundColor Gray
Write-Host "  -RetentionDays <days>                  Keep runs for N days" -ForegroundColor Gray
Write-Host ""
