# update_service.ps1
# Phase H.3 Batch 2/5: Windows Update Service (Scheduled Task)

param(
    [string]$Action = "install",
    [int]$CheckIntervalHours = 24
)

$ServiceName = "RawrXDUpdate"
$TaskName = "RawrXD Auto-Update"

function Install-UpdateService {
    Write-Host "Installing RawrXD auto-update service..."
    
    # Create scheduled task
    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-ExecutionPolicy Bypass -File `"$PSScriptRoot\update_checker.ps1`" -AutoInstall"
    
    $trigger = New-ScheduledTaskTrigger -Daily -At "03:00"
    
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -RunOnlyIfNetworkAvailable
    
    $principal = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest
    
    try {
        Register-ScheduledTask `
            -TaskName $TaskName `
            -Action $action `
            -Trigger $trigger `
            -Settings $settings `
            -Principal $principal `
            -Force
        
        Write-Host "Update service installed successfully" -ForegroundColor Green
        Write-Host "Scheduled to run daily at 3:00 AM"
    }
    catch {
        Write-Host "Failed to install update service: $_" -ForegroundColor Red
        exit 1
    }
}

function Uninstall-UpdateService {
    Write-Host "Removing RawrXD auto-update service..."
    
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "Update service removed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to remove update service: $_" -ForegroundColor Red
        exit 1
    }
}

function Get-UpdateServiceStatus {
    try {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        Write-Host "Update Service Status: $($task.State)" -ForegroundColor Cyan
        Write-Host "Next Run Time: $($task.NextRunTime)"
        Write-Host "Last Run Time: $($task.LastRunTime)"
        
        # Get last run result
        $history = Get-ScheduledTaskInfo -TaskName $TaskName
        Write-Host "Last Run Result: $($history.LastTaskResult)"
    }
    catch {
        Write-Host "Update service not installed" -ForegroundColor Yellow
    }
}

# Main
switch ($Action.ToLower()) {
    "install" { Install-UpdateService }
    "uninstall" { Uninstall-UpdateService }
    "status" { Get-UpdateServiceStatus }
    default {
        Write-Host "Usage: update_service.ps1 -Action [install|uninstall|status]"
        exit 1
    }
}
