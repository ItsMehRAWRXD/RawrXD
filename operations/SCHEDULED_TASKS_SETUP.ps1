# SCHEDULED_TASKS_SETUP.ps1
# Phase K Batch 5/5: Automated Scheduled Task Configuration

param(
    [switch]$Install,
    [switch]$Remove,
    [switch]$List
)

$ErrorActionPreference = "Stop"

$RawrXDPath = "${env:ProgramFiles}\RawrXD"
$TaskPrefix = "RawrXD"

$ScheduledTasks = @(
    @{
        Name = "DailyMaintenance"
        Description = "Daily maintenance tasks for RawrXD"
        Script = "operations\maintenance\daily_maintenance.ps1"
        Schedule = "Daily"
        Time = "02:00"
        Arguments = "-CreateBackup"
    },
    @{
        Name = "MetricsCollection"
        Description = "Collect and export metrics"
        Script = "monitoring\telemetry\metrics_collector.ps1"
        Schedule = "AtStartup"
        Arguments = "-EnableRemoteWrite"
    },
    @{
        Name = "AlertManager"
        Description = "Monitor and alert on thresholds"
        Script = "monitoring\alerting\alert_manager.ps1"
        Schedule = "AtStartup"
        Arguments = ""
    },
    @{
        Name = "LogAggregation"
        Description = "Aggregate and ship logs"
        Script = "monitoring\logging\log_aggregator.ps1"
        Schedule = "Daily"
        Time = "01:00"
        Arguments = ""
    },
    @{
        Name = "HealthCheck"
        Description = "Periodic health verification"
        Script = "recovery\health\health_check.ps1"
        Schedule = "Daily"
        Time = "06:00"
        Arguments = "-Mode quick"
    }
)

function Write-TaskLog($Message, $Level = "INFO") {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        "TASK" { "Cyan" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Install-RawrxdTasks {
    Write-TaskLog "Installing RawrXD Scheduled Tasks"
    Write-TaskLog "Source: $RawrXDPath"
    Write-TaskLog ""
    
    foreach ($task in $ScheduledTasks) {
        $taskName = "$TaskPrefix-$($task.Name)"
        $scriptPath = "$RawrXDPath\$($task.Script)"
        
        Write-TaskLog "Creating task: $taskName" "TASK"
        
        if (-not (Test-Path $scriptPath)) {
            Write-TaskLog "Script not found: $scriptPath" "WARNING"
            continue
        }
        
        try {
            # Create action
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`" $($task.Arguments)"
            
            # Create trigger
            $trigger = if ($task.Schedule -eq "AtStartup") {
                New-ScheduledTaskTrigger -AtStartup
            } else {
                New-ScheduledTaskTrigger -Daily -At $task.Time
            }
            
            # Create settings
            $settings = New-ScheduledTaskSettingsSet `
                -AllowStartIfOnBatteries `
                -DontStopIfGoingOnBatteries `
                -StartWhenAvailable `
                -RunOnlyIfNetworkAvailable:$false
            
            # Create principal
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            
            # Register task
            Register-ScheduledTask `
                -TaskName $taskName `
                -Action $action `
                -Trigger $trigger `
                -Settings $settings `
                -Principal $principal `
                -Description $task.Description `
                -Force | Out-Null
            
            Write-TaskLog "✅ Task created: $taskName" "SUCCESS"
        }
        catch {
            Write-TaskLog "❌ Failed to create task: $_" "ERROR"
        }
    }
    
    Write-TaskLog ""
    Write-TaskLog "Scheduled tasks installation complete"
}

function Remove-RawrxdTasks {
    Write-TaskLog "Removing RawrXD Scheduled Tasks"
    Write-TaskLog ""
    
    foreach ($task in $ScheduledTasks) {
        $taskName = "$TaskPrefix-$($task.Name)"
        
        try {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
            Write-TaskLog "✅ Removed task: $taskName" "SUCCESS"
        }
        catch {
            if ($_.Exception.Message -like "*cannot find*") {
                Write-TaskLog "Task not found: $taskName" "WARNING"
            } else {
                Write-TaskLog "❌ Failed to remove task: $_" "ERROR"
            }
        }
    }
    
    Write-TaskLog ""
    Write-TaskLog "Scheduled tasks removal complete"
}

function List-RawrxdTasks {
    Write-TaskLog "RawrXD Scheduled Tasks Status"
    Write-TaskLog ""
    
    foreach ($task in $ScheduledTasks) {
        $taskName = "$TaskPrefix-$($task.Name)"
        
        try {
            $scheduledTask = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
            $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName
            
            Write-TaskLog "Task: $taskName" "TASK"
            Write-TaskLog "  State: $($scheduledTask.State)"
            Write-TaskLog "  Last Run: $($taskInfo.LastRunTime)"
            Write-TaskLog "  Next Run: $($taskInfo.NextRunTime)"
            Write-TaskLog "  Last Result: $($taskInfo.LastTaskResult)"
            Write-TaskLog ""
        }
        catch {
            Write-TaskLog "Task not found: $taskName" "WARNING"
        }
    }
}

# Main execution
Write-TaskLog "RawrXD Scheduled Task Manager"
Write-TaskLog ""

if ($Install) {
    Install-RawrxdTasks
}
elseif ($Remove) {
    Remove-RawrxdTasks
}
elseif ($List) {
    List-RawrxdTasks
}
else {
    Write-TaskLog "Usage:"
    Write-TaskLog "  .\SCHEDULED_TASKS_SETUP.ps1 -Install    # Install all tasks"
    Write-TaskLog "  .\SCHEDULED_TASKS_SETUP.ps1 -Remove    # Remove all tasks"
    Write-TaskLog "  .\SCHEDULED_TASKS_SETUP.ps1 -List      # List task status"
}
