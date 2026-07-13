# RawrXD Task Scheduler
# Manages scheduled tasks and cron jobs

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("List", "Create", "Delete", "Run", "Enable", "Disable", "Export", "Import")]
    [string]$Action = "List",
    
    [string]$TaskName = "",
    [string]$Command = "",
    [string]$Schedule = "Daily",
    [string]$Time = "02:00",
    [int]$IntervalMinutes = 0,
    [string]$WorkingDirectory = "",
    [string]$Description = "",
    [switch]$RunAsSystem,
    [string]$UserName = "",
    [string]$ExportPath = "",
    [string]$ImportPath = "",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Initialize-Scheduler {
    Write-Status "RawrXD Task Scheduler"
    Write-Status "Action: $Action"
}

function Get-ScheduledTasksList {
    Write-Status "Listing scheduled tasks..."
    
    $tasks = Get-ScheduledTask | Where-Object { $_.TaskName -like "*RawrXD*" -or $_.TaskPath -like "*RawrXD*" }
    
    if ($tasks.Count -eq 0) {
        Write-Warning "No RawrXD tasks found"
        return
    }
    
    Write-Host ""
    Write-Host "Scheduled Tasks:" -ForegroundColor Cyan
    Write-Host "=================" -ForegroundColor Cyan
    
    foreach ($task in $tasks) {
        $state = $task.State
        $stateColor = switch ($state) {
            "Running" { "Green" }
            "Ready" { "Cyan" }
            "Disabled" { "Yellow" }
            default { "White" }
        }
        
        Write-Host "  Task: $($task.TaskName)" -ForegroundColor White
        Write-Host "    Path: $($task.TaskPath)"
        Write-Host "    State: " -NoNewline
        Write-Host $state -ForegroundColor $stateColor
        Write-Host "    Next Run: $($task.NextRunTime)"
        Write-Host "    Last Run: $($task.LastRunTime)"
        Write-Host ""
    }
}

function New-ScheduledTask {
    if (-not $TaskName) {
        Write-Error "TaskName parameter required for Create action"
        return
    }
    
    if (-not $Command) {
        Write-Error "Command parameter required for Create action"
        return
    }
    
    Write-Status "Creating scheduled task: $TaskName"
    
    # Check if task already exists
    $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existingTask -and -not $Force) {
        Write-Error "Task '$TaskName' already exists. Use -Force to overwrite."
        return
    }
    
    # Build trigger
    $trigger = $null
    switch ($Schedule) {
        "Daily" {
            $trigger = New-ScheduledTaskTrigger -Daily -At $Time
        }
        "Weekly" {
            $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At $Time
        }
        "Monthly" {
            $trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 4 -At $Time
        }
        "AtStartup" {
            $trigger = New-ScheduledTaskTrigger -AtStartup
        }
        "AtLogon" {
            $trigger = New-ScheduledTaskTrigger -AtLogon
        }
        "Once" {
            $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)
        }
        "Interval" {
            if ($IntervalMinutes -gt 0) {
                $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
            }
        }
    }
    
    if (-not $trigger) {
        Write-Error "Failed to create trigger for schedule: $Schedule"
        return
    }
    
    # Build action
    $actionArgs = @{
        Execute = "powershell.exe"
        Argument = "-ExecutionPolicy Bypass -Command `"$Command`""
    }
    
    if ($WorkingDirectory) {
        $actionArgs.WorkingDirectory = $WorkingDirectory
    }
    
    $taskAction = New-ScheduledTaskAction @actionArgs
    
    # Build principal (security context)
    $principalArgs = @{}
    if ($RunAsSystem) {
        $principalArgs = @{
            UserId = "SYSTEM"
            LogonType = "ServiceAccount"
        }
    } elseif ($UserName) {
        $principalArgs = @{
            UserId = $UserName
            LogonType = "Interactive"
        }
    } else {
        $principalArgs = @{
            UserId = $env:USERNAME
            LogonType = "Interactive"
        }
    }
    
    $principal = New-ScheduledTaskPrincipal @principalArgs
    
    # Build settings
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -RunOnlyIfNetworkAvailable:$false
    
    # Register task
    $regArgs = @{
        TaskName = $TaskName
        Trigger = $trigger
        Action = $taskAction
        Principal = $principal
        Settings = $settings
        Description = if ($Description) { $Description } else { "RawrXD scheduled task: $TaskName" }
    }
    
    if ($Force -and $existingTask) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    
    try {
        Register-ScheduledTask @regArgs | Out-Null
        Write-Success "Task '$TaskName' created successfully"
        Write-Status "Schedule: $Schedule at $Time"
        
        # Show next run time
        $createdTask = Get-ScheduledTask -TaskName $TaskName
        Write-Status "Next run: $($createdTask.NextRunTime)"
    }
    catch {
        Write-Error "Failed to create task: $_"
    }
}

function Remove-ScheduledTask {
    if (-not $TaskName) {
        Write-Error "TaskName parameter required for Delete action"
        return
    }
    
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) {
        Write-Error "Task '$TaskName' not found"
        return
    }
    
    Write-Status "Deleting task: $TaskName"
    
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Success "Task '$TaskName' deleted"
    }
    catch {
        Write-Error "Failed to delete task: $_"
    }
}

function Invoke-ScheduledTask {
    if (-not $TaskName) {
        Write-Error "TaskName parameter required for Run action"
        return
    }
    
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) {
        Write-Error "Task '$TaskName' not found"
        return
    }
    
    Write-Status "Running task: $TaskName"
    
    try {
        Start-ScheduledTask -TaskName $TaskName
        Write-Success "Task '$TaskName' started"
        
        # Wait a moment and check status
        Start-Sleep -Seconds 2
        $updatedTask = Get-ScheduledTask -TaskName $TaskName
        Write-Status "Current state: $($updatedTask.State)"
    }
    catch {
        Write-Error "Failed to run task: $_"
    }
}

function Set-TaskEnabled {
    param([bool]$Enabled)
    
    if (-not $TaskName) {
        Write-Error "TaskName parameter required"
        return
    }
    
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) {
        Write-Error "Task '$TaskName' not found"
        return
    }
    
    $action = if ($Enabled) { "Enabling" } else { "Disabling" }
    Write-Status "$action task: $TaskName"
    
    try {
        if ($Enabled) {
            Enable-ScheduledTask -TaskName $TaskName | Out-Null
        } else {
            Disable-ScheduledTask -TaskName $TaskName | Out-Null
        }
        Write-Success "Task '$TaskName' $(if($Enabled){'enabled'}else{'disabled'})"
    }
    catch {
        Write-Error "Failed to modify task: $_"
    }
}

function Export-TaskConfiguration {
    if (-not $ExportPath) {
        $ExportPath = "tasks-export-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    }
    
    Write-Status "Exporting tasks to: $ExportPath"
    
    $tasks = Get-ScheduledTask | Where-Object { $_.TaskName -like "*RawrXD*" }
    
    $exportData = @()
    foreach ($task in $tasks) {
        $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName
        $exportData += @{
            TaskName = $task.TaskName
            TaskPath = $task.TaskPath
            State = $task.State
            Description = $task.Description
            Author = $task.Author
            RunAs = $task.Principal.UserId
            NextRunTime = $task.NextRunTime
            LastRunTime = $task.LastRunTime
        }
    }
    
    $exportData | ConvertTo-Json -Depth 5 | Out-File $ExportPath
    Write-Success "Exported $($tasks.Count) tasks to $ExportPath"
}

function Import-TaskConfiguration {
    if (-not $ImportPath) {
        Write-Error "ImportPath parameter required"
        return
    }
    
    if (-not (Test-Path $ImportPath)) {
        Write-Error "Import file not found: $ImportPath"
        return
    }
    
    Write-Status "Importing tasks from: $ImportPath"
    
    $importData = Get-Content $ImportPath | ConvertFrom-Json
    
    foreach ($taskConfig in $importData) {
        Write-Status "Would import: $($taskConfig.TaskName)"
        # Note: Full import would require recreating triggers/actions
        # This is a simplified version that just logs what would be imported
    }
    
    Write-Success "Import analysis complete"
}

# Main execution
function Main {
    Write-Host "RawrXD Task Scheduler" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-Scheduler
    
    switch ($Action) {
        "List" { Get-ScheduledTasksList }
        "Create" { New-ScheduledTask }
        "Delete" { Remove-ScheduledTask }
        "Run" { Invoke-ScheduledTask }
        "Enable" { Set-TaskEnabled -Enabled $true }
        "Disable" { Set-TaskEnabled -Enabled $false }
        "Export" { Export-TaskConfiguration }
        "Import" { Import-TaskConfiguration }
    }
    
    Write-Host ""
}

Main
