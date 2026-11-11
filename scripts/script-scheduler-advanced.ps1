# RawrXD Advanced Script Scheduler
# Enterprise-grade task scheduling with dependencies and retries
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [ValidateSet("List", "Create", "Run", "Delete", "Pause", "Resume", "History", "Dependency")]
    [string]$Action = "List",
    
    [Parameter()]
    [string]$JobName,
    
    [Parameter()]
    [string]$ScriptPath,
    
    [Parameter()]
    [string]$Schedule,
    
    [Parameter()]
    [hashtable]$Parameters = @{},
    
    [Parameter()]
    [string[]]$DependsOn = @(),
    
    [Parameter()]
    [int]$RetryCount = 3,
    
    [Parameter()]
    [int]$RetryDelay = 60,
    
    [Parameter()]
    [string]$Priority = "Normal",
    
    [Parameter()]
    [string]$OutputPath = "scheduled-jobs.json"
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }

function Get-JobsDataPath {
    return "$PSScriptRoot\.scheduled-jobs.json"
}

function Get-ScheduledJobs {
    $jobsPath = Get-JobsDataPath
    if (Test-Path $jobsPath) {
        return Get-Content $jobsPath | ConvertFrom-Json
    }
    return @{ Jobs = @(); NextId = 1 }
}

function Save-ScheduledJobs {
    param([hashtable]$Data)
    $Data | ConvertTo-Json -Depth 10 | Set-Content (Get-JobsDataPath)
}

function Show-ScheduledJobs {
    $data = Get-ScheduledJobs
    
    Write-Host "`nScheduled Jobs" -ForegroundColor Cyan
    Write-Host "===============" -ForegroundColor Cyan
    Write-Host ""
    
    if ($data.Jobs.Count -eq 0) {
        Write-Status "No scheduled jobs found"
        return
    }
    
    Write-Host "ID    Name                 Status      Schedule              Next Run"
    Write-Host "--    ----                 ------      --------              --------"
    
    foreach ($job in $data.Jobs) {
        $statusColor = switch ($job.Status) {
            "Running" { "Green" }
            "Paused" { "Yellow" }
            "Failed" { "Red" }
            default { "White" }
        }
        
        $nextRun = if ($job.NextRun) { 
            ([datetime]$job.NextRun).ToString("yyyy-MM-dd HH:mm") 
        } else { "-" }
        
        Write-Host $job.Id.ToString().PadRight(6) -NoNewline
        Write-Host $job.Name.PadRight(21) -NoNewline
        Write-Host $job.Status.PadRight(12) -ForegroundColor $statusColor -NoNewline
        Write-Host $job.Schedule.PadRight(22) -NoNewline
        Write-Host $nextRun
    }
    Write-Host ""
}

function New-ScheduledJob {
    if (-not $JobName -or -not $ScriptPath) {
        throw "JobName and ScriptPath parameters required for Create action"
    }
    
    $data = Get-ScheduledJobs
    
    # Check for duplicate names
    if ($data.Jobs | Where-Object { $_.Name -eq $JobName }) {
        throw "Job '$JobName' already exists"
    }
    
    $newJob = @{
        Id = $data.NextId
        Name = $JobName
        ScriptPath = $ScriptPath
        Schedule = $Schedule
        Parameters = $Parameters
        DependsOn = $DependsOn
        RetryCount = $RetryCount
        RetryDelay = $RetryDelay
        Priority = $Priority
        Status = "Created"
        CreatedAt = (Get-Date).ToString("o")
        LastRun = $null
        NextRun = $null
        RunCount = 0
        SuccessCount = 0
        FailureCount = 0
        History = @()
    }
    
    # Calculate next run
    if ($Schedule) {
        $newJob.NextRun = (Get-Date).AddMinutes(5).ToString("o")  # Simplified
    }
    
    $data.Jobs += $newJob
    $data.NextId++
    
    Save-ScheduledJobs -Data $data
    
    Write-Success "Scheduled job '$JobName' created (ID: $($newJob.Id))"
}

function Invoke-ScheduledJob {
    if (-not $JobName) {
        throw "JobName parameter required for Run action"
    }
    
    $data = Get-ScheduledJobs
    $job = $data.Jobs | Where-Object { $_.Name -eq $JobName }
    
    if (-not $job) {
        throw "Job '$JobName' not found"
    }
    
    Write-Status "Running scheduled job: $JobName"
    
    # Check dependencies
    foreach ($dep in $job.DependsOn) {
        $depJob = $data.Jobs | Where-Object { $_.Name -eq $dep }
        if ($depJob -and $depJob.Status -eq "Failed") {
            Write-Warning "Dependency '$dep' failed. Skipping execution."
            return
        }
    }
    
    $job.Status = "Running"
    Save-ScheduledJobs -Data $data
    
    $startTime = Get-Date
    $success = $false
    $attempt = 0
    $errorMessage = $null
    
    while ($attempt -lt $job.RetryCount -and -not $success) {
        $attempt++
        
        try {
            if (Test-Path $job.ScriptPath) {
                $scriptBlock = [scriptblock]::Create("& '$($job.ScriptPath)' @Parameters")
                Invoke-Command -ScriptBlock $scriptBlock
                $success = $true
            } else {
                throw "Script not found: $($job.ScriptPath)"
            }
        }
        catch {
            $errorMessage = $_.Exception.Message
            Write-Warning "Attempt $attempt failed: $errorMessage"
            
            if ($attempt -lt $job.RetryCount) {
                Write-Status "Waiting $RetryDelay seconds before retry..."
                Start-Sleep -Seconds $RetryDelay
            }
        }
    }
    
    $duration = ((Get-Date) - $startTime).TotalSeconds
    
    # Update job stats
    $job.RunCount++
    $job.LastRun = (Get-Date).ToString("o")
    
    if ($success) {
        $job.SuccessCount++
        $job.Status = "Completed"
        Write-Success "Job '$JobName' completed successfully in $([math]::Round($duration, 2))s"
    } else {
        $job.FailureCount++
        $job.Status = "Failed"
        Write-Error "Job '$JobName' failed after $attempt attempts"
    }
    
    # Add to history
    $job.History += @{
        Timestamp = (Get-Date).ToString("o")
        Duration = $duration
        Success = $success
        Error = $errorMessage
        Attempt = $attempt
    }
    
    # Keep only last 10 history entries
    if ($job.History.Count -gt 10) {
        $job.History = $job.History | Select-Object -Last 10
    }
    
    Save-ScheduledJobs -Data $data
}

function Remove-ScheduledJob {
    if (-not $JobName) {
        throw "JobName parameter required for Delete action"
    }
    
    $data = Get-ScheduledJobs
    $job = $data.Jobs | Where-Object { $_.Name -eq $JobName }
    
    if (-not $job) {
        throw "Job '$JobName' not found"
    }
    
    $data.Jobs = $data.Jobs | Where-Object { $_.Name -ne $JobName }
    Save-ScheduledJobs -Data $data
    
    Write-Success "Job '$JobName' deleted"
}

function Set-JobStatus {
    param([string]$Status)
    
    if (-not $JobName) {
        throw "JobName parameter required"
    }
    
    $data = Get-ScheduledJobs
    $job = $data.Jobs | Where-Object { $_.Name -eq $JobName }
    
    if (-not $job) {
        throw "Job '$JobName' not found"
    }
    
    $job.Status = $Status
    Save-ScheduledJobs -Data $data
    
    Write-Success "Job '$JobName' $Status"
}

function Show-JobHistory {
    if (-not $JobName) {
        throw "JobName parameter required for History action"
    }
    
    $data = Get-ScheduledJobs
    $job = $data.Jobs | Where-Object { $_.Name -eq $JobName }
    
    if (-not $job) {
        throw "Job '$JobName' not found"
    }
    
    Write-Host "`nJob History: $JobName" -ForegroundColor Cyan
    Write-Host "===================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Total Runs: $($job.RunCount)"
    Write-Host "Successful: $($job.SuccessCount)"
    Write-Host "Failed: $($job.FailureCount)"
    Write-Host ""
    
    if ($job.History.Count -gt 0) {
        Write-Host "Recent Executions:"
        Write-Host "Time                    Duration    Result    Attempts"
        Write-Host "----                    --------    ------    --------"
        
        foreach ($entry in ($job.History | Select-Object -Last 10)) {
            $result = if ($entry.Success) { "Success" } else { "Failed" }
            $color = if ($entry.Success) { "Green" } else { "Red" }
            
            Write-Host ([datetime]$entry.Timestamp).ToString("yyyy-MM-dd HH:mm:ss").PadRight(24) -NoNewline
            Write-Host "$([math]::Round($entry.Duration, 1))s".PadRight(12) -NoNewline
            Write-Host $result.PadRight(10) -ForegroundColor $color -NoNewline
            Write-Host $entry.Attempt
        }
    }
    Write-Host ""
}

function Show-DependencyGraph {
    Write-Host "`nJob Dependencies" -ForegroundColor Cyan
    Write-Host "=================" -ForegroundColor Cyan
    Write-Host ""
    
    $data = Get-ScheduledJobs
    
    foreach ($job in $data.Jobs) {
        if ($job.DependsOn.Count -gt 0) {
            Write-Host "$($job.Name) depends on: $($job.DependsOn -join ', ')"
        }
    }
    Write-Host ""
}

# Main execution
try {
    switch ($Action) {
        "List" { Show-ScheduledJobs }
        "Create" { New-ScheduledJob }
        "Run" { Invoke-ScheduledJob }
        "Delete" { Remove-ScheduledJob }
        "Pause" { Set-JobStatus -Status "Paused" }
        "Resume" { Set-JobStatus -Status "Created" }
        "History" { Show-JobHistory }
        "Dependency" { Show-DependencyGraph }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
