# RawrXD Maintenance Window Manager
# Schedules and manages maintenance windows with notifications
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [ValidateSet("List", "Schedule", "Start", "Complete", "Cancel", "Status")]
    [string]$Action = "List",
    
    [Parameter()]
    [string]$WindowId,
    
    [Parameter()]
    [string]$Title,
    
    [Parameter()]
    [string]$Description,
    
    [Parameter()]
    [datetime]$StartTime,
    
    [Parameter()]
    [int]$DurationMinutes = 60,
    
    [Parameter()]
    [string[]]$AffectedServices = @(),
    
    [Parameter()]
    [string[]]$NotifyChannels = @("email", "slack"),
    
    [Parameter()]
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }

function Get-MaintenanceWindowsPath {
    return "$PSScriptRoot\.maintenance-windows.json"
}

function Get-MaintenanceWindows {
    $path = Get-MaintenanceWindowsPath
    if (Test-Path $path) {
        return Get-Content $path | ConvertFrom-Json
    }
    return @{ Windows = @(); NextId = 1 }
}

function Save-MaintenanceWindows {
    param([hashtable]$Data)
    $Data | ConvertTo-Json -Depth 10 | Set-Content (Get-MaintenanceWindowsPath)
}

function Show-MaintenanceWindows {
    $data = Get-MaintenanceWindows
    
    Write-Host "`nMaintenance Windows" -ForegroundColor Cyan
    Write-Host "====================" -ForegroundColor Cyan
    Write-Host ""
    
    $now = Get-Date
    $upcoming = $data.Windows | Where-Object { [datetime]$_.StartTime -gt $now -and $_.Status -eq "Scheduled" }
    $active = $data.Windows | Where-Object { $_.Status -eq "In Progress" }
    $completed = $data.Windows | Where-Object { $_.Status -eq "Completed" } | Select-Object -Last 5
    
    if ($active.Count -gt 0) {
        Write-Host "🔧 ACTIVE MAINTENANCE" -ForegroundColor Red
        Write-Host ""
        foreach ($window in $active) {
            Write-Host "  ID: $($window.Id)" -ForegroundColor Yellow
            Write-Host "  Title: $($window.Title)"
            Write-Host "  Started: $($window.ActualStartTime)"
            Write-Host "  Services: $($window.AffectedServices -join ', ')"
            Write-Host ""
        }
    }
    
    if ($upcoming.Count -gt 0) {
        Write-Host "📅 UPCOMING" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "ID          Start Time            Duration    Services"
        Write-Host "--          ----------            --------    --------"
        
        foreach ($window in ($upcoming | Sort-Object StartTime)) {
            Write-Host ($window.Id).PadRight(12) -NoNewline
            Write-Host ([datetime]$window.StartTime).ToString("yyyy-MM-dd HH:mm").PadRight(22) -NoNewline
            Write-Host "$($window.DurationMinutes)m".PadRight(12) -NoNewline
            Write-Host ($window.AffectedServices -join ', ')
        }
        Write-Host ""
    }
    
    if ($completed.Count -gt 0) {
        Write-Host "✅ RECENTLY COMPLETED" -ForegroundColor Green
        Write-Host ""
        foreach ($window in $completed) {
            Write-Host "  $($window.Id): $($window.Title) - Completed at $($window.CompletedAt)"
        }
        Write-Host ""
    }
}

function New-MaintenanceWindow {
    if (-not $Title -or -not $StartTime) {
        throw "Title and StartTime parameters required"
    }
    
    $data = Get-MaintenanceWindows
    
    $window = @{
        Id = "MAINT-$($data.NextId)"
        Title = $Title
        Description = $Description
        StartTime = $StartTime.ToString("o")
        DurationMinutes = $DurationMinutes
        AffectedServices = $AffectedServices
        NotifyChannels = $NotifyChannels
        Status = "Scheduled"
        CreatedAt = (Get-Date).ToString("o")
        ActualStartTime = $null
        CompletedAt = $null
        CreatedBy = $env:USERNAME
    }
    
    $data.Windows += $window
    $data.NextId++
    
    Save-MaintenanceWindows -Data $data
    
    Write-Success "Maintenance window scheduled: $($window.Id)"
    Write-Status "Start: $($StartTime.ToString('yyyy-MM-dd HH:mm'))"
    Write-Status "Duration: $DurationMinutes minutes"
    Write-Status "Services: $($AffectedServices -join ', ')"
    
    # Send notifications
    Send-MaintenanceNotification -Window $window -Type "Scheduled"
}

function Send-MaintenanceNotification {
    param([hashtable]$Window, [string]$Type)
    
    Write-Status "Sending $Type notification..."
    
    foreach ($channel in $Window.NotifyChannels) {
        switch ($channel) {
            "email" { Write-Status "  📧 Email notification would be sent" }
            "slack" { Write-Status "  💬 Slack notification would be sent" }
            "teams" { Write-Status "  👥 Teams notification would be sent" }
        }
    }
}

function Start-MaintenanceWindow {
    if (-not $WindowId) {
        throw "WindowId parameter required"
    }
    
    $data = Get-MaintenanceWindows
    $window = $data.Windows | Where-Object { $_.Id -eq $WindowId }
    
    if (-not $window) {
        throw "Maintenance window not found: $WindowId"
    }
    
    if ($window.Status -ne "Scheduled") {
        throw "Window is not in Scheduled status"
    }
    
    $window.Status = "In Progress"
    $window.ActualStartTime = (Get-Date).ToString("o")
    
    Save-MaintenanceWindows -Data $data
    
    Write-Success "Maintenance window started: $WindowId"
    Send-MaintenanceNotification -Window $window -Type "Started"
}

function Complete-MaintenanceWindow {
    if (-not $WindowId) {
        throw "WindowId parameter required"
    }
    
    $data = Get-MaintenanceWindows
    $window = $data.Windows | Where-Object { $_.Id -eq $WindowId }
    
    if (-not $window) {
        throw "Maintenance window not found: $WindowId"
    }
    
    $window.Status = "Completed"
    $window.CompletedAt = (Get-Date).ToString("o")
    
    Save-MaintenanceWindows -Data $data
    
    Write-Success "Maintenance window completed: $WindowId"
    Send-MaintenanceNotification -Window $window -Type "Completed"
}

function Cancel-MaintenanceWindow {
    if (-not $WindowId) {
        throw "WindowId parameter required"
    }
    
    $data = Get-MaintenanceWindows
    $window = $data.Windows | Where-Object { $_.Id -eq $WindowId }
    
    if (-not $window) {
        throw "Maintenance window not found: $WindowId"
    }
    
    if (-not $Force) {
        $confirm = Read-Host "Cancel maintenance window '$WindowId'? (yes/no)"
        if ($confirm -ne "yes") {
            Write-Status "Cancelled"
            return
        }
    }
    
    $window.Status = "Cancelled"
    $window.CompletedAt = (Get-Date).ToString("o")
    
    Save-MaintenanceWindows -Data $data
    
    Write-Success "Maintenance window cancelled: $WindowId"
    Send-MaintenanceNotification -Window $window -Type "Cancelled"
}

function Show-MaintenanceStatus {
    $data = Get-MaintenanceWindows
    $now = Get-Date
    
    $active = $data.Windows | Where-Object { $_.Status -eq "In Progress" }
    $scheduled = $data.Windows | Where-Object { $_.Status -eq "Scheduled" -and [datetime]$_.StartTime -gt $now }
    
    Write-Host "`nMaintenance Status" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Active: $($active.Count)" -ForegroundColor $(if ($active.Count -gt 0) { "Red" } else { "Green" })
    Write-Host "Scheduled: $($scheduled.Count)"
    Write-Host ""
    
    if ($active.Count -gt 0) {
        Write-Warning "⚠️  Maintenance in progress!"
        foreach ($w in $active) {
            Write-Host "  - $($w.Title) (started at $($w.ActualStartTime))"
        }
    }
}

# Main execution
try {
    switch ($Action) {
        "List" { Show-MaintenanceWindows }
        "Schedule" { New-MaintenanceWindow }
        "Start" { Start-MaintenanceWindow }
        "Complete" { Complete-MaintenanceWindow }
        "Cancel" { Cancel-MaintenanceWindow }
        "Status" { Show-MaintenanceStatus }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
