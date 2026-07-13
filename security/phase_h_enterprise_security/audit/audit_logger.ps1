#Requires -Version 7.0
<#
.SYNOPSIS
    Comprehensive Audit Logger for RawrXD Hotpatch System

.DESCRIPTION
    Logs all security-relevant events for compliance and forensic analysis.

.PARAMETER EventType
    Type of event: patch, auth, system, security

.PARAMETER Action
    Action performed

.PARAMETER UserId
    User who performed the action

.PARAMETER Details
    Additional event details (JSON string)

.PARAMETER Severity
    Event severity: info, warning, error, critical

.EXAMPLE
    .\audit_logger.ps1 -EventType patch -Action apply -UserId "john.doe" -Details '{"patch_id": "123"}' -Severity info
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("patch", "auth", "system", "security", "rbac")]
    [string]$EventType,

    [Parameter(Mandatory = $true)]
    [string]$Action,

    [Parameter(Mandatory = $false)]
    [string]$UserId = $env:USERNAME,

    [Parameter(Mandatory = $false)]
    [string]$Details = "{}",

    [Parameter(Mandatory = $false)]
    [ValidateSet("info", "warning", "error", "critical")]
    [string]$Severity = "info",

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:RAWRXD_HOME\logs\audit",

    [Parameter(Mandatory = $false)]
    [switch]$RealTime
)

# Audit log configuration
$script:AuditConfig = @{
    LogPath = $LogPath
    MaxLogSizeMB = 100
    MaxLogFiles = 10
    RetentionDays = 365
    EncryptLogs = $true
    RealTimeStreaming = $false
}

# Initialize audit system
function Initialize-AuditSystem {
    if (-not (Test-Path $script:AuditConfig.LogPath)) {
        New-Item -ItemType Directory -Path $script:AuditConfig.LogPath -Force | Out-Null
        Write-Host "✅ Audit log directory created: $($script:AuditConfig.LogPath)" -ForegroundColor Green
    }

    # Create audit config file
    $configFile = Join-Path $script:AuditConfig.LogPath "audit_config.json"
    if (-not (Test-Path $configFile)) {
        $script:AuditConfig | ConvertTo-Json | Out-File $configFile -Encoding UTF8
    }
}

# Get current log file
function Get-CurrentLogFile {
    $date = Get-Date -Format "yyyy-MM-dd"
    return Join-Path $script:AuditConfig.LogPath "audit_$date.jsonl"
}

# Rotate logs if needed
function Test-LogRotation {
    $currentLog = Get-CurrentLogFile

    if (Test-Path $currentLog) {
        $fileSize = (Get-Item $currentLog).Length / 1MB
        if ($fileSize -gt $script:AuditConfig.MaxLogSizeMB) {
            # Rotate log
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $rotatedName = "audit_$(Get-Date -Format 'yyyy-MM-dd')_$timestamp.jsonl"
            $rotatedPath = Join-Path $script:AuditConfig.LogPath $rotatedName
            Move-Item $currentLog $rotatedPath

            # Clean up old logs
            Get-ChildItem $script:AuditConfig.LogPath -Filter "audit_*.jsonl" |
                Sort-Object LastWriteTime -Descending |
                Select-Object -Skip $script:AuditConfig.MaxLogFiles |
                Remove-Item -Force
        }
    }
}

# Write audit entry
function Write-AuditEntry {
    param(
        [string]$Type,
        [string]$Action,
        [string]$User,
        [hashtable]$EventDetails,
        [string]$Level
    )

    Initialize-AuditSystem
    Test-LogRotation

    $entry = @{
        Timestamp = Get-Date -Format "o"
        EventType = $Type
        Action = $Action
        UserId = $User
        Severity = $Level
        SourceHost = $env:COMPUTERNAME
        ProcessId = $PID
        SessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
        Details = $EventDetails
    }

    # Add to log file (JSON Lines format)
    $logFile = Get-CurrentLogFile
    $entry | ConvertTo-Json -Compress | Out-File $logFile -Append -Encoding UTF8

    # Real-time streaming (if enabled)
    if ($script:AuditConfig.RealTimeStreaming -or $RealTime) {
        Write-Host "[AUDIT] [$($entry.Timestamp)] $Type`: $Action by $User" -ForegroundColor Cyan
    }

    # Critical events to Windows Event Log
    if ($Level -eq "critical") {
        Write-EventLog -LogName "Application" -Source "RawrXD Hotpatch" -EventId 1001 -EntryType Error -Message ($entry | ConvertTo-Json)
    }
}

# Main execution
$detailsHash = @{}
try {
    $detailsHash = $Details | ConvertFrom-Json -AsHashtable
}
catch {
    $detailsHash = @{ RawDetails = $Details }
}

Write-AuditEntry -Type $EventType -Action $Action -User $UserId -EventDetails $detailsHash -Level $Severity

Write-Host "✅ Audit entry logged" -ForegroundColor Green
