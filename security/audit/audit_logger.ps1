# RawrXD Audit Logger
# Phase M.4 - Audit Logging & Monitoring
# Comprehensive audit trail for security events and compliance

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("log", "query", "export", "monitor")]
    [string]$Action = "log",

    [Parameter(Mandatory=$false)]
    [hashtable]$Event = @{},

    [Parameter(Mandatory=$false)]
    [string]$Query = "",

    [Parameter(Mandatory=$false)]
    [DateTime]$StartTime = (Get-Date).AddDays(-1),

    [Parameter(Mandatory=$false)]
    [DateTime]$EndTime = (Get-Date),

    [Parameter(Mandatory=$false)]
    [string]$ExportPath = "",

    [Parameter(Mandatory=$false)]
    [string]$LogPath = "/var/log/rawrxd/audit"
)

$ErrorActionPreference = "Stop"

# Ensure log directory exists
if (!(Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

# Logging
function Write-AuditLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{ "INFO" = "White"; "SUCCESS" = "Green"; "WARNING" = "Yellow"; "ERROR" = "Red"; "AUDIT" = "Cyan" }
    Write-Host "[$timestamp] [AUDIT] [$Level] $Message" -ForegroundColor $colors[$Level]
}

# Audit event class
class AuditEvent {
    [string]$EventId
    [DateTime]$Timestamp
    [string]$EventType
    [string]$Severity
    [string]$UserId
    [string]$UserName
    [string]$SourceIP
    [string]$Resource
    [string]$Action
    [string]$Result
    [hashtable]$Details
    [string]$SessionId
    [string]$CorrelationId

    AuditEvent([string]$eventType, [string]$severity) {
        $this.EventId = [Guid]::NewGuid().ToString()
        $this.Timestamp = Get-Date
        $this.EventType = $eventType
        $this.Severity = $severity
        $this.Details = @{}
        $this.SessionId = [Guid]::NewGuid().ToString()
        $this.CorrelationId = [Guid]::NewGuid().ToString()
    }

    [string] ToJson() {
        return @{
            event_id = $this.EventId
            timestamp = $this.Timestamp.ToString("o")
            event_type = $this.EventType
            severity = $this.Severity
            user_id = $this.UserId
            user_name = $this.UserName
            source_ip = $this.SourceIP
            resource = $this.Resource
            action = $this.Action
            result = $this.Result
            details = $this.Details
            session_id = $this.SessionId
            correlation_id = $this.CorrelationId
        } | ConvertTo-Json -Depth 10 -Compress
    }
}

# Event types
$EventTypes = @{
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    CONFIG_CHANGE = "config_change"
    ADMIN_ACTION = "admin_action"
    SECURITY_ALERT = "security_alert"
    SYSTEM_EVENT = "system_event"
    API_CALL = "api_call"
    MODEL_ACCESS = "model_access"
}

# Severity levels
$Severities = @{
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
}

# Write audit event to log
function Write-AuditEvent {
    param([AuditEvent]$Event)

    $logFile = Join-Path $LogPath "audit_$(Get-Date -Format 'yyyyMMdd').log"
    $json = $Event.ToJson()

    # Append to daily log file
    Add-Content -Path $logFile -Value $json

    # Also write to structured format for SIEM
    $siemFile = Join-Path $LogPath "siem_$(Get-Date -Format 'yyyyMMdd').json"
    Add-Content -Path $siemFile -Value $json

    # Log to console for critical events
    if ($Event.Severity -in @($Severities.CRITICAL, $Severities.HIGH)) {
        Write-AuditLog "CRITICAL EVENT: $($Event.EventType) - $($Event.Action) on $($Event.Resource)" $Event.Severity.ToUpper()
    }
}

# Log authentication event
function Write-AuthEvent {
    param(
        [string]$UserName,
        [string]$UserId,
        [string]$SourceIP,
        [string]$Result,  # success, failure, mfa_required
        [string]$Reason = ""
    )

    $event = [AuditEvent]::new($EventTypes.AUTHENTICATION, $(if ($Result -eq "success") { $Severities.INFO } else { $Severities.HIGH }))
    $event.UserName = $UserName
    $event.UserId = $UserId
    $event.SourceIP = $SourceIP
    $event.Action = "login"
    $event.Result = $Result
    $event.Resource = "auth_system"
    $event.Details = @{
        reason = $Reason
        auth_method = "jwt"
        user_agent = $env:HTTP_USER_AGENT
    }

    Write-AuditEvent -Event $event
    return $event.EventId
}

# Log API access event
function Write-APIEvent {
    param(
        [string]$UserName,
        [string]$Endpoint,
        [string]$Method,
        [int]$StatusCode,
        [long]$ResponseTimeMs,
        [hashtable]$RequestDetails = @{}
    )

    $severity = switch ($StatusCode) {
        { $_ -ge 500 } { $Severities.HIGH }
        { $_ -ge 400 } { $Severities.MEDIUM }
        default { $Severities.INFO }
    }

    $event = [AuditEvent]::new($EventTypes.API_CALL, $severity)
    $event.UserName = $UserName
    $event.SourceIP = $RequestDetails.client_ip
    $event.Action = $Method
    $event.Resource = $Endpoint
    $event.Result = if ($StatusCode -lt 400) { "success" } else { "failure" }
    $event.Details = @{
        status_code = $StatusCode
        response_time_ms = $ResponseTimeMs
        request_size = $RequestDetails.request_size
        response_size = $RequestDetails.response_size
        user_agent = $RequestDetails.user_agent
    }

    Write-AuditEvent -Event $event
}

# Log data access event
function Write-DataAccessEvent {
    param(
        [string]$UserName,
        [string]$Resource,
        [string]$Action,  # read, write, delete
        [string]$DataType,
        [string]$Result = "success"
    )

    $severity = switch ($Action) {
        "delete" { $Severities.HIGH }
        "write" { $Severities.MEDIUM }
        default { $Severities.INFO }
    }

    $event = [AuditEvent]::new($EventTypes.DATA_ACCESS, $severity)
    $event.UserName = $UserName
    $event.Action = $Action
    $event.Resource = $Resource
    $event.Result = $Result
    $event.Details = @{
        data_type = $DataType
        classification = "confidential"
    }

    Write-AuditEvent -Event $event
}

# Log admin action
function Write-AdminEvent {
    param(
        [string]$UserName,
        [string]$Action,
        [string]$Resource,
        [hashtable]$Changes = @{}
    )

    $event = [AuditEvent]::new($EventTypes.ADMIN_ACTION, $Severities.HIGH)
    $event.UserName = $UserName
    $event.Action = $Action
    $event.Resource = $Resource
    $event.Result = "success"
    $event.Details = @{
        changes = $Changes
        requires_approval = $true
    }

    Write-AuditEvent -Event $event
}

# Log security alert
function Write-SecurityAlert {
    param(
        [string]$AlertType,
        [string]$Description,
        [string]$Severity,
        [hashtable]$Context = @{}
    )

    $event = [AuditEvent]::new($EventTypes.SECURITY_ALERT, $Severity)
    $event.Action = $AlertType
    $event.Resource = "security_system"
    $event.Result = "alert"
    $event.Details = @{
        description = $Description
        context = $Context
        alert_id = [Guid]::NewGuid().ToString()
    }

    Write-AuditEvent -Event $event

    # Trigger immediate notification for critical alerts
    if ($Severity -eq $Severities.CRITICAL) {
        Send-SecurityNotification -Event $event
    }
}

# Send security notification
function Send-SecurityNotification {
    param([AuditEvent]$Event)

    Write-AuditLog "Sending security notification for event $($Event.EventId)" "WARNING"

    # In production, this would send to PagerDuty, Slack, email, etc.
    $notification = @{
        alert_id = $Event.Details.alert_id
        severity = $Event.Severity
        event_type = $Event.EventType
        description = $Event.Details.description
        timestamp = $Event.Timestamp.ToString("o")
        channels = @("slack", "pagerduty", "email")
    }

    # Simulate notification
    Write-AuditLog "Notification sent to: $($notification.channels -join ', ')" "SUCCESS"
}

# Query audit log
function Get-AuditEvents {
    param(
        [DateTime]$Start,
        [DateTime]$End,
        [string]$EventType = "",
        [string]$Severity = "",
        [string]$UserName = "",
        [string]$Resource = ""
    )

    Write-AuditLog "Querying audit events from $($Start.ToString('yyyy-MM-dd HH:mm')) to $($End.ToString('yyyy-MM-dd HH:mm'))" "INFO"

    $events = @()

    # Get log files in date range
    $currentDate = $Start.Date
    while ($currentDate -le $End.Date) {
        $logFile = Join-Path $LogPath "audit_$($currentDate.ToString('yyyyMMdd')).log"

        if (Test-Path $logFile) {
            $lines = Get-Content $logFile
            foreach ($line in $lines) {
                try {
                    $event = $line | ConvertFrom-Json
                    $eventTime = [DateTime]$event.timestamp

                    # Apply filters
                    if ($eventTime -ge $Start -and $eventTime -le $End) {
                        $include = $true

                        if ($EventType -and $event.event_type -ne $EventType) { $include = $false }
                        if ($Severity -and $event.severity -ne $Severity) { $include = $false }
                        if ($UserName -and $event.user_name -ne $UserName) { $include = $false }
                        if ($Resource -and $event.resource -notlike "*$Resource*") { $include = $false }

                        if ($include) {
                            $events += $event
                        }
                    }
                } catch {
                    # Skip malformed lines
                }
            }
        }

        $currentDate = $currentDate.AddDays(1)
    }

    Write-AuditLog "Found $($events.Count) matching events" "SUCCESS"
    return $events | Sort-Object timestamp
}

# Export audit log
function Export-AuditLog {
    param(
        [DateTime]$Start,
        [DateTime]$End,
        [string]$OutputPath,
        [string]$Format = "json"  # json, csv
    )

    Write-AuditLog "Exporting audit events to $OutputPath..." "INFO"

    $events = Get-AuditEvents -Start $Start -End $End

    switch ($Format) {
        "json" {
            $events | ConvertTo-Json -Depth 10 | Out-File $OutputPath -Encoding UTF8
        }
        "csv" {
            $events | ForEach-Object {
                [PSCustomObject]@{
                    Timestamp = $_.timestamp
                    EventType = $_.event_type
                    Severity = $_.severity
                    UserName = $_.user_name
                    SourceIP = $_.source_ip
                    Resource = $_.resource
                    Action = $_.action
                    Result = $_.result
                }
            } | Export-Csv -Path $OutputPath -NoTypeInformation
        }
    }

    Write-AuditLog "Exported $($events.Count) events to $OutputPath" "SUCCESS"
}

# Real-time monitoring
function Start-AuditMonitor {
    param([string]$LogFile)

    Write-AuditLog "Starting real-time audit monitoring..." "INFO"
    Write-AuditLog "Monitoring file: $LogFile" "INFO"

    # Use Get-Content -Wait for real-time tailing
    Get-Content $LogFile -Wait -Tail 10 | ForEach-Object {
        try {
            $event = $_ | ConvertFrom-Json

            # Alert on critical events
            if ($event.severity -in @("critical", "high")) {
                Write-AuditLog "ALERT: $($event.event_type) - $($event.action) by $($event.user_name)" $event.severity.ToUpper()
            }
        } catch {
            # Skip malformed lines
        }
    }
}

# Main execution
switch ($Action) {
    "log" {
        # Example: Log an authentication event
        if ($Event.Count -gt 0) {
            $auditEvent = [AuditEvent]::new($Event.event_type, $Event.severity)
            $auditEvent.UserName = $Event.user_name
            $auditEvent.Action = $Event.action
            $auditEvent.Resource = $Event.resource
            $auditEvent.Result = $Event.result
            $auditEvent.Details = $Event.details

            Write-AuditEvent -Event $auditEvent
            Write-AuditLog "Event logged: $($auditEvent.EventId)" "SUCCESS"
        } else {
            Write-Host @"
Usage: .\audit_logger.ps1 -Action log -Event @{
    event_type = "authentication"
    severity = "info"
    user_name = "john.doe"
    action = "login"
    resource = "api"
    result = "success"
    details = @{ ip = "192.168.1.100" }
}
"@ -ForegroundColor Cyan
        }
    }
    "query" {
        $results = Get-AuditEvents -Start $StartTime -End $EndTime

        if ($results.Count -gt 0) {
            $results | Select-Object -First 20 | Format-Table timestamp, event_type, severity, user_name, resource, action -AutoSize | Out-String | Write-Host
            Write-Host "Showing first 20 of $($results.Count) events" -ForegroundColor Gray
        } else {
            Write-AuditLog "No events found" "INFO"
        }
    }
    "export" {
        $outputFile = if ($ExportPath) { $ExportPath } else { "audit_export_$(Get-Date -Format 'yyyyMMdd_HHmmss').json" }
        Export-AuditLog -Start $StartTime -End $EndTime -OutputPath $outputFile
    }
    "monitor" {
        $todayLog = Join-Path $LogPath "audit_$(Get-Date -Format 'yyyyMMdd').log"
        if (Test-Path $todayLog) {
            Start-AuditMonitor -LogFile $todayLog
        } else {
            Write-AuditLog "No log file found for today" "ERROR"
        }
    }
}
