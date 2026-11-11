# RawrXD Advanced Audit System
# Phase K Batch 4/5: Comprehensive Audit Logging
# Tracks all system events with tamper-evident logging

param(
    [Parameter()]
    [ValidateSet("LogEvent", "QueryEvents", "ExportAudit", "VerifyIntegrity", "ShowStatus")]
    [string]$Action = "ShowStatus",
    
    [Parameter()]
    [string]$EventType,
    
    [Parameter()]
    [string]$UserId,
    
    [Parameter()]
    [string]$TenantId,
    
    [Parameter()]
    [hashtable]$EventData = @{},
    
    [Parameter()]
    [string]$StartTime,
    
    [Parameter()]
    [string]$EndTime,
    
    [Parameter()]
    [string]$ExportPath,
    
    [Parameter()]
    [string]$DataPath = "$PSScriptRoot\audit_data",
    
    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\..\..\logs\enterprise"
)

# Event type definitions
$EventTypes = @{
    "AUTH" = @{ Name = "Authentication"; Severity = "HIGH"; Retention = 365 }
    "AUTH_FAIL" = @{ Name = "Authentication Failure"; Severity = "CRITICAL"; Retention = 730 }
    "ACCESS" = @{ Name = "Resource Access"; Severity = "MEDIUM"; Retention = 90 }
    "CONFIG_CHANGE" = @{ Name = "Configuration Change"; Severity = "HIGH"; Retention = 365 }
    "DATA_ACCESS" = @{ Name = "Data Access"; Severity = "HIGH"; Retention = 365 }
    "DATA_MODIFY" = @{ Name = "Data Modification"; Severity = "CRITICAL"; Retention = 730 }
    "ADMIN" = @{ Name = "Administrative Action"; Severity = "CRITICAL"; Retention = 730 }
    "SYSTEM" = @{ Name = "System Event"; Severity = "MEDIUM"; Retention = 90 }
    "SECURITY" = @{ Name = "Security Event"; Severity = "CRITICAL"; Retention = 730 }
    "COMPLIANCE" = @{ Name = "Compliance Event"; Severity = "HIGH"; Retention = 2555 }  # 7 years
}

# Ensure directories exist
if (-not (Test-Path $DataPath)) {
    New-Item -ItemType Directory -Path $DataPath -Force | Out-Null
}
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

$StateFile = "$PSScriptRoot\audit_state.json"
$CurrentLogFile = Join-Path $DataPath "audit_$(Get-Date -Format 'yyyyMM').log"

function Get-AuditState {
    if (Test-Path $StateFile) {
        return Get-Content $StateFile | ConvertFrom-Json
    }
    return @{
        LastEventId = 0
        LastHash = "0" * 64
        ChainStart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        EventCounts = @{}
        Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

function Save-AuditState {
    param($State)
    $State | ConvertTo-Json | Out-File $StateFile -Encoding UTF8
}

function Get-EventHash {
    param([hashtable]$Event)
    
    $eventString = ($Event.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "|"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($eventString)
    $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    return [BitConverter]::ToString($hash).Replace("-", "").ToLower()
}

function Write-AuditEvent {
    param(
        [string]$Type,
        [string]$User = "system",
        [string]$Tenant = "global",
        [hashtable]$Data = @{},
        [string]$Severity = "INFO"
    )
    
    if (-not $EventTypes.ContainsKey($Type)) {
        $Type = "SYSTEM"
    }
    
    $state = Get-AuditState
    $state.LastEventId++
    $eventId = $state.LastEventId
    
    $event = @{
        Id = $eventId
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        Type = $Type
        UserId = $User
        TenantId = $Tenant
        Severity = $Severity
        Data = $Data
        PreviousHash = $state.LastHash
    }
    
    # Calculate event hash including previous hash for chain integrity
    $event.Hash = Get-EventHash -Event $event
    $state.LastHash = $event.Hash
    
    # Update event counts
    if (-not $state.EventCounts.ContainsKey($Type)) {
        $state.EventCounts[$Type] = 0
    }
    $state.EventCounts[$Type]++
    
    Save-AuditState -State $state
    
    # Write to audit log
    $logEntry = $event | ConvertTo-Json -Compress
    Add-Content -Path $CurrentLogFile -Value $logEntry
    
    # Also write to standard log
    $logFile = Join-Path $LogPath "audit_$(Get-Date -Format 'yyyyMMdd').log"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "[$timestamp] [AUDIT:$Type] [User:$User] [Tenant:$Tenant] Event #$eventId"
    Add-Content -Path $logFile -Value $logLine
    
    $color = switch ($EventTypes[$Type].Severity) {
        "CRITICAL" { "Red" }
        "HIGH" { "Yellow" }
        "MEDIUM" { "Cyan" }
        default { "Gray" }
    }
    Write-Host $logLine -ForegroundColor $color
    
    return $event
}

function Get-AuditEvents {
    param(
        [string]$FilterType,
        [string]$FilterUser,
        [string]$FilterTenant,
        [DateTime]$FilterStart,
        [DateTime]$FilterEnd,
        [int]$Limit = 100
    )
    
    $events = @()
    
    # Get all audit log files
    $logFiles = Get-ChildItem -Path $DataPath -Filter "audit_*.log" | Sort-Object Name
    
    foreach ($file in $logFiles) {
        $lines = Get-Content $file.FullName
        foreach ($line in $lines) {
            try {
                $event = $line | ConvertFrom-Json
                
                # Apply filters
                if ($FilterType -and $event.Type -ne $FilterType) { continue }
                if ($FilterUser -and $event.UserId -ne $FilterUser) { continue }
                if ($FilterTenant -and $event.TenantId -ne $FilterTenant) { continue }
                
                $eventTime = [DateTime]::Parse($event.Timestamp)
                if ($FilterStart -and $eventTime -lt $FilterStart) { continue }
                if ($FilterEnd -and $eventTime -gt $FilterEnd) { continue }
                
                $events += $event
            }
            catch {
                # Skip malformed lines
            }
        }
    }
    
    return $events | Sort-Object Id -Descending | Select-Object -First $Limit
}

function Export-AuditLog {
    param(
        [string]$OutputPath,
        [DateTime]$StartTime,
        [DateTime]$EndTime
    )
    
    $events = Get-AuditEvents -FilterStart $StartTime -FilterEnd $EndTime -Limit 10000
    
    $export = @{
        ExportTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        StartTime = $StartTime.ToString("yyyy-MM-dd HH:mm:ss")
        EndTime = $EndTime.ToString("yyyy-MM-dd HH:mm:ss")
        TotalEvents = $events.Count
        Events = $events
        IntegrityHash = ""
    }
    
    # Calculate integrity hash of export
    $exportString = ($events | ForEach-Object { $_.Hash }) -join ""
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($exportString)
    $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    $export.IntegrityHash = [BitConverter]::ToString($hash).Replace("-", "").ToLower()
    
    # Export to file
    $export | ConvertTo-Json -Depth 10 | Out-File $OutputPath -Encoding UTF8
    
    Write-Host "Exported $($events.Count) events to $OutputPath" -ForegroundColor Green
    Write-Host "Integrity hash: $($export.IntegrityHash)" -ForegroundColor Gray
    
    return $export
}

function Test-AuditIntegrity {
    $issues = @()
    $events = Get-AuditEvents -Limit 10000
    
    if ($events.Count -eq 0) {
        return @{ Valid = $true; Issues = @(); Message = "No events to verify" }
    }
    
    # Sort by ID to verify chain
    $sortedEvents = $events | Sort-Object Id
    
    $previousHash = "0" * 64
    
    for ($i = 0; $i -lt $sortedEvents.Count; $i++) {
        $event = $sortedEvents[$i]
        
        # Verify previous hash linkage
        if ($event.PreviousHash -ne $previousHash) {
            $issues += @{
                EventId = $event.Id
                Issue = "Hash chain broken"
                Expected = $previousHash
                Found = $event.PreviousHash
            }
        }
        
        # Verify event hash
        $eventCopy = $event.PSObject.Copy()
        $eventCopy.PSObject.Properties.Remove("Hash")
        $calculatedHash = Get-EventHash -Event ($eventCopy | ConvertTo-Json | ConvertFrom-Json)
        
        if ($calculatedHash -ne $event.Hash) {
            $issues += @{
                EventId = $event.Id
                Issue = "Event hash mismatch"
                Expected = $calculatedHash
                Found = $event.Hash
            }
        }
        
        $previousHash = $event.Hash
    }
    
    return @{
        Valid = $issues.Count -eq 0
        TotalEvents = $events.Count
        Issues = $issues
        Message = if ($issues.Count -eq 0) { "Audit chain verified successfully" } else { "Found $($issues.Count) integrity issues" }
    }
}

function Show-AuditStatus {
    $state = Get-AuditState
    $events = Get-AuditEvents -Limit 1
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           RawrXD Advanced Audit System Status                 ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Total Events: $($state.LastEventId)" -ForegroundColor Cyan
    Write-Host "║ Chain Start: $($state.ChainStart)" -ForegroundColor Cyan
    Write-Host "║ Last Hash: $($state.LastHash.Substring(0,16))..." -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    if ($state.EventCounts.Count -gt 0) {
        Write-Host "║ Event Counts by Type:" -ForegroundColor Cyan
        foreach ($type in $state.EventCounts.Keys | Sort-Object) {
            $count = $state.EventCounts[$type]
            $severity = $EventTypes[$type].Severity
            $color = switch ($severity) {
                "CRITICAL" { "Red" }
                "HIGH" { "Yellow" }
                default { "Gray" }
            }
            Write-Host "║   $type`: $count" -ForegroundColor $color
        }
    }
    
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Event Types:" -ForegroundColor Cyan
    foreach ($type in $EventTypes.Keys | Sort-Object) {
        $info = $EventTypes[$type]
        Write-Host "║   $type - $($info.Name) [Retention: $($info.Retention) days]" -ForegroundColor Gray
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
switch ($Action) {
    "LogEvent" {
        if (-not $EventType) {
            Write-Host "EventType required" -ForegroundColor Red
            exit 1
        }
        $event = Write-AuditEvent -Type $EventType -User $UserId -Tenant $TenantId -Data $EventData
        $event | ConvertTo-Json
    }
    "QueryEvents" {
        $start = if ($StartTime) { [DateTime]::Parse($StartTime) } else { (Get-Date).AddDays(-7) }
        $end = if ($EndTime) { [DateTime]::Parse($EndTime) } else { Get-Date }
        
        $events = Get-AuditEvents -FilterType $EventType -FilterUser $UserId -FilterTenant $TenantId -FilterStart $start -FilterEnd $end
        $events | ConvertTo-Json -Depth 10
    }
    "ExportAudit" {
        if (-not $ExportPath) {
            Write-Host "ExportPath required" -ForegroundColor Red
            exit 1
        }
        $start = if ($StartTime) { [DateTime]::Parse($StartTime) } else { (Get-Date).AddDays(-30) }
        $end = if ($EndTime) { [DateTime]::Parse($EndTime) } else { Get-Date }
        
        Export-AuditLog -OutputPath $ExportPath -StartTime $start -EndTime $end
    }
    "VerifyIntegrity" {
        $result = Test-AuditIntegrity
        $result | ConvertTo-Json -Depth 10
    }
    "ShowStatus" {
        Show-AuditStatus
    }
}
