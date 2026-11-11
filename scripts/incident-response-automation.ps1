# RawrXD Incident Response Automation
# Automated incident detection, response, and resolution workflows
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [ValidateSet("Detect", "Create", "Respond", "Resolve", "Status", "History", "Escalate")]
    [string]$Action = "Status",
    
    [Parameter()]
    [string]$IncidentId,
    
    [Parameter()]
    [ValidateSet("Critical", "High", "Medium", "Low")]
    [string]$Severity = "Medium",
    
    [Parameter()]
    [string]$Title,
    
    [Parameter()]
    [string]$Description,
    
    [Parameter()]
    [string]$Service,
    
    [Parameter()]
    [hashtable]$Tags = @{},
    
    [Parameter()]
    [string]$AssignedTo,
    
    [Parameter()]
    [string]$Resolution,
    
    [Parameter()]
    [switch]$AutoRemediate
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

function Get-IncidentsPath {
    return "$PSScriptRoot\.incidents.json"
}

function Get-Incidents {
    $path = Get-IncidentsPath
    if (Test-Path $path) {
        return Get-Content $path | ConvertFrom-Json
    }
    return @{ Incidents = @(); NextId = 1 }
}

function Save-Incidents {
    param([hashtable]$Data)
    $Data | ConvertTo-Json -Depth 10 | Set-Content (Get-IncidentsPath)
}

function New-IncidentId {
    return "INC-$(Get-Date -Format 'yyyyMMdd')-$(Get-Random -Minimum 1000 -Maximum 9999)"
}

function Show-IncidentStatus {
    $data = Get-Incidents
    
    Write-Host "`nIncident Status" -ForegroundColor Cyan
    Write-Host "===============" -ForegroundColor Cyan
    Write-Host ""
    
    $active = ($data.Incidents | Where-Object { $_.Status -ne "Resolved" }).Count
    $critical = ($data.Incidents | Where-Object { $_.Severity -eq "Critical" -and $_.Status -ne "Resolved" }).Count
    
    Write-Host "Active Incidents: $active" -ForegroundColor $(if ($active -gt 0) { "Yellow" } else { "Green" })
    Write-Host "Critical: $critical" -ForegroundColor $(if ($critical -gt 0) { "Red" } else { "Green" })
    Write-Host "Total: $($data.Incidents.Count)"
    Write-Host ""
    
    $openIncidents = $data.Incidents | Where-Object { $_.Status -ne "Resolved" } | Sort-Object CreatedAt -Descending | Select-Object -First 10
    
    if ($openIncidents.Count -gt 0) {
        Write-Host "Open Incidents:" -ForegroundColor Yellow
        Write-Host "ID                Severity    Service           Status      Title"
        Write-Host "--                --------    -------           ------      -----"
        
        foreach ($inc in $openIncidents) {
            $color = switch ($inc.Severity) {
                "Critical" { "Red" }
                "High" { "Yellow" }
                default { "White" }
            }
            
            Write-Host $inc.Id.PadRight(18) -NoNewline
            Write-Host $inc.Severity.PadRight(12) -ForegroundColor $color -NoNewline
            Write-Host $inc.Service.PadRight(18) -NoNewline
            Write-Host $inc.Status.PadRight(12) -NoNewline
            Write-Host $inc.Title
        }
        Write-Host ""
    }
}

function Invoke-IncidentDetection {
    Write-Status "Running incident detection..."
    
    # Simulated detection logic
    $alerts = @(
        @{ Service = "api"; Metric = "error_rate"; Value = 15; Threshold = 5 },
        @{ Service = "database"; Metric = "latency"; Value = 2000; Threshold = 500 }
    )
    
    $detected = @()
    
    foreach ($alert in $alerts) {
        if ($alert.Value -gt $alert.Threshold) {
            $detected += $alert
            Write-Warning "Alert: $($alert.Service) - $($alert.Metric) is $($alert.Value) (threshold: $($alert.Threshold))"
        }
    }
    
    if ($detected.Count -gt 0) {
        Write-Status "Detected $($detected.Count) potential incidents"
        
        foreach ($det in $detected) {
            $title = "$($det.Service) $($det.metric) elevated"
            $desc = "$($det.Metric) is $($det.Value), exceeding threshold of $($det.Threshold)"
            
            $severity = if ($det.Value -gt $det.Threshold * 3) { "Critical" } 
                       elseif ($det.Value -gt $det.Threshold * 2) { "High" }
                       else { "Medium" }
            
            New-Incident -Title $title -Description $desc -Service $det.Service -Severity $severity
        }
    } else {
        Write-Success "No incidents detected"
    }
}

function New-Incident {
    param([string]$Title, [string]$Description, [string]$Service, [string]$Severity)
    
    $data = Get-Incidents
    
    $incident = @{
        Id = New-IncidentId
        Title = $Title
        Description = $Description
        Service = $Service
        Severity = $Severity
        Status = "Open"
        Tags = $Tags
        AssignedTo = $AssignedTo
        CreatedAt = (Get-Date).ToString("o")
        UpdatedAt = (Get-Date).ToString("o")
        ResolvedAt = $null
        Resolution = $null
        Timeline = @(@{ Time = (Get-Date).ToString("o"); Action = "Incident created"; User = $env:USERNAME })
    }
    
    $data.Incidents += $incident
    Save-Incidents -Data $data
    
    Write-Success "Incident created: $($incident.Id)"
    Write-Status "Severity: $Severity"
    Write-Status "Service: $Service"
    
    # Auto-remediate if enabled
    if ($AutoRemediate) {
        Invoke-IncidentResponse -IncidentId $incident.Id -Severity $Severity
    }
}

function Invoke-IncidentResponse {
    param([string]$IncidentId, [string]$Severity)
    
    $data = Get-Incidents
    $incident = $data.Incidents | Where-Object { $_.Id -eq $IncidentId }
    
    if (-not $incident) {
        throw "Incident not found: $IncidentId"
    }
    
    Write-Status "Responding to incident: $IncidentId"
    
    # Automated response based on severity and service
    $responses = @()
    
    switch ($incident.Service) {
        "api" {
            $responses += "Restarting API service"
            $responses += "Checking load balancer health"
        }
        "database" {
            $responses += "Checking database connections"
            $responses += "Analyzing slow query log"
        }
        default {
            $responses += "Gathering diagnostic information"
        }
    }
    
    foreach ($response in $responses) {
        Write-Status "  → $response"
        Start-Sleep -Seconds 1  # Simulate action
    }
    
    $incident.Status = "In Progress"
    $incident.UpdatedAt = (Get-Date).ToString("o")
    $incident.Timeline += @{ Time = (Get-Date).ToString("o"); Action = "Automated response initiated"; User = "System" }
    
    Save-Incidents -Data $data
    Write-Success "Response actions completed"
}

function Resolve-Incident {
    if (-not $IncidentId) {
        throw "IncidentId parameter required for Resolve action"
    }
    
    if (-not $Resolution) {
        throw "Resolution parameter required"
    }
    
    $data = Get-Incidents
    $incident = $data.Incidents | Where-Object { $_.Id -eq $IncidentId }
    
    if (-not $incident) {
        throw "Incident not found: $IncidentId"
    }
    
    $incident.Status = "Resolved"
    $incident.Resolution = $Resolution
    $incident.ResolvedAt = (Get-Date).ToString("o")
    $incident.UpdatedAt = (Get-Date).ToString("o")
    $incident.Timeline += @{ Time = (Get-Date).ToString("o"); Action = "Incident resolved: $Resolution"; User = $env:USERNAME }
    
    Save-Incidents -Data $data
    
    Write-Success "Incident $IncidentId resolved"
    Write-Status "Resolution: $Resolution"
}

function Show-IncidentHistory {
    $data = Get-Incidents
    
    Write-Host "`nIncident History" -ForegroundColor Cyan
    Write-Host "=================" -ForegroundColor Cyan
    Write-Host ""
    
    $resolved = $data.Incidents | Where-Object { $_.Status -eq "Resolved" } | Sort-Object ResolvedAt -Descending | Select-Object -First 10
    
    if ($resolved.Count -eq 0) {
        Write-Status "No resolved incidents"
        return
    }
    
    Write-Host "Recently Resolved Incidents:"
    Write-Host "ID                Service           Severity    Duration    Resolution"
    Write-Host "--                -------           --------    --------    ----------"
    
    foreach ($inc in $resolved) {
        $created = [datetime]$inc.CreatedAt
        $resolved = [datetime]$inc.ResolvedAt
        $duration = $resolved - $created
        
        Write-Host $inc.Id.PadRight(18) -NoNewline
        Write-Host $inc.Service.PadRight(18) -NoNewline
        Write-Host $inc.Severity.PadRight(12) -NoNewline
        Write-Host $duration.ToString("hh\:mm\:ss").PadRight(12) -NoNewline
        Write-Host $inc.Resolution
    }
    Write-Host ""
}

function Invoke-Escalation {
    if (-not $IncidentId) {
        throw "IncidentId parameter required for Escalate action"
    }
    
    $data = Get-Incidents
    $incident = $data.Incidents | Where-Object { $_.Id -eq $IncidentId }
    
    if (-not $incident) {
        throw "Incident not found: $IncidentId"
    }
    
    $severities = @("Low", "Medium", "High", "Critical")
    $currentIndex = $severities.IndexOf($incident.Severity)
    
    if ($currentIndex -lt $severities.Count - 1) {
        $newSeverity = $severities[$currentIndex + 1]
        $incident.Severity = $newSeverity
        $incident.UpdatedAt = (Get-Date).ToString("o")
        $incident.Timeline += @{ Time = (Get-Date).ToString("o"); Action = "Escalated to $newSeverity"; User = $env:USERNAME }
        
        Save-Incidents -Data $data
        Write-Success "Incident escalated to $newSeverity"
    } else {
        Write-Warning "Incident is already at maximum severity"
    }
}

# Main execution
try {
    switch ($Action) {
        "Detect" { Invoke-IncidentDetection }
        "Create" { 
            if (-not $Title -or -not $Service) {
                throw "Title and Service parameters required for Create action"
            }
            New-Incident -Title $Title -Description $Description -Service $Service -Severity $Severity 
        }
        "Respond" { Invoke-IncidentResponse -IncidentId $IncidentId -Severity $Severity }
        "Resolve" { Resolve-Incident }
        "Status" { Show-IncidentStatus }
        "History" { Show-IncidentHistory }
        "Escalate" { Invoke-Escalation }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
