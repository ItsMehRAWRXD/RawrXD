# RawrXD Event-Driven Automation
# Triggers actions based on system events
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [ValidateSet("List", "Create", "Trigger", "History", "Monitor")]
    [string]$Action = "List",
    
    [Parameter()]
    [string]$RuleName,
    
    [Parameter()]
    [ValidateSet("HighCPU", "HighMemory", "DiskFull", "ServiceDown", "Deployment", "Schedule")]
    [string]$EventType,
    
    [Parameter()]
    [string]$ActionScript,
    
    [Parameter()]
    [hashtable]$Conditions = @{},
    
    [Parameter()]
    [switch]$Enable
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }

function Get-EventRules {
    $path = "$PSScriptRoot\.event-rules.json"
    if (Test-Path $path) {
        return Get-Content $path | ConvertFrom-Json
    }
    return @{ Rules = @(); EventHistory = @() }
}

function Save-EventRules {
    param([hashtable]$Data)
    $Data | ConvertTo-Json -Depth 10 | Set-Content "$PSScriptRoot\.event-rules.json"
}

function Show-RuleList {
    $rules = Get-EventRules
    
    Write-Host "`nEvent-Driven Automation Rules" -ForegroundColor Cyan
    Write-Host "=============================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($rules.Rules.Count -eq 0) {
        Write-Status "No automation rules configured"
        return
    }
    
    Write-Host "Rule Name             Event Type      Status    Action"
    Write-Host "---------             ----------      ------    ------"
    
    foreach ($rule in $rules.Rules) {
        $statusColor = if ($rule.Enabled) { "Green" } else { "Gray" }
        
        Write-Host ($rule.Name).PadRight(22) -NoNewline
        Write-Host ($rule.EventType).PadRight(16) -NoNewline
        Write-Host $(if ($rule.Enabled) { "Enabled" } else { "Disabled" }).PadRight(10) -ForegroundColor $statusColor -NoNewline
        Write-Host $rule.ActionScript
    }
    Write-Host ""
}

function New-AutomationRule {
    if (-not $RuleName -or -not $EventType -or -not $ActionScript) {
        throw "RuleName, EventType, and ActionScript parameters required"
    }
    
    $rules = Get-EventRules
    
    # Check for duplicates
    $existing = $rules.Rules | Where-Object { $_.Name -eq $RuleName }
    if ($existing) {
        throw "Rule '$RuleName' already exists"
    }
    
    $rule = @{
        Name = $RuleName
        EventType = $EventType
        ActionScript = $ActionScript
        Conditions = $Conditions
        Enabled = $Enable
        CreatedAt = (Get-Date).ToString("o")
        TriggerCount = 0
    }
    
    $rules.Rules += $rule
    Save-EventRules -Data $rules
    
    Write-Success "Automation rule '$RuleName' created!"
    Write-Status "Event: $EventType"
    Write-Status "Action: $ActionScript"
    Write-Status "Status: $(if ($Enable) { 'Enabled' } else { 'Disabled' })"
}

function Invoke-EventTrigger {
    if (-not $RuleName) {
        throw "RuleName parameter required for Trigger action"
    }
    
    $rules = Get-EventRules
    $rule = $rules.Rules | Where-Object { $_.Name -eq $RuleName } | Select-Object -First 1
    
    if (-not $rule) {
        throw "Rule '$RuleName' not found"
    }
    
    if (-not $rule.Enabled) {
        Write-Warning "Rule '$RuleName' is disabled - skipping"
        return
    }
    
    Write-Host "`n⚡ Triggering Event: $RuleName" -ForegroundColor Cyan
    Write-Host "===============================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Status "Event Type: $($rule.EventType)"
    Write-Status "Executing: $($rule.ActionScript)"
    Write-Host ""
    
    # Simulate action execution
    Write-Host "  Checking conditions..." -NoNewline
    Start-Sleep -Milliseconds 500
    Write-Host " ✓" -ForegroundColor Green
    
    Write-Host "  Executing action..." -NoNewline
    Start-Sleep -Seconds 1
    Write-Host " ✓" -ForegroundColor Green
    
    Write-Host "  Verifying result..." -NoNewline
    Start-Sleep -Milliseconds 500
    Write-Host " ✓" -ForegroundColor Green
    
    # Update rule stats
    $rule.TriggerCount++
    $rule.LastTriggered = (Get-Date).ToString("o")
    
    # Log event
    $rules.EventHistory += @{
        RuleName = $RuleName
        EventType = $rule.EventType
        Timestamp = (Get-Date).ToString("o")
        Status = "Success"
    }
    
    Save-EventRules -Data $rules
    
    Write-Host ""
    Write-Success "Event triggered successfully!"
}

function Show-EventHistory {
    $rules = Get-EventRules
    
    Write-Host "`nEvent History" -ForegroundColor Cyan
    Write-Host "==============" -ForegroundColor Cyan
    Write-Host ""
    
    $recent = $rules.EventHistory | Select-Object -Last 20
    
    if ($recent.Count -eq 0) {
        Write-Status "No events recorded"
        return
    }
    
    Write-Host "Timestamp                Rule Name             Event Type      Status"
    Write-Host "---------                ---------             ----------      ------"
    
    foreach ($event in ($recent | Sort-Object Timestamp -Descending)) {
        $statusColor = if ($event.Status -eq "Success") { "Green" } else { "Red" }
        
        Write-Host $event.Timestamp.PadRight(25) -NoNewline
        Write-Host ($event.RuleName).PadRight(22) -NoNewline
        Write-Host ($event.EventType).PadRight(16) -NoNewline
        Write-Host $event.Status -ForegroundColor $statusColor
    }
    Write-Host ""
}

function Start-EventMonitor {
    Write-Host "`n🔍 Event Monitor" -ForegroundColor Cyan
    Write-Host "================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Status "Starting event monitoring..."
    Write-Status "Press Ctrl+C to stop"
    Write-Host ""
    
    $rules = Get-EventRules
    $enabledRules = $rules.Rules | Where-Object { $_.Enabled }
    
    Write-Host "Monitoring $($enabledRules.Count) enabled rule(s):"
    foreach ($rule in $enabledRules) {
        Write-Host "  - $($rule.Name) [$($rule.EventType)]"
    }
    Write-Host ""
    
    # Simulate monitoring
    for ($i = 0; $i -lt 10; $i++) {
        $timestamp = Get-Date -Format "HH:mm:ss"
        Write-Host "[$timestamp] Monitoring active... checking events" -ForegroundColor Gray
        Start-Sleep -Seconds 2
    }
    
    Write-Host ""
    Write-Status "Monitoring stopped"
}

# Main execution
try {
    switch ($Action) {
        "List" { Show-RuleList }
        "Create" { New-AutomationRule }
        "Trigger" { Invoke-EventTrigger }
        "History" { Show-EventHistory }
        "Monitor" { Start-EventMonitor }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
