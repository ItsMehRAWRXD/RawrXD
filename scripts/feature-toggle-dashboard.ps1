# RawrXD Feature Toggle Dashboard
# Manages feature flags with rollout percentages and targeting
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [ValidateSet("List", "Create", "Enable", "Disable", "Rollout", "Target", "Status")]
    [string]$Action = "List",
    
    [Parameter()]
    [string]$FeatureName,
    
    [Parameter()]
    [string]$Description,
    
    [Parameter()]
    [ValidateSet("Boolean", "Percentage", "UserGroup", "TimeBased")]
    [string]$Type = "Boolean",
    
    [Parameter()]
    [int]$Percentage = 0,
    
    [Parameter()]
    [string[]]$UserGroups = @(),
    
    [Parameter()]
    [hashtable]$Metadata = @{},
    
    [Parameter()]
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }

function Get-FeatureStorePath {
    return "$PSScriptRoot\.feature-toggles.json"
}

function Get-FeatureStore {
    $path = Get-FeatureStorePath
    if (Test-Path $path) {
        return Get-Content $path | ConvertFrom-Json
    }
    return @{ Features = @(); History = @() }
}

function Save-FeatureStore {
    param([hashtable]$Data)
    $Data | ConvertTo-Json -Depth 10 | Set-Content (Get-FeatureStorePath)
}

function Show-FeatureList {
    $store = Get-FeatureStore
    
    Write-Host "`nFeature Toggle Dashboard" -ForegroundColor Cyan
    Write-Host "========================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($store.Features.Count -eq 0) {
        Write-Status "No feature toggles configured"
        return
    }
    
    Write-Host "Feature Name         Type         Status    Rollout    Target Groups"
    Write-Host "------------         ----         ------    -------    -------------"
    
    foreach ($feature in $store.Features) {
        $statusColor = switch ($feature.Status) {
            "Enabled" { "Green" }
            "Rolling" { "Yellow" }
            "Disabled" { "Red" }
            default { "White" }
        }
        
        $targetGroups = if ($feature.UserGroups) { $feature.UserGroups -join ", " } else { "All" }
        
        Write-Host ($feature.Name).PadRight(21) -NoNewline
        Write-Host ($feature.Type).PadRight(13) -NoNewline
        Write-Host ($feature.Status).PadRight(10) -ForegroundColor $statusColor -NoNewline
        Write-Host "$($feature.Percentage)%".PadRight(11) -NoNewline
        Write-Host $targetGroups
    }
    Write-Host ""
}

function New-FeatureToggle {
    if (-not $FeatureName) {
        throw "FeatureName parameter required for Create action"
    }
    
    $store = Get-FeatureStore
    
    if ($store.Features | Where-Object { $_.Name -eq $FeatureName }) {
        throw "Feature '$FeatureName' already exists"
    }
    
    $feature = @{
        Name = $FeatureName
        Description = $Description
        Type = $Type
        Status = "Disabled"
        Percentage = if ($Type -eq "Percentage") { $Percentage } else { 0 }
        UserGroups = $UserGroups
        Metadata = $Metadata
        CreatedAt = (Get-Date).ToString("o")
        UpdatedAt = (Get-Date).ToString("o")
        CreatedBy = $env:USERNAME
    }
    
    $store.Features += $feature
    
    $store.History += @{
        FeatureName = $FeatureName
        Action = "Created"
        Timestamp = (Get-Date).ToString("o")
        User = $env:USERNAME
    }
    
    Save-FeatureStore -Data $store
    
    Write-Success "Feature toggle '$FeatureName' created"
    Write-Status "Type: $Type"
    Write-Status "Status: Disabled (use Enable to activate)"
}

function Set-FeatureState {
    param([string]$State)
    
    if (-not $FeatureName) {
        throw "FeatureName parameter required"
    }
    
    $store = Get-FeatureStore
    $feature = $store.Features | Where-Object { $_.Name -eq $FeatureName }
    
    if (-not $feature) {
        throw "Feature '$FeatureName' not found"
    }
    
    $feature.Status = $State
    $feature.UpdatedAt = (Get-Date).ToString("o")
    
    $store.History += @{
        FeatureName = $FeatureName
        Action = $State
        Timestamp = (Get-Date).ToString("o")
        User = $env:USERNAME
    }
    
    Save-FeatureStore -Data $store
    
    Write-Success "Feature '$FeatureName' is now $State"
}

function Update-RolloutPercentage {
    if (-not $FeatureName) {
        throw "FeatureName parameter required for Rollout action"
    }
    
    $store = Get-FeatureStore
    $feature = $store.Features | Where-Object { $_.Name -eq $FeatureName }
    
    if (-not $feature) {
        throw "Feature '$FeatureName' not found"
    }
    
    if ($feature.Type -ne "Percentage") {
        throw "Feature '$FeatureName' is not a percentage-based toggle"
    }
    
    $oldPercentage = $feature.Percentage
    $feature.Percentage = $Percentage
    $feature.Status = if ($Percentage -eq 100) { "Enabled" } elseif ($Percentage -eq 0) { "Disabled" } else { "Rolling" }
    $feature.UpdatedAt = (Get-Date).ToString("o")
    
    $store.History += @{
        FeatureName = $FeatureName
        Action = "Rollout"
        OldValue = "$oldPercentage%"
        NewValue = "$Percentage%"
        Timestamp = (Get-Date).ToString("o")
        User = $env:USERNAME
    }
    
    Save-FeatureStore -Data $store
    
    Write-Success "Feature '$FeatureName' rollout updated to $Percentage%"
}

function Set-FeatureTargeting {
    if (-not $FeatureName) {
        throw "FeatureName parameter required for Target action"
    }
    
    $store = Get-FeatureStore
    $feature = $store.Features | Where-Object { $_.Name -eq $FeatureName }
    
    if (-not $feature) {
        throw "Feature '$FeatureName' not found"
    }
    
    $feature.UserGroups = $UserGroups
    $feature.UpdatedAt = (Get-Date).ToString("o")
    
    Save-FeatureStore -Data $store
    
    Write-Success "Feature '$FeatureName' targeting updated"
    Write-Status "Target groups: $($UserGroups -join ', ')"
}

function Show-FeatureStatus {
    if (-not $FeatureName) {
        throw "FeatureName parameter required for Status action"
    }
    
    $store = Get-FeatureStore
    $feature = $store.Features | Where-Object { $_.Name -eq $FeatureName }
    
    if (-not $feature) {
        throw "Feature '$FeatureName' not found"
    }
    
    Write-Host "`nFeature Status: $FeatureName" -ForegroundColor Cyan
    Write-Host "==========================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Name: $($feature.Name)"
    Write-Host "Description: $($feature.Description)"
    Write-Host "Type: $($feature.Type)"
    Write-Host "Status: $($feature.Status)" -ForegroundColor $(
        switch ($feature.Status) {
            "Enabled" { "Green" }
            "Rolling" { "Yellow" }
            "Disabled" { "Red" }
        }
    )
    Write-Host "Rollout: $($feature.Percentage)%"
    Write-Host "Target Groups: $(if ($feature.UserGroups) { $feature.UserGroups -join ', ' } else { 'All Users' })"
    Write-Host "Created: $($feature.CreatedAt)"
    Write-Host "Updated: $($feature.UpdatedAt)"
    Write-Host "Created By: $($feature.CreatedBy)"
    Write-Host ""
    
    # Show recent history
    $history = $store.History | Where-Object { $_.FeatureName -eq $FeatureName } | Select-Object -Last 5
    if ($history.Count -gt 0) {
        Write-Host "Recent Changes:" -ForegroundColor Yellow
        foreach ($entry in $history) {
            Write-Host "  [$($entry.Timestamp)] $($entry.Action) by $($entry.User)"
        }
    }
    Write-Host ""
}

# Main execution
try {
    switch ($Action) {
        "List" { Show-FeatureList }
        "Create" { New-FeatureToggle }
        "Enable" { Set-FeatureState -State "Enabled" }
        "Disable" { Set-FeatureState -State "Disabled" }
        "Rollout" { Update-RolloutPercentage }
        "Target" { Set-FeatureTargeting }
        "Status" { Show-FeatureStatus }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
