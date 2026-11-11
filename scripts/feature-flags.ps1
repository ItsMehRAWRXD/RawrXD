# RawrXD Feature Flags Manager
# Manages feature flags and toggles for gradual rollouts

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("List", "Enable", "Disable", "Create", "Delete", "Rollout", "Status")]
    [string]$Action = "List",
    
    [string]$FlagName = "",
    [string]$Description = "",
    [ValidateSet("Boolean", "Percentage", "UserGroup", "TimeBased")]
    [string]$FlagType = "Boolean",
    [int]$Percentage = 0,
    [string[]]$UserGroups = @(),
    [string]$ConfigPath = "config/feature-flags.json",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$script:FeatureFlags = @{}

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

function Initialize-FeatureFlagsManager {
    Write-Status "Feature Flags Manager initialized"
    Write-Status "Action: $Action"
    
    # Load existing feature flags
    if (Test-Path $ConfigPath) {
        try {
            $script:FeatureFlags = Get-Content $ConfigPath | ConvertFrom-Json
        }
        catch {
            Write-Warning "Failed to load feature flags configuration"
            $script:FeatureFlags = @{}
        }
    }
}

function Save-FeatureFlags {
    $configDir = Split-Path $ConfigPath -Parent
    if ($configDir -and -not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }
    
    $script:FeatureFlags | ConvertTo-Json -Depth 5 | Out-File $ConfigPath
    Write-Success "Feature flags saved to $ConfigPath"
}

function Get-FeatureFlags {
    Write-Host ""
    Write-Host "Feature Flags" -ForegroundColor Cyan
    Write-Host "=============" -ForegroundColor Cyan
    
    if ($script:FeatureFlags.Count -eq 0) {
        Write-Warning "No feature flags configured"
        return
    }
    
    foreach ($flag in $script:FeatureFlags.PSObject.Properties) {
        $status = $flag.Value.enabled
        $statusColor = if ($status) { "Green" } else { "Red" }
        $statusText = if ($status) { "ENABLED" } else { "DISABLED" }
        
        Write-Host "  $($flag.Name)" -NoNewline
        Write-Host " [$statusText]" -ForegroundColor $statusColor
        Write-Host "    Type: $($flag.Value.type)"
        Write-Host "    Description: $($flag.Value.description)"
        
        if ($flag.Value.type -eq "Percentage") {
            Write-Host "    Rollout: $($flag.Value.percentage)%"
        }
        
        if ($flag.Value.modified) {
            Write-Host "    Last Modified: $($flag.Value.modified)"
        }
        Write-Host ""
    }
}

function New-FeatureFlag {
    if (-not $FlagName) {
        $FlagName = Read-Host "Enter feature flag name"
    }
    
    if ($script:FeatureFlags.$FlagName) {
        Write-Error "Feature flag '$FlagName' already exists"
        return
    }
    
    if (-not $Description) {
        $Description = Read-Host "Enter description"
    }
    
    Write-Status "Creating feature flag: $FlagName"
    
    $flag = @{
        name = $FlagName
        description = $Description
        type = $FlagType
        enabled = $false
        created = Get-Date -Format "o"
        modified = Get-Date -Format "o"
    }
    
    switch ($FlagType) {
        "Percentage" {
            $flag.percentage = $Percentage
        }
        "UserGroup" {
            $flag.userGroups = $UserGroups
        }
        "TimeBased" {
            $flag.startTime = $null
            $flag.endTime = $null
        }
    }
    
    $script:FeatureFlags | Add-Member -NotePropertyName $FlagName -NotePropertyValue $flag -Force
    
    Save-FeatureFlags
    Write-Success "Feature flag '$FlagName' created"
}

function Set-FeatureFlag {
    param([bool]$Enabled)
    
    if (-not $FlagName) {
        Write-Error "FlagName parameter required"
        return
    }
    
    if (-not $script:FeatureFlags.$FlagName) {
        Write-Error "Feature flag '$FlagName' not found"
        return
    }
    
    $action = if ($Enabled) { "Enabling" } else { "Disabling" }
    Write-Status "$action feature flag: $FlagName"
    
    $script:FeatureFlags.$FlagName.enabled = $Enabled
    $script:FeatureFlags.$FlagName.modified = Get-Date -Format "o"
    
    Save-FeatureFlags
    Write-Success "Feature flag '$FlagName' $(if($Enabled){'enabled'}else{'disabled'})"
}

function Remove-FeatureFlag {
    if (-not $FlagName) {
        Write-Error "FlagName parameter required"
        return
    }
    
    if (-not $script:FeatureFlags.$FlagName) {
        Write-Error "Feature flag '$FlagName' not found"
        return
    }
    
    if (-not $Force) {
        $confirm = Read-Host "Are you sure you want to delete '$FlagName'? (yes/no)"
        if ($confirm -ne "yes") {
            Write-Status "Deletion cancelled"
            return
        }
    }
    
    $script:FeatureFlags.PSObject.Properties.Remove($FlagName)
    Save-FeatureFlags
    Write-Success "Feature flag '$FlagName' deleted"
}

function Invoke-GradualRollout {
    if (-not $FlagName) {
        Write-Error "FlagName parameter required"
        return
    }
    
    if (-not $script:FeatureFlags.$FlagName) {
        Write-Error "Feature flag '$FlagName' not found"
        return
    }
    
    $flag = $script:FeatureFlags.$FlagName
    
    if ($flag.type -ne "Percentage") {
        Write-Error "Rollout only supported for Percentage-type flags"
        return
    }
    
    Write-Status "Starting gradual rollout for: $FlagName"
    
    $currentPercentage = $flag.percentage
    $targetPercentage = Read-Host "Enter target percentage (current: $currentPercentage%)"
    
    if ($targetPercentage -le $currentPercentage) {
        Write-Error "Target percentage must be greater than current"
        return
    }
    
    # Gradual rollout steps
    $steps = @(25, 50, 75, 100)
    
    foreach ($step in $steps) {
        if ($step -gt $targetPercentage) { break }
        if ($step -le $currentPercentage) { continue }
        
        Write-Status "Rolling out to $step%..."
        
        $flag.percentage = $step
        $flag.modified = Get-Date -Format "o"
        Save-FeatureFlags
        
        if ($step -lt $targetPercentage) {
            Write-Status "Waiting for stabilization..."
            Start-Sleep -Seconds 5
        }
    }
    
    # Enable flag when fully rolled out
    if ($targetPercentage -eq 100) {
        $flag.enabled = $true
        Save-FeatureFlags
    }
    
    Write-Success "Rollout complete: $FlagName at $targetPercentage%"
}

function Show-FlagStatus {
    if (-not $FlagName) {
        Write-Error "FlagName parameter required"
        return
    }
    
    if (-not $script:FeatureFlags.$FlagName) {
        Write-Error "Feature flag '$FlagName' not found"
        return
    }
    
    $flag = $script:FeatureFlags.$FlagName
    
    Write-Host ""
    Write-Host "Feature Flag Status: $FlagName" -ForegroundColor Cyan
    Write-Host "================================" -ForegroundColor Cyan
    Write-Host "Name: $($flag.name)"
    Write-Host "Description: $($flag.description)"
    Write-Host "Type: $($flag.type)"
    Write-Host "Enabled: $($flag.enabled)"
    Write-Host "Created: $($flag.created)"
    Write-Host "Modified: $($flag.modified)"
    
    if ($flag.type -eq "Percentage") {
        Write-Host "Rollout Percentage: $($flag.percentage)%"
    }
    
    if ($flag.userGroups) {
        Write-Host "User Groups: $($flag.userGroups -join ', ')"
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Feature Flags Manager" -ForegroundColor Cyan
    Write-Host "===========================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-FeatureFlagsManager
    
    switch ($Action) {
        "List" { Get-FeatureFlags }
        "Enable" { Set-FeatureFlag -Enabled $true }
        "Disable" { Set-FeatureFlag -Enabled $false }
        "Create" { New-FeatureFlag }
        "Delete" { Remove-FeatureFlag }
        "Rollout" { Invoke-GradualRollout }
        "Status" { Show-FlagStatus }
    }
    
    Write-Host ""
}

Main
