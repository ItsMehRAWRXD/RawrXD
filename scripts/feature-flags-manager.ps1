# RawrXD Feature Flags Manager
# Manages feature flags for gradual rollouts and experimentation

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("list", "create", "toggle", "rollout", "audit")]
    [string]$Action = "list",
    
    [string]$FlagName,
    [string]$Description,
    [ValidateSet("boolean", "percentage", "user_segment", "time_based")]
    [string]$FlagType = "boolean",
    [int]$RolloutPercentage = 0,
    [string[]]$UserSegments = @(),
    [switch]$Enable,
    [switch]$Disable,
    [string]$ConfigFile = "feature-flags.json"
)

$ErrorActionPreference = "Stop"

$FFConfig = @{
    ValidTypes = @("boolean", "percentage", "user_segment", "time_based")
    MaxRolloutPercentage = 100
    AuditRetentionDays = 90
}

$script:FFState = @{
    StartTime = Get-Date
    FlagsLoaded = 0
    ChangesMade = 0
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }

function Get-FeatureFlags {
    if (-not (Test-Path $ConfigFile)) {
        return @{}
    }
    
    return Get-Content $ConfigFile | ConvertFrom-Json
}

function Save-FeatureFlags {
    param($Flags)
    
    $Flags | ConvertTo-Json -Depth 3 | Out-File $ConfigFile
}

function Show-FeatureFlags {
    $flags = Get-FeatureFlags
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Feature Flags" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($flags.Count -eq 0) {
        Write-Host "No feature flags configured" -ForegroundColor Gray
        return
    }
    
    Write-Host "Name                 Type          Status    Rollout   Created" -ForegroundColor White
    Write-Host "----                 ----          ------    -------   -------" -ForegroundColor White
    
    foreach ($flag in $flags.PSObject.Properties) {
        $f = $flag.Value
        $status = if ($f.Enabled) { "Enabled" } else { "Disabled" }
        $statusColor = if ($f.Enabled) { "Green" } else { "Red" }
        
        Write-Host "$($flag.Name.PadRight(20)) $($f.Type.PadRight(13)) $status.PadRight(9) $($f.RolloutPercentage)%   $($f.CreatedAt)" -ForegroundColor $statusColor
    }
}

function New-FeatureFlag {
    if (-not $FlagName) {
        Write-Error "FlagName required"
        return
    }
    
    Write-Status "Creating feature flag: $FlagName"
    
    $flags = Get-FeatureFlags
    
    if ($flags.$FlagName) {
        Write-Warning "Flag already exists, updating..."
    }
    
    $flag = @{
        Name = $FlagName
        Type = $FlagType
        Description = $Description
        Enabled = $Enable -or ($RolloutPercentage -gt 0)
        RolloutPercentage = [math]::Min($RolloutPercentage, $FFConfig.MaxRolloutPercentage)
        UserSegments = $UserSegments
        CreatedAt = Get-Date -Format "o"
        UpdatedAt = Get-Date -Format "o"
        AuditLog = @()
    }
    
    $flags | Add-Member -NotePropertyName $FlagName -NotePropertyValue $flag -Force
    
    Save-FeatureFlags -Flags $flags
    $script:FFState.ChangesMade++
    
    Write-Success "Feature flag '$FlagName' created"
}

function Set-FeatureFlag {
    if (-not $FlagName) {
        Write-Error "FlagName required"
        return
    }
    
    $flags = Get-FeatureFlags
    
    if (-not $flags.$FlagName) {
        Write-Error "Flag not found: $FlagName"
        return
    }
    
    $flag = $flags.$FlagName
    
    if ($Enable) {
        $flag.Enabled = $true
        Write-Status "Enabled flag: $FlagName"
    }
    
    if ($Disable) {
        $flag.Enabled = $false
        Write-Status "Disabled flag: $FlagName"
    }
    
    if ($RolloutPercentage -gt 0) {
        $oldRollout = $flag.RolloutPercentage
        $flag.RolloutPercentage = [math]::Min($RolloutPercentage, $FFConfig.MaxRolloutPercentage)
        Write-Status "Updated rollout: $oldRollout% → $($flag.RolloutPercentage)%"
    }
    
    $flag.UpdatedAt = Get-Date -Format "o"
    $flag.AuditLog += @{
        Action = "toggle"
        Timestamp = Get-Date -Format "o"
        Enabled = $flag.Enabled
        RolloutPercentage = $flag.RolloutPercentage
    }
    
    Save-FeatureFlags -Flags $flags
    $script:FFState.ChangesMade++
    
    Write-Success "Feature flag updated"
}

function Invoke-GradualRollout {
    if (-not $FlagName) {
        Write-Error "FlagName required"
        return
    }
    
    $flags = Get-FeatureFlags
    $flag = $flags.$FlagName
    
    if (-not $flag) {
        Write-Error "Flag not found: $FlagName"
        return
    }
    
    Write-Status "Starting gradual rollout for $FlagName"
    
    $steps = @(1, 5, 10, 25, 50, 75, 100)
    
    foreach ($step in $steps) {
        if ($step -le $RolloutPercentage) {
            Write-Status "Rolling out to $step%..."
            $flag.RolloutPercentage = $step
            $flag.AuditLog += @{
                Action = "rollout"
                Timestamp = Get-Date -Format "o"
                RolloutPercentage = $step
            }
            Save-FeatureFlags -Flags $flags
            Start-Sleep -Seconds 1
        }
    }
    
    Write-Success "Rollout complete: $FlagName now at $($flag.RolloutPercentage)%"
}

function Show-FeatureFlagAudit {
    $flags = Get-FeatureFlags
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Feature Flag Audit Log" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($flag in $flags.PSObject.Properties) {
        $f = $flag.Value
        Write-Host "`n$($flag.Name):" -ForegroundColor White
        
        if ($f.AuditLog.Count -eq 0) {
            Write-Host "  No audit history" -ForegroundColor Gray
        } else {
            foreach ($entry in $f.AuditLog | Select-Object -Last 5) {
                Write-Host "  [$($entry.Timestamp)] $($entry.Action)" -ForegroundColor Gray
            }
        }
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Feature Flags Manager" -ForegroundColor Cyan
    Write-Host "============================" -ForegroundColor Cyan
    Write-Host ""
    
    switch ($Action) {
        "list" { Show-FeatureFlags }
        "create" { New-FeatureFlag }
        "toggle" { Set-FeatureFlag }
        "rollout" { Invoke-GradualRollout }
        "audit" { Show-FeatureFlagAudit }
    }
    
    Write-Host ""
    Write-Success "Feature flags manager complete!"
}

Main
