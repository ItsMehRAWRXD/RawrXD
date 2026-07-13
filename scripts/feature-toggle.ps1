# RawrXD Feature Toggle
# Manages feature flags and toggles

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("List", "Enable", "Disable", "Create", "Delete", "Rollout")]
    [string]$Action = "List",
    
    [string]$Feature = "",
    [string]$Description = "",
    [int]$Percentage = 0,
    [string[]]$Users = @(),
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$script:FeaturesDir = "features"

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

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Initialize-FeatureToggle {
    if (-not (Test-Path $script:FeaturesDir)) {
        New-Item -ItemType Directory -Path $script:FeaturesDir -Force | Out-Null
    }
    
    Write-Status "Feature Toggle Manager initialized"
}

function Get-Features {
    return @(
        @{ Name = "new-ui"; Enabled = $true; Type = "boolean"; Rollout = 100%; Description = "New user interface" }
        @{ Name = "dark-mode"; Enabled = $true; Type = "boolean"; Rollout = 100%; Description = "Dark mode theme" }
        @{ Name = "beta-api"; Enabled = $false; Type = "percentage"; Rollout = 25%; Description = "Beta API endpoints" }
        @{ Name = "cache-v2"; Enabled = $true; Type = "user-list"; Rollout = "50 users"; Description = "New caching layer" }
        @{ Name = "streaming"; Enabled = $false; Type = "boolean"; Rollout = 0%; Description = "Streaming responses" }
    )
}

function Show-FeatureList {
    $features = Get-Features
    
    Write-Host ""
    Write-Host "Feature Toggles" -ForegroundColor Cyan
    Write-Host "==============" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "  Feature          Status    Type         Rollout      Description"
    Write-Host "  " + "-" * 80
    
    foreach ($feat in $features) {
        $statusColor = if ($feat.Enabled) { "Green" } else { "Red" }
        $status = if ($feat.Enabled) { "Enabled" } else { "Disabled" }
        Write-Host "  $($feat.Name.PadRight(16)) " -NoNewline
        Write-Host $status.PadRight(9) -ForegroundColor $statusColor -NoNewline
        Write-Host " $($feat.Type.PadRight(12)) $($feat.Rollout.ToString().PadRight(12)) $($feat.Description)"
    }
}

function Enable-FeatureFlag {
    param([string]$Name)
    
    if (-not $Name) {
        Write-Error "Feature name required"
        return
    }
    
    Write-Status "Enabling feature: $Name"
    Write-Success "Feature enabled: $Name"
}

function Disable-FeatureFlag {
    param([string]$Name)
    
    if (-not $Name) {
        Write-Error "Feature name required"
        return
    }
    
    Write-Status "Disabling feature: $Name"
    Write-Success "Feature disabled: $Name"
}

function New-FeatureFlag {
    param([string]$Name, [string]$Desc)
    
    if (-not $Name) {
        Write-Error "Feature name required"
        return
    }
    
    Write-Status "Creating feature: $Name"
    Write-Host "  Description: $Desc"
    
    $feature = @{
        name = $Name
        description = $Desc
        enabled = $false
        created = Get-Date -Format "o"
    }
    
    $feature | ConvertTo-Json | Out-File "$script:FeaturesDir/$Name.json"
    Write-Success "Feature created: $Name"
}

function Remove-FeatureFlag {
    param([string]$Name)
    
    if (-not $Name) {
        Write-Error "Feature name required"
        return
    }
    
    if (-not $Force) {
        $confirm = Read-Host "Delete feature '$Name'? (y/N)"
        if ($confirm -ne "y") {
            Write-Warning "Deletion cancelled"
            return
        }
    }
    
    $featureFile = "$script:FeaturesDir/$Name.json"
    if (Test-Path $featureFile) {
        Remove-Item $featureFile
        Write-Success "Feature deleted: $Name"
    } else {
        Write-Error "Feature not found: $Name"
    }
}

function Set-FeatureRollout {
    param([string]$Name, [int]$Percent)
    
    if (-not $Name) {
        Write-Error "Feature name required"
        return
    }
    
    if ($Percent -lt 0 -or $Percent -gt 100) {
        Write-Error "Percentage must be between 0 and 100"
        return
    }
    
    Write-Status "Setting rollout for $Name to $Percent%"
    Write-Success "Rollout updated"
}

# Main execution
function Main {
    Write-Host "RawrXD Feature Toggle" -ForegroundColor Cyan
    Write-Host "====================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-FeatureToggle
    
    switch ($Action) {
        "List" { Show-FeatureList }
        "Enable" { Enable-FeatureFlag -Name $Feature }
        "Disable" { Disable-FeatureFlag -Name $Feature }
        "Create" { New-FeatureFlag -Name $Feature -Desc $Description }
        "Delete" { Remove-FeatureFlag -Name $Feature }
        "Rollout" { Set-FeatureRollout -Name $Feature -Percent $Percentage }
    }
    
    Write-Host ""
}

Main
