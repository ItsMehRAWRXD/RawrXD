# RawrXD Environment Manager
# Manages environment configurations and promotions

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Create", "Update", "Promote", "Clone", "Delete", "List")]
    [string]$Action,
    
    [string]$EnvironmentName,
    [string]$SourceEnvironment,
    [string]$TargetEnvironment,
    [hashtable]$Configuration = @{}
)

$ErrorActionPreference = "Stop"

# Environment registry
$script:EnvironmentRegistryPath = "deployment/environments/registry.json"
$script:DefaultConfig = @{
    base_path = "C:\\RawrXD"
    log_level = "info"
    backup_enabled = $true
    monitoring_enabled = $true
    health_check_interval = 30
    auto_rollback = $true
}

function Initialize-EnvironmentRegistry {
    if (-not (Test-Path $script:EnvironmentRegistryPath)) {
        $registry = @{
            environments = @{}
            created_at = Get-Date -Format "o"
            version = "1.0.0"
        }
        
        $dir = Split-Path $script:EnvironmentRegistryPath -Parent
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        
        $registry | ConvertTo-Json -Depth 10 | Out-File $script:EnvironmentRegistryPath
    }
}

function Get-EnvironmentRegistry {
    Initialize-EnvironmentRegistry
    return Get-Content $script:EnvironmentRegistryPath | ConvertFrom-Json
}

function Save-EnvironmentRegistry {
    param([PSCustomObject]$Registry)
    
    $Registry | ConvertTo-Json -Depth 10 | Out-File $script:EnvironmentRegistryPath
}

function New-Environment {
    param([string]$Name, [hashtable]$Config)
    
    Write-Host "Creating environment: $Name" -ForegroundColor Cyan
    
    $registry = Get-EnvironmentRegistry
    
    if ($registry.environments.$Name) {
        throw "Environment already exists: $Name"
    }
    
    # Merge with defaults
    $mergedConfig = $script:DefaultConfig.Clone()
    foreach ($key in $Config.Keys) {
        $mergedConfig[$key] = $Config[$key]
    }
    
    # Create environment path
    $envPath = Join-Path $mergedConfig.base_path $Name
    if (-not (Test-Path $envPath)) {
        New-Item -ItemType Directory -Path $envPath -Force | Out-Null
    }
    
    # Create subdirectories
    @("logs", "backups", "config") | ForEach-Object {
        $subPath = Join-Path $envPath $_
        if (-not (Test-Path $subPath)) {
            New-Item -ItemType Directory -Path $subPath -Force | Out-Null
        }
    }
    
    # Create environment config
    $envConfig = @{
        name = $Name
        path = $envPath
        config = $mergedConfig
        created_at = Get-Date -Format "o"
        updated_at = Get-Date -Format "o"
        status = "active"
    }
    
    $registry.environments | Add-Member -NotePropertyName $Name -NotePropertyValue $envConfig -Force
    Save-EnvironmentRegistry -Registry $registry
    
    Write-Host "  ✓ Environment created: $envPath" -ForegroundColor Green
    return $envConfig
}

function Update-Environment {
    param([string]$Name, [hashtable]$Config)
    
    Write-Host "Updating environment: $Name" -ForegroundColor Cyan
    
    $registry = Get-EnvironmentRegistry
    
    if (-not $registry.environments.$Name) {
        throw "Environment not found: $Name"
    }
    
    $envConfig = $registry.environments.$Name
    
    # Update configuration
    foreach ($key in $Config.Keys) {
        $envConfig.config.$key = $Config[$key]
    }
    
    $envConfig.updated_at = Get-Date -Format "o"
    
    Save-EnvironmentRegistry -Registry $registry
    
    Write-Host "  ✓ Environment updated" -ForegroundColor Green
    return $envConfig
}

function Invoke-EnvironmentPromotion {
    param([string]$Source, [string]$Target)
    
    Write-Host "Promoting from $Source to $Target" -ForegroundColor Cyan
    
    $registry = Get-EnvironmentRegistry
    
    if (-not $registry.environments.$Source) {
        throw "Source environment not found: $Source"
    }
    
    if (-not $registry.environments.$Target) {
        throw "Target environment not found: $Target"
    }
    
    $sourceConfig = $registry.environments.$Source
    $targetConfig = $registry.environments.$Target
    
    # Validate promotion path
    $validPaths = @(
        @{ From = "dev"; To = "staging" },
        @{ From = "staging"; To = "production" }
    )
    
    $isValid = $validPaths | Where-Object { $_.From -eq $Source -and $_.To -eq $Target }
    if (-not $isValid) {
        throw "Invalid promotion path: $Source -> $Target"
    }
    
    # Run tests on source
    Write-Host "  Running tests on $Source..." -ForegroundColor Gray
    $testResult = Invoke-Pester -Path "tests/smoke" -PassThru -Show None
    if ($testResult.FailedCount -gt 0) {
        throw "Tests failed on $Source - cannot promote"
    }
    
    # Backup target
    Write-Host "  Backing up $Target..." -ForegroundColor Gray
    $backupPath = "disaster-recovery/backups/pre-promotion-$Target-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    & "disaster-recovery/backups/backup_manager.ps1" -BackupType ConfigOnly -BackupPath $backupPath
    
    # Deploy to target
    Write-Host "  Deploying to $Target..." -ForegroundColor Gray
    & "deployment/deployment_orchestrator.ps1" `
        -Strategy BlueGreen `
        -Version (Get-Date -Format "yyyyMMdd-HHmmss") `
        -Environment $Target `
        -SourcePath $sourceConfig.path
    
    # Update registry
    $targetConfig.updated_at = Get-Date -Format "o"
    $targetConfig.promoted_from = $Source
    $targetConfig.promotion_time = Get-Date -Format "o"
    Save-EnvironmentRegistry -Registry $registry
    
    Write-Host "  ✓ Promotion complete" -ForegroundColor Green
}

function Copy-Environment {
    param([string]$Source, [string]$Target)
    
    Write-Host "Cloning environment: $Source -> $Target" -ForegroundColor Cyan
    
    $registry = Get-EnvironmentRegistry
    
    if (-not $registry.environments.$Source) {
        throw "Source environment not found: $Source"
    }
    
    if ($registry.environments.$Target) {
        throw "Target environment already exists: $Target"
    }
    
    $sourceConfig = $registry.environments.$Source
    
    # Create new environment
    $newConfig = $sourceConfig.config.Clone()
    $newConfig.base_path = $script:DefaultConfig.base_path
    
    $newEnv = New-Environment -Name $Target -Config $newConfig
    
    # Copy files
    Write-Host "  Copying files..." -ForegroundColor Gray
    Copy-Item "$($sourceConfig.path)\*" $newEnv.path -Recurse -Force
    
    Write-Host "  ✓ Environment cloned" -ForegroundColor Green
    return $newEnv
}

function Remove-Environment {
    param([string]$Name)
    
    Write-Host "Deleting environment: $Name" -ForegroundColor Cyan
    
    $registry = Get-EnvironmentRegistry
    
    if (-not $registry.environments.$Name) {
        throw "Environment not found: $Name"
    }
    
    $envConfig = $registry.environments.$Name
    
    # Confirm deletion
    $confirmation = Read-Host "Confirm deletion of $Name? This cannot be undone. (yes/no)"
    if ($confirmation -ne "yes") {
        Write-Host "Deletion cancelled" -ForegroundColor Yellow
        return
    }
    
    # Backup before deletion
    Write-Host "  Creating final backup..." -ForegroundColor Gray
    $backupPath = "disaster-recovery/backups/pre-deletion-$Name-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    & "disaster-recovery/backups/backup_manager.ps1" -BackupType Full -BackupPath $backupPath
    
    # Remove files
    if (Test-Path $envConfig.path) {
        Remove-Item $envConfig.path -Recurse -Force
    }
    
    # Remove from registry
    $registry.environments.PSObject.Properties.Remove($Name)
    Save-EnvironmentRegistry -Registry $registry
    
    Write-Host "  ✓ Environment deleted" -ForegroundColor Green
}

function Get-EnvironmentList {
    $registry = Get-EnvironmentRegistry
    
    Write-Host "`nRegistered Environments:" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    
    foreach ($envName in $registry.environments.PSObject.Properties.Name) {
        $env = $registry.environments.$envName
        $statusColor = if ($env.status -eq "active") { "Green" } else { "Yellow" }
        
        Write-Host "`n$envName" -ForegroundColor $statusColor
        Write-Host "  Path: $($env.path)" -ForegroundColor Gray
        Write-Host "  Status: $($env.status)" -ForegroundColor Gray
        Write-Host "  Created: $($env.created_at)" -ForegroundColor Gray
        Write-Host "  Updated: $($env.updated_at)" -ForegroundColor Gray
        
        if ($env.promoted_from) {
            Write-Host "  Promoted from: $($env.promoted_from)" -ForegroundColor Gray
        }
    }
}

# Main execution
function Invoke-EnvironmentManager {
    Write-Host "RawrXD Environment Manager" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host ""
    
    switch ($Action) {
        "Create" {
            if (-not $EnvironmentName) {
                throw "EnvironmentName required for Create action"
            }
            New-Environment -Name $EnvironmentName -Config $Configuration
        }
        "Update" {
            if (-not $EnvironmentName) {
                throw "EnvironmentName required for Update action"
            }
            Update-Environment -Name $EnvironmentName -Config $Configuration
        }
        "Promote" {
            if (-not $SourceEnvironment -or -not $TargetEnvironment) {
                throw "SourceEnvironment and TargetEnvironment required for Promote action"
            }
            Invoke-EnvironmentPromotion -Source $SourceEnvironment -Target $TargetEnvironment
        }
        "Clone" {
            if (-not $SourceEnvironment -or -not $TargetEnvironment) {
                throw "SourceEnvironment and TargetEnvironment required for Clone action"
            }
            Copy-Environment -Source $SourceEnvironment -Target $TargetEnvironment
        }
        "Delete" {
            if (-not $EnvironmentName) {
                throw "EnvironmentName required for Delete action"
            }
            Remove-Environment -Name $EnvironmentName
        }
        "List" {
            Get-EnvironmentList
        }
    }
}

# Run manager
Invoke-EnvironmentManager
