# RawrXD Multi-Environment Config Manager
# Manages configuration across multiple environments
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [ValidateSet("List", "Compare", "Sync", "Validate", "Promote")]
    [string]$Action = "List",
    
    [Parameter()]
    [string]$ConfigKey,
    
    [Parameter()]
    [string]$SourceEnv = "dev",
    
    [Parameter()]
    [string]$TargetEnv = "staging",
    
    [Parameter()]
    [string]$Value,
    
    [Parameter()]
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

function Get-ConfigStore {
    $path = "$PSScriptRoot\.multi-env-config.json"
    if (Test-Path $path) {
        return Get-Content $path | ConvertFrom-Json
    }
    return @{
        Environments = @{
            dev = @{ Config = @{}; LastUpdated = $null }
            staging = @{ Config = @{}; LastUpdated = $null }
            production = @{ Config = @{}; LastUpdated = $null }
        }
        History = @()
    }
}

function Save-ConfigStore {
    param([hashtable]$Data)
    $Data | ConvertTo-Json -Depth 10 | Set-Content "$PSScriptRoot\.multi-env-config.json"
}

function Initialize-DefaultConfig {
    $store = Get-ConfigStore
    
    $defaultConfig = @{
        DatabaseConnection = "server={ENV}-db;database=rawrxd"
        ApiEndpoint = "https://api.{ENV}.rawrxd.local"
        LogLevel = "Info"
        FeatureFlags = @{ NewUI = $false; BetaAPI = $false }
        CacheTTL = 300
        MaxConnections = 100
    }
    
    foreach ($env in $store.Environments.PSObject.Properties.Name) {
        $envConfig = @{}
        foreach ($key in $defaultConfig.Keys) {
            $envValue = $defaultConfig[$key] -replace "{ENV}", $env
            $envConfig[$key] = $envValue
        }
        
        # Environment-specific overrides
        if ($env -eq "dev") {
            $envConfig.LogLevel = "Debug"
            $envConfig.FeatureFlags.NewUI = $true
        }
        if ($env -eq "production") {
            $envConfig.LogLevel = "Warning"
            $envConfig.MaxConnections = 500
        }
        
        $store.Environments.$env.Config = $envConfig
        $store.Environments.$env.LastUpdated = (Get-Date).ToString("o")
    }
    
    Save-ConfigStore -Data $store
}

function Show-ConfigList {
    $store = Get-ConfigStore
    
    # Initialize if empty
    if (-not $store.Environments.dev.LastUpdated) {
        Initialize-DefaultConfig
        $store = Get-ConfigStore
    }
    
    Write-Host "`n🌍 Multi-Environment Configuration" -ForegroundColor Cyan
    Write-Host "==================================" -ForegroundColor Cyan
    Write-Host ""
    
    $envs = @("dev", "staging", "production")
    $configKeys = $store.Environments.dev.Config.PSObject.Properties.Name
    
    Write-Host "Configuration Values by Environment" -ForegroundColor Yellow
    Write-Host "===================================" -ForegroundColor Yellow
    Write-Host ""
    
    foreach ($key in $configKeys) {
        Write-Host "$key:" -ForegroundColor Yellow
        foreach ($env in $envs) {
            $value = $store.Environments.$env.Config.$key
            if ($value -is [PSCustomObject]) {
                $value = ($value.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ", "
            }
            Write-Host "  $env`: $value"
        }
        Write-Host ""
    }
}

function Compare-Environments {
    $store = Get-ConfigStore
    
    if (-not $store.Environments.$SourceEnv -or -not $store.Environments.$TargetEnv) {
        throw "Invalid environment specified"
    }
    
    Write-Host "`n🔍 Comparing: $SourceEnv vs $TargetEnv" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host ""
    
    $sourceConfig = $store.Environments.$SourceEnv.Config
    $targetConfig = $store.Environments.$TargetEnv.Config
    
    $differences = @()
    
    foreach ($key in $sourceConfig.PSObject.Properties.Name) {
        $sourceValue = $sourceConfig.$key
        $targetValue = $targetConfig.$key
        
        if ($sourceValue -ne $targetValue) {
            $differences += @{
                Key = $key
                SourceValue = $sourceValue
                TargetValue = $targetValue
            }
        }
    }
    
    if ($differences.Count -eq 0) {
        Write-Success "No differences found between $SourceEnv and $TargetEnv"
    } else {
        Write-Warning "Found $($differences.Count) difference(s):"
        Write-Host ""
        Write-Host "Key                  $SourceEnv".PadRight(30) "$TargetEnv"
        Write-Host "---                  $("-" * $SourceEnv.Length)".PadRight(30) "$("-" * $TargetEnv.Length)"
        
        foreach ($diff in $differences) {
            Write-Host ($diff.Key).PadRight(21) -NoNewline
            Write-Host ($diff.SourceValue.ToString()).PadRight(30) -NoNewline
            Write-Host $diff.TargetValue.ToString()
        }
    }
    Write-Host ""
}

function Sync-Configuration {
    if (-not $ConfigKey) {
        throw "ConfigKey parameter required for Sync action"
    }
    
    $store = Get-ConfigStore
    
    Write-Host "`n🔄 Syncing Configuration" -ForegroundColor Cyan
    Write-Host "========================" -ForegroundColor Cyan
    Write-Host ""
    
    $sourceValue = $store.Environments.$SourceEnv.Config.$ConfigKey
    
    Write-Status "Syncing '$ConfigKey' from $SourceEnv to $TargetEnv"
    Write-Status "Source value: $sourceValue"
    
    if (-not $Force) {
        $confirm = Read-Host "Confirm sync? (yes/no)"
        if ($confirm -ne "yes") {
            Write-Status "Sync cancelled"
            return
        }
    }
    
    $store.Environments.$TargetEnv.Config.$ConfigKey = $sourceValue
    $store.Environments.$TargetEnv.LastUpdated = (Get-Date).ToString("o")
    
    $store.History += @{
        Action = "Sync"
        ConfigKey = $ConfigKey
        From = $SourceEnv
        To = $TargetEnv
        Timestamp = (Get-Date).ToString("o")
        User = $env:USERNAME
    }
    
    Save-ConfigStore -Data $store
    
    Write-Success "Configuration synced successfully!"
}

# Main execution
try {
    switch ($Action) {
        "List" { Show-ConfigList }
        "Compare" { Compare-Environments }
        "Sync" { Sync-Configuration }
        "Validate" { Write-Status "Configuration validation would check for required keys" }
        "Promote" { Sync-Configuration }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
