# RawrXD Environment Manager
# Manages different deployment environments (dev, staging, prod)

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("List", "Create", "Switch", "Delete", "Compare", "Sync")]
    [string]$Action = "List",
    
    [string]$Environment = "",
    [string]$SourceEnv = "",
    [string]$ConfigPath = "config/environments",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$script:CurrentEnvFile = ".rawrxd-env"
$script:DefaultEnvironments = @("development", "staging", "production")

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

function Initialize-EnvManager {
    Write-Status "Environment Manager initialized"
    Write-Status "Action: $Action"
    
    # Ensure environments directory exists
    if (-not (Test-Path $ConfigPath)) {
        New-Item -ItemType Directory -Path $ConfigPath -Force | Out-Null
        Write-Status "Created environments directory: $ConfigPath"
        
        # Create default environments
        foreach ($env in $script:DefaultEnvironments) {
            Create-DefaultEnvironment -Name $env
        }
    }
}

function Get-CurrentEnvironment {
    if (Test-Path $script:CurrentEnvFile) {
        return Get-Content $script:CurrentEnvFile
    }
    return "development"
}

function Set-CurrentEnvironment {
    param([string]$Name)
    $Name | Out-File $script:CurrentEnvFile
    $env:RAWRXD_ENV = $Name
}

function Create-DefaultEnvironment {
    param([string]$Name)
    
    $envPath = "$ConfigPath/$Name.json"
    
    $config = switch ($Name) {
        "development" {
            @{
                name = "development"
                debug = $true
                logLevel = "debug"
                hotReload = $true
                profiling = $true
                apiUrl = "http://localhost:8080"
                database = @{
                    type = "sqlite"
                    path = "data/dev.db"
                }
                features = @{
                    experimental = $true
                    betaFeatures = $true
                }
            }
        }
        "staging" {
            @{
                name = "staging"
                debug = $false
                logLevel = "info"
                hotReload = $false
                profiling = $true
                apiUrl = "https://staging.api.rawrxd.io"
                database = @{
                    type = "postgresql"
                    host = "staging.db.rawrxd.io"
                    port = 5432
                }
                features = @{
                    experimental = $true
                    betaFeatures = $true
                }
            }
        }
        "production" {
            @{
                name = "production"
                debug = $false
                logLevel = "warn"
                hotReload = $false
                profiling = $false
                apiUrl = "https://api.rawrxd.io"
                database = @{
                    type = "postgresql"
                    host = "prod.db.rawrxd.io"
                    port = 5432
                }
                features = @{
                    experimental = $false
                    betaFeatures = $false
                }
            }
        }
    }
    
    $config | ConvertTo-Json -Depth 5 | Out-File $envPath
    Write-Status "Created default environment: $Name"
}

function New-Environment {
    if (-not $Environment) {
        $Environment = Read-Host "Enter environment name"
    }
    
    $envPath = "$ConfigPath/$Environment.json"
    
    if (Test-Path $envPath) {
        Write-Error "Environment '$Environment' already exists"
        return
    }
    
    Write-Status "Creating environment: $Environment"
    
    # Start with development template
    $templatePath = "$ConfigPath/development.json"
    $config = Get-Content $templatePath | ConvertFrom-Json
    $config.name = $Environment
    $config.created = Get-Date -Format "o"
    
    $config | ConvertTo-Json -Depth 5 | Out-File $envPath
    Write-Success "Environment '$Environment' created"
}

function Switch-Environment {
    if (-not $Environment) {
        $Environment = Read-Host "Enter environment name"
    }
    
    $envPath = "$ConfigPath/$Environment.json"
    
    if (-not (Test-Path $envPath)) {
        Write-Error "Environment '$Environment' not found"
        return
    }
    
    Write-Status "Switching to environment: $Environment"
    
    Set-CurrentEnvironment -Name $Environment
    
    # Load and apply environment config
    $config = Get-Content $envPath | ConvertFrom-Json
    
    # Set environment variables
    $env:RAWRXD_ENV = $Environment
    $env:RAWRXD_DEBUG = $config.debug
    $env:RAWRXD_LOG_LEVEL = $config.logLevel
    $env:RAWRXD_API_URL = $config.apiUrl
    
    Write-Success "Switched to environment: $Environment"
    Write-Status "Debug: $($config.debug)"
    Write-Status "Log Level: $($config.logLevel)"
    Write-Status "API URL: $($config.apiUrl)"
}

function Get-Environments {
    Write-Host ""
    Write-Host "Available Environments" -ForegroundColor Cyan
    Write-Host "======================" -ForegroundColor Cyan
    
    $current = Get-CurrentEnvironment
    $envFiles = Get-ChildItem -Path $ConfigPath -Filter "*.json"
    
    if ($envFiles.Count -eq 0) {
        Write-Warning "No environments found"
        return
    }
    
    foreach ($file in $envFiles) {
        $envName = $file.BaseName
        $isCurrent = ($envName -eq $current)
        $marker = if ($isCurrent) { "* " } else { "  " }
        $color = if ($isCurrent) { "Green" } else { "White" }
        
        $config = Get-Content $file.FullName | ConvertFrom-Json
        
        Write-Host "$marker$envName" -ForegroundColor $color
        Write-Host "    Debug: $($config.debug)"
        Write-Host "    Log Level: $($config.logLevel)"
        Write-Host "    API URL: $($config.apiUrl)"
    }
    
    Write-Host ""
    Write-Host "Current: $current" -ForegroundColor Green
}

function Remove-Environment {
    if (-not $Environment) {
        $Environment = Read-Host "Enter environment name to delete"
    }
    
    $envPath = "$ConfigPath/$Environment.json"
    
    if (-not (Test-Path $envPath)) {
        Write-Error "Environment '$Environment' not found"
        return
    }
    
    # Check if current environment
    $current = Get-CurrentEnvironment
    if ($current -eq $Environment) {
        Write-Warning "Cannot delete current environment. Switch to another environment first."
        return
    }
    
    # Check if default environment
    if ($Environment -in $script:DefaultEnvironments -and -not $Force) {
        Write-Error "Cannot delete default environment '$Environment'. Use -Force to override."
        return
    }
    
    if (-not $Force) {
        $confirm = Read-Host "Are you sure you want to delete '$Environment'? (yes/no)"
        if ($confirm -ne "yes") {
            Write-Status "Deletion cancelled"
            return
        }
    }
    
    Remove-Item $envPath
    Write-Success "Environment '$Environment' deleted"
}

function Compare-Environments {
    if (-not $Environment -or -not $SourceEnv) {
        Write-Error "Both Environment and SourceEnv parameters required"
        return
    }
    
    $env1Path = "$ConfigPath/$Environment.json"
    $env2Path = "$ConfigPath/$SourceEnv.json"
    
    if (-not (Test-Path $env1Path) -or -not (Test-Path $env2Path)) {
        Write-Error "One or both environments not found"
        return
    }
    
    $env1 = Get-Content $env1Path | ConvertFrom-Json
    $env2 = Get-Content $env2Path | ConvertFrom-Json
    
    Write-Host ""
    Write-Host "Comparing: $SourceEnv vs $Environment" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    
    # Compare key properties
    $properties = @("debug", "logLevel", "hotReload", "profiling", "apiUrl")
    
    foreach ($prop in $properties) {
        $val1 = $env1.$prop
        $val2 = $env2.$prop
        $color = if ($val1 -eq $val2) { "White" } else { "Yellow" }
        
        Write-Host "$prop`:" -ForegroundColor $color
        Write-Host "  $SourceEnv`: $val1"
        Write-Host "  $Environment`: $val2"
    }
}

function Sync-Environment {
    if (-not $Environment -or -not $SourceEnv) {
        Write-Error "Both Environment and SourceEnv parameters required"
        return
    }
    
    $sourcePath = "$ConfigPath/$SourceEnv.json"
    $targetPath = "$ConfigPath/$Environment.json"
    
    if (-not (Test-Path $sourcePath)) {
        Write-Error "Source environment not found: $SourceEnv"
        return
    }
    
    Write-Status "Syncing $SourceEnv -> $Environment"
    
    $source = Get-Content $sourcePath | ConvertFrom-Json
    $source.name = $Environment
    $source.syncedFrom = $SourceEnv
    $source.syncedAt = Get-Date -Format "o"
    
    $source | ConvertTo-Json -Depth 5 | Out-File $targetPath
    Write-Success "Environment '$Environment' synced from '$SourceEnv'"
}

# Main execution
function Main {
    Write-Host "RawrXD Environment Manager" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-EnvManager
    
    switch ($Action) {
        "List" { Get-Environments }
        "Create" { New-Environment }
        "Switch" { Switch-Environment }
        "Delete" { Remove-Environment }
        "Compare" { Compare-Environments }
        "Sync" { Sync-Environment }
    }
    
    Write-Host ""
}

Main
