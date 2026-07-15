# RawrXD Configuration Manager
# Manages configuration files, environment variables, and settings

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Show", "Edit", "Validate", "Backup", "Restore", "Reset", "Migrate")]
    [string]$Action = "Show",
    
    [string]$ConfigFile = "config.json",
    [string]$Key = "",
    [string]$Value = "",
    [string]$BackupPath = "backups/config",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# Default configuration template
$DefaultConfig = @{
    server = @{
        host = "0.0.0.0"
        port = 8080
        workers = 4
        timeout = 300
    }
    models = @{
        path = "models"
        auto_load = $true
        max_memory_gb = 16
    }
    gpu = @{
        enabled = $true
        device = 0
        memory_fraction = 0.8
        cuda_visible_devices = "0"
    }
    logging = @{
        level = "info"
        file = "logs/rawrxd.log"
        max_size_mb = 100
        max_files = 5
    }
    security = @{
        api_key_required = $true
        rate_limit_requests = 100
        rate_limit_window = 60
        max_request_size_mb = 50
    }
    generation = @{
        default_width = 512
        default_height = 512
        default_steps = 20
        max_batch_size = 4
    }
}

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

function Get-ConfigPath {
    $paths = @(
        $ConfigFile,
        "config/$ConfigFile",
        "/etc/rawrxd/$ConfigFile",
        "$env:APPDATA/RawrXD/$ConfigFile",
        "$env:LOCALAPPDATA/RawrXD/$ConfigFile"
    )
    
    foreach ($path in $paths) {
        if (Test-Path $path) {
            return (Resolve-Path $path).Path
        }
    }
    
    # Return default location
    return $ConfigFile
}

function Load-Config {
    $configPath = Get-ConfigPath
    
    if (Test-Path $configPath) {
        try {
            $content = Get-Content $configPath -Raw
            $config = $content | ConvertFrom-Json -AsHashtable
            Write-Success "Configuration loaded from: $configPath"
            return $config
        }
        catch {
            Write-Error "Failed to parse configuration file: $_"
            return $null
        }
    }
    
    Write-Warning "Configuration file not found, using defaults"
    return $DefaultConfig
}

function Save-Config {
    param([hashtable]$Config)
    
    $configPath = Get-ConfigPath
    
    # Ensure directory exists
    $configDir = Split-Path $configPath -Parent
    if ($configDir -and -not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }
    
    try {
        $Config | ConvertTo-Json -Depth 10 | Out-File $configPath -Encoding UTF8
        Write-Success "Configuration saved to: $configPath"
    }
    catch {
        Write-Error "Failed to save configuration: $_"
    }
}

function Show-Config {
    $config = Load-Config
    
    if (-not $config) {
        return
    }
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Current Configuration" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($Key) {
        # Show specific key
        $keys = $Key.Split('.')
        $value = $config
        
        foreach ($k in $keys) {
            if ($value -is [hashtable] -and $value.ContainsKey($k)) {
                $value = $value[$k]
            } else {
                Write-Error "Key not found: $Key"
                return
            }
        }
        
        Write-Host "$Key = $($value | ConvertTo-Json -Compress)" -ForegroundColor White
    } else {
        # Show all configuration
        $config | ConvertTo-Json -Depth 10 | Write-Host
    }
    
    Write-Host ""
}

function Edit-Config {
    if (-not $Key) {
        Write-Error "Key parameter required for edit operation"
        return
    }
    
    if (-not $Value -and $Value -ne "") {
        Write-Error "Value parameter required for edit operation"
        return
    }
    
    $config = Load-Config
    
    if (-not $config) {
        return
    }
    
    # Navigate to the key
    $keys = $Key.Split('.')
    $current = $config
    
    for ($i = 0; $i -lt $keys.Count - 1; $i++) {
        $k = $keys[$i]
        if (-not $current.ContainsKey($k)) {
            $current[$k] = @{}
        }
        $current = $current[$k]
    }
    
    $lastKey = $keys[-1]
    
    # Try to parse value as JSON
    try {
        $parsedValue = $Value | ConvertFrom-Json
    }
    catch {
        $parsedValue = $Value
    }
    
    $current[$lastKey] = $parsedValue
    
    Save-Config $config
    Write-Success "Configuration updated: $Key = $Value"
}

function Test-Config {
    $config = Load-Config
    
    if (-not $config) {
        return
    }
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Configuration Validation" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    $issues = @()
    
    # Check required sections
    $requiredSections = @("server", "models", "logging")
    foreach ($section in $requiredSections) {
        if (-not $config.ContainsKey($section)) {
            $issues += "Missing required section: $section"
        }
    }
    
    # Validate server settings
    if ($config.server) {
        if ($config.server.port -lt 1 -or $config.server.port -gt 65535) {
            $issues += "Invalid server port: $($config.server.port)"
        }
    }
    
    # Validate paths
    if ($config.models -and $config.models.path) {
        if (-not (Test-Path $config.models.path)) {
            $issues += "Models path does not exist: $($config.models.path)"
        }
    }
    
    if ($config.logging -and $config.logging.file) {
        $logDir = Split-Path $config.logging.file -Parent
        if ($logDir -and -not (Test-Path $logDir)) {
            $issues += "Log directory does not exist: $logDir"
        }
    }
    
    # Validate GPU settings
    if ($config.gpu -and $config.gpu.enabled) {
        if ($config.gpu.memory_fraction -lt 0 -or $config.gpu.memory_fraction -gt 1) {
            $issues += "Invalid GPU memory fraction: $($config.gpu.memory_fraction)"
        }
    }
    
    if ($issues.Count -eq 0) {
        Write-Success "Configuration is valid"
    } else {
        Write-Warning "Configuration issues found:"
        foreach ($issue in $issues) {
            Write-Host "  ! $issue" -ForegroundColor Yellow
        }
    }
    
    Write-Host ""
}

function Backup-Config {
    $config = Load-Config
    
    if (-not $config) {
        return
    }
    
    if (-not (Test-Path $BackupPath)) {
        New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backupFile = "$BackupPath/config-backup-$timestamp.json"
    
    $config | ConvertTo-Json -Depth 10 | Out-File $backupFile
    
    Write-Success "Configuration backed up to: $backupFile"
}

function Restore-Config {
    if (-not $Key) {
        # List available backups
        if (-not (Test-Path $BackupPath)) {
            Write-Error "No backups found"
            return
        }
        
        $backups = Get-ChildItem $BackupPath -Filter "config-backup-*.json" | Sort-Object Name -Descending
        
        if ($backups.Count -eq 0) {
            Write-Error "No backups found"
            return
        }
        
        Write-Host "`nAvailable backups:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $backups.Count; $i++) {
            Write-Host "  [$i] $($backups[$i].Name)" -ForegroundColor White
        }
        
        $selection = Read-Host "`nSelect backup to restore (0-$($backups.Count - 1))"
        $backupFile = $backups[$selection].FullName
    } else {
        $backupFile = $Key
    }
    
    if (-not (Test-Path $backupFile)) {
        Write-Error "Backup file not found: $backupFile"
        return
    }
    
    if (-not $Force) {
        $confirm = Read-Host "This will overwrite current configuration. Continue? (y/N)"
        if ($confirm -ne "y") {
            Write-Status "Restore cancelled"
            return
        }
    }
    
    try {
        $config = Get-Content $backupFile -Raw | ConvertFrom-Json -AsHashtable
        Save-Config $config
        Write-Success "Configuration restored from: $backupFile"
    }
    catch {
        Write-Error "Failed to restore configuration: $_"
    }
}

function Reset-Config {
    if (-not $Force) {
        $confirm = Read-Host "This will reset configuration to defaults. Continue? (y/N)"
        if ($confirm -ne "y") {
            Write-Status "Reset cancelled"
            return
        }
    }
    
    Save-Config $DefaultConfig
    Write-Success "Configuration reset to defaults"
}

# Main execution
function Main {
    Write-Host "RawrXD Configuration Manager" -ForegroundColor Cyan
    Write-Host "============================" -ForegroundColor Cyan
    Write-Host ""
    
    switch ($Action) {
        "Show" { Show-Config }
        "Edit" { Edit-Config }
        "Validate" { Test-Config }
        "Backup" { Backup-Config }
        "Restore" { Restore-Config }
        "Reset" { Reset-Config }
    }
    
    Write-Host ""
}

Main
