# RawrXD Plugin Manager
# Manages plugins and extensions

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("List", "Install", "Uninstall", "Enable", "Disable", "Update", "Search", "Info")]
    [string]$Action = "List",
    
    [string]$PluginName = "",
    [string]$Source = "",
    [string]$Version = "latest",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$script:PluginDir = "plugins"
$script:PluginRegistry = "$script:PluginDir/registry.json"
$script:PluginRepo = "https://plugins.rawrxd.io"

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

function Initialize-PluginManager {
    if (-not (Test-Path $script:PluginDir)) {
        New-Item -ItemType Directory -Path $script:PluginDir -Force | Out-Null
    }
    
    if (-not (Test-Path $script:PluginRegistry)) {
        @{} | ConvertTo-Json | Out-File $script:PluginRegistry
    }
    
    Write-Status "Plugin Manager initialized"
}

function Get-PluginRegistry {
    if (Test-Path $script:PluginRegistry) {
        return Get-Content $script:PluginRegistry | ConvertFrom-Json
    }
    return @{}
}

function Save-PluginRegistry {
    param([hashtable]$Registry)
    $Registry | ConvertTo-Json -Depth 5 | Out-File $script:PluginRegistry
}

function Get-InstalledPlugins {
    $registry = Get-PluginRegistry
    return $registry
}

function Show-PluginList {
    $plugins = Get-InstalledPlugins
    
    Write-Host ""
    Write-Host "Installed Plugins" -ForegroundColor Cyan
    Write-Host "=================" -ForegroundColor Cyan
    
    if ($plugins.Count -eq 0) {
        Write-Warning "No plugins installed"
        return
    }
    
    foreach ($plugin in $plugins.PSObject.Properties) {
        $info = $plugin.Value
        $status = if ($info.enabled) { "Enabled" } else { "Disabled" }
        $statusColor = if ($info.enabled) { "Green" } else { "Yellow" }
        
        Write-Host "  $($plugin.Name)" -ForegroundColor Cyan
        Write-Host "    Version: $($info.version)"
        Write-Host "    Status: $status" -ForegroundColor $statusColor
        Write-Host "    Path: $($info.path)"
        if ($info.description) {
            Write-Host "    Description: $($info.description)"
        }
        Write-Host ""
    }
}

function Search-Plugins {
    param([string]$Query)
    
    Write-Status "Searching for plugins: $Query"
    
    try {
        $url = "$script:PluginRepo/search?q=$Query"
        $results = Invoke-RestMethod -Uri $url -Method Get
        
        Write-Host ""
        Write-Host "Search Results" -ForegroundColor Cyan
        Write-Host "==============" -ForegroundColor Cyan
        
        foreach ($plugin in $results) {
            Write-Host "  $($plugin.name)" -ForegroundColor Cyan
            Write-Host "    Description: $($plugin.description)"
            Write-Host "    Author: $($plugin.author)"
            Write-Host "    Version: $($plugin.version)"
            Write-Host "    Downloads: $($plugin.downloads)"
            Write-Host ""
        }
    }
    catch {
        Write-Error "Search failed: $_"
    }
}

function Get-PluginInfo {
    param([string]$Name)
    
    $plugins = Get-InstalledPlugins
    
    if (-not $plugins.$Name) {
        Write-Error "Plugin not found: $Name"
        return
    }
    
    $info = $plugins.$Name
    
    Write-Host ""
    Write-Host "Plugin Information: $Name" -ForegroundColor Cyan
    Write-Host "==========================" -ForegroundColor Cyan
    Write-Host "Name: $Name"
    Write-Host "Version: $($info.version)"
    Write-Host "Enabled: $($info.enabled)"
    Write-Host "Path: $($info.path)"
    Write-Host "Installed: $($info.installedDate)"
    if ($info.description) {
        Write-Host "Description: $($info.description)"
    }
    if ($info.author) {
        Write-Host "Author: $($info.author)"
    }
    if ($info.dependencies) {
        Write-Host "Dependencies: $($info.dependencies -join ', ')"
    }
}

function Install-PluginPackage {
    param([string]$Name, [string]$Source, [string]$Version)
    
    Write-Status "Installing plugin: $Name"
    
    $plugins = Get-InstalledPlugins
    
    if ($plugins.$Name -and -not $Force) {
        Write-Warning "Plugin already installed. Use -Force to reinstall."
        return
    }
    
    try {
        $pluginPath = "$script:PluginDir/$Name"
        
        if (Test-Path $pluginPath) {
            Remove-Item $pluginPath -Recurse -Force
        }
        
        New-Item -ItemType Directory -Path $pluginPath -Force | Out-Null
        
        if ($Source) {
            # Install from local source
            if (Test-Path $Source) {
                Copy-Item -Path "$Source/*" -Destination $pluginPath -Recurse -Force
            } else {
                Write-Error "Source not found: $Source"
                return
            }
        } else {
            # Install from repository
            $url = "$script:PluginRepo/download/$Name/$Version"
            $tempFile = "$env:TEMP/$Name-$Version.zip"
            
            Invoke-WebRequest -Uri $url -OutFile $tempFile
            Expand-Archive -Path $tempFile -DestinationPath $pluginPath -Force
            Remove-Item $tempFile -Force
        }
        
        # Read plugin manifest
        $manifestPath = "$pluginPath/plugin.json"
        $manifest = @{}
        if (Test-Path $manifestPath) {
            $manifest = Get-Content $manifestPath | ConvertFrom-Json
        }
        
        # Update registry
        $plugins.$Name = @{
            version = $manifest.version -or $Version
            enabled = $true
            path = $pluginPath
            installedDate = Get-Date -Format "o"
            description = $manifest.description
            author = $manifest.author
            dependencies = $manifest.dependencies
        }
        
        Save-PluginRegistry -Registry $plugins
        Write-Success "Plugin installed: $Name"
    }
    catch {
        Write-Error "Installation failed: $_"
    }
}

function Uninstall-PluginPackage {
    param([string]$Name)
    
    Write-Status "Uninstalling plugin: $Name"
    
    $plugins = Get-InstalledPlugins
    
    if (-not $plugins.$Name) {
        Write-Error "Plugin not found: $Name"
        return
    }
    
    try {
        $pluginPath = $plugins.$Name.path
        
        if (Test-Path $pluginPath) {
            Remove-Item $pluginPath -Recurse -Force
        }
        
        $plugins.PSObject.Properties.Remove($Name)
        Save-PluginRegistry -Registry $plugins
        
        Write-Success "Plugin uninstalled: $Name"
    }
    catch {
        Write-Error "Uninstallation failed: $_"
    }
}

function Set-PluginState {
    param([string]$Name, [bool]$Enabled)
    
    $plugins = Get-InstalledPlugins
    
    if (-not $plugins.$Name) {
        Write-Error "Plugin not found: $Name"
        return
    }
    
    $plugins.$Name.enabled = $Enabled
    Save-PluginRegistry -Registry $plugins
    
    $action = if ($Enabled) { "enabled" } else { "disabled" }
    Write-Success "Plugin $action: $Name"
}

function Update-AllPlugins {
    Write-Status "Checking for plugin updates..."
    
    $plugins = Get-InstalledPlugins
    $updated = 0
    
    foreach ($plugin in $plugins.PSObject.Properties) {
        $name = $plugin.Name
        $currentVersion = $plugin.Value.version
        
        try {
            $url = "$script:PluginRepo/info/$name"
            $info = Invoke-RestMethod -Uri $url -Method Get
            
            if ([version]$info.version -gt [version]$currentVersion) {
                Write-Status "Updating $name from $currentVersion to $($info.version)"
                Install-PluginPackage -Name $name -Version $info.version -Force
                $updated++
            }
        }
        catch {
            Write-Warning "Could not check updates for $name"
        }
    }
    
    if ($updated -eq 0) {
        Write-Success "All plugins are up to date"
    } else {
        Write-Success "Updated $updated plugin(s)"
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Plugin Manager" -ForegroundColor Cyan
    Write-Host "===================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-PluginManager
    
    switch ($Action) {
        "List" { Show-PluginList }
        "Search" { Search-Plugins -Query $PluginName }
        "Info" { Get-PluginInfo -Name $PluginName }
        "Install" { Install-PluginPackage -Name $PluginName -Source $Source -Version $Version }
        "Uninstall" { Uninstall-PluginPackage -Name $PluginName }
        "Enable" { Set-PluginState -Name $PluginName -Enabled $true }
        "Disable" { Set-PluginState -Name $PluginName -Enabled $false }
        "Update" { Update-AllPlugins }
    }
    
    Write-Host ""
}

Main
