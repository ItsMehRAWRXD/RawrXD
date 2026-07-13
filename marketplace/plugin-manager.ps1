# RawrXD Plugin Manager
# Phase F.1 Batch 5/5: Marketplace Plugin Management
# Usage: .\marketplace\plugin-manager.ps1 [list|install|uninstall|update|search|info] [plugin-id]

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("list", "install", "uninstall", "update", "search", "info", "init")]
    [string]$Action,
    
    [string]$PluginId = "",
    [string]$Category = "",
    [string]$Query = "",
    [switch]$Force,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# Configuration
$PluginStorePath = "$env:USERPROFILE\.rawrxd\plugins"
$RegistryUrl = "https://rawrxd.ai/marketplace/plugin-registry.json"
$InstalledDbPath = "$PluginStorePath\installed.json"

# Colors
$Colors = @{
    Primary = "Cyan"
    Success = "Green"
    Warning = "Yellow"
    Error = "Red"
    Info = "Gray"
}

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Color($Message, $Color = "White") {
    Write-Host $Message -ForegroundColor $Colors[$Color]
}

function Initialize-PluginStore {
    if (-not (Test-Path $PluginStorePath)) {
        New-Item -ItemType Directory -Path $PluginStorePath -Force | Out-Null
        Write-Color "Created plugin store: $PluginStorePath" "Success"
    }
    
    if (-not (Test-Path $InstalledDbPath)) {
        @{
            version = "1.0"
            plugins = @{}
            last_check = $null
        } | ConvertTo-Json -Depth 10 | Set-Content $InstalledDbPath
        Write-Color "Initialized plugin database" "Success"
    }
}

function Get-Registry {
    try {
        $response = Invoke-RestMethod -Uri $RegistryUrl -TimeoutSec 30
        return $response
    } catch {
        # Fallback to local registry for offline mode
        $localRegistry = Join-Path $PSScriptRoot "plugin-registry.json"
        if (Test-Path $localRegistry) {
            return Get-Content $localRegistry | ConvertFrom-Json
        }
        throw "Failed to fetch registry: $_"
    }
}

function Get-InstalledDb {
    return Get-Content $InstalledDbPath | ConvertFrom-Json
}

function Save-InstalledDb($db) {
    $db | ConvertTo-Json -Depth 10 | Set-Content $InstalledDbPath
}

function Format-PluginInfo($plugin, [switch]$Detailed) {
    $output = @"

📦 $($plugin.name) @ $($plugin.version)
   $($plugin.description)
   
"@
    
    if ($Detailed) {
        $output += @"
   ID: $($plugin.id)
   Author: $($plugin.author)
   Category: $($plugin.category)
   License: $($plugin.license)
   Pricing: $($plugin.pricing)
   Downloads: $($plugin.stats.downloads.ToString('N0'))
   Rating: $($plugin.stats.rating)/5.0 ($($plugin.stats.reviews) reviews)
   Min Version: $($plugin.min_rawrxd_version)
   Verified: $(if ($plugin.verified) { "✅" } else { "⚠️" })
   
   Tags: $($plugin.tags -join ", ")
   
   Repository: $($plugin.repository)
"@
    }
    
    return $output
}

function Show-Progress($Activity, $PercentComplete) {
    Write-Progress -Activity $Activity -PercentComplete $PercentComplete
}

# ============================================================================
# Plugin Operations
# ============================================================================

function Get-PluginList {
    param(
        [string]$Category = "",
        [switch]$Installed
    )
    
    $registry = Get-Registry
    $installedDb = Get-InstalledDb
    
    $plugins = $registry.plugins
    
    if ($Category) {
        $plugins = $plugins | Where-Object { $_.category -eq $Category }
    }
    
    if ($Installed) {
        $plugins = $plugins | Where-Object { $installedDb.plugins.ContainsKey($_.id) }
    }
    
    Write-Color "`n📦 Available Plugins ($($plugins.Count) found)" "Primary"
    Write-Color "================================" "Primary"
    
    foreach ($plugin in ($plugins | Sort-Object -Property stats.downloads -Descending)) {
        $isInstalled = $installedDb.plugins.ContainsKey($plugin.id)
        $status = if ($isInstalled) { "[✓]" } else { "[ ]" }
        $featured = if ($plugin.featured) { "⭐" } else { "  " }
        
        Write-Color "$featured $status $($plugin.name) v$($plugin.version) - $($plugin.category)" "Info"
        Write-Color "    $($plugin.description)" "Info"
        Write-Color "    ⭐ $($plugin.stats.rating) | 📥 $($plugin.stats.downloads) downloads" "Info"
        Write-Color ""
    }
}

function Search-Plugins {
    param([string]$Query)
    
    $registry = Get-Registry
    
    $results = $registry.plugins | Where-Object {
        $_.name -like "*$Query*" -or
        $_.description -like "*$Query*" -or
        $_.tags -contains $Query -or
        $_.category -like "*$Query*"
    }
    
    Write-Color "`n🔍 Search Results for '$Query' ($($results.Count) found)" "Primary"
    Write-Color "==========================================" "Primary"
    
    foreach ($plugin in $results) {
        Write-Color (Format-PluginInfo $plugin) "Info"
    }
}

function Get-PluginInfo {
    param([string]$PluginId)
    
    $registry = Get-Registry
    $plugin = $registry.plugins | Where-Object { $_.id -eq $PluginId }
    
    if (-not $plugin) {
        throw "Plugin '$PluginId' not found in registry"
    }
    
    Write-Color (Format-PluginInfo $plugin -Detailed) "Info"
}

function Install-Plugin {
    param(
        [string]$PluginId,
        [switch]$Force
    )
    
    $registry = Get-Registry
    $plugin = $registry.plugins | Where-Object { $_.id -eq $PluginId }
    
    if (-not $plugin) {
        throw "Plugin '$PluginId' not found in registry"
    }
    
    $installedDb = Get-InstalledDb
    
    if ($installedDb.plugins.ContainsKey($PluginId) -and -not $Force) {
        $current = $installedDb.plugins[$PluginId]
        if ($current.version -eq $plugin.version) {
            Write-Color "Plugin '$PluginId' v$($plugin.version) is already installed" "Warning"
            Write-Color "Use -Force to reinstall" "Info"
            return
        }
    }
    
    Write-Color "`n📥 Installing $($plugin.name) v$($plugin.version)..." "Primary"
    
    # Create plugin directory
    $pluginDir = Join-Path $PluginStorePath $PluginId
    if (Test-Path $pluginDir) {
        Remove-Item -Path $pluginDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $pluginDir -Force | Out-Null
    
    # Download plugin
    $downloadPath = Join-Path $pluginDir "plugin.zip"
    
    try {
        Show-Progress -Activity "Downloading $PluginId..." -PercentComplete 0
        Invoke-WebRequest -Uri $plugin.download_url -OutFile $downloadPath
        Show-Progress -Activity "Downloading $PluginId..." -PercentComplete 100
        
        # Extract
        Show-Progress -Activity "Extracting $PluginId..." -PercentComplete 0
        Expand-Archive -Path $downloadPath -DestinationPath $pluginDir -Force
        Remove-Item $downloadPath
        Show-Progress -Activity "Extracting $PluginId..." -PercentComplete 100
        
        # Update database
        $installedDb.plugins[$PluginId] = @{
            id = $plugin.id
            version = $plugin.version
            installed_at = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            path = $pluginDir
            enabled = $true
        }
        
        Save-InstalledDb $installedDb
        
        Write-Color "✅ Successfully installed $($plugin.name) v$($plugin.version)" "Success"
        Write-Color "   Location: $pluginDir" "Info"
        
        # Show post-install instructions
        if (Test-Path (Join-Path $pluginDir "README.md")) {
            Write-Color "   README: $(Join-Path $pluginDir "README.md")" "Info"
        }
        
    } catch {
        throw "Failed to install plugin: $_"
    } finally {
        Write-Progress -Activity "Installing $PluginId" -Completed
    }
}

function Uninstall-Plugin {
    param([string]$PluginId)
    
    $installedDb = Get-InstalledDb
    
    if (-not $installedDb.plugins.ContainsKey($PluginId)) {
        throw "Plugin '$PluginId' is not installed"
    }
    
    $pluginInfo = $installedDb.plugins[$PluginId]
    
    Write-Color "`n🗑️  Uninstalling $PluginId..." "Warning"
    
    # Remove files
    if (Test-Path $pluginInfo.path) {
        Remove-Item -Path $pluginInfo.path -Recurse -Force
    }
    
    # Update database
    $installedDb.plugins.Remove($PluginId)
    Save-InstalledDb $installedDb
    
    Write-Color "✅ Successfully uninstalled $PluginId" "Success"
}

function Update-Plugins {
    $registry = Get-Registry
    $installedDb = Get-InstalledDb
    
    $updates = @()
    
    foreach ($key in $installedDb.plugins.Keys) {
        $installed = $installedDb.plugins[$key]
        $available = $registry.plugins | Where-Object { $_.id -eq $key }
        
        if ($available -and $available.version -ne $installed.version) {
            $updates += @{
                Plugin = $available
                CurrentVersion = $installed.version
            }
        }
    }
    
    if ($updates.Count -eq 0) {
        Write-Color "`n✅ All plugins are up to date" "Success"
        return
    }
    
    Write-Color "`n📦 Available Updates ($($updates.Count))" "Primary"
    Write-Color "========================" "Primary"
    
    foreach ($update in $updates) {
        Write-Color "$($update.Plugin.name): $($update.CurrentVersion) → $($update.Plugin.version)" "Info"
    }
    
    $confirm = Read-Host "`nUpdate all plugins? [Y/n]"
    if ($confirm -eq "Y" -or $confirm -eq "y" -or $confirm -eq "") {
        foreach ($update in $updates) {
            Install-Plugin -PluginId $update.Plugin.id -Force
        }
    }
}

function Show-Categories {
    $registry = Get-Registry
    
    Write-Color "`n📂 Plugin Categories" "Primary"
    Write-Color "===================" "Primary"
    
    foreach ($cat in $registry.categories) {
        $count = ($registry.plugins | Where-Object { $_.category -eq $cat.id }).Count
        Write-Color "  $($cat.name) ($count plugins)" "Info"
        Write-Color "    $($cat.description)" "Info"
    }
}

# ============================================================================
# Main Execution
# ============================================================================

Write-Color "RawrXD Plugin Manager" "Primary"
Write-Color "====================" "Primary"
Write-Color ""

switch ($Action) {
    "init" {
        Initialize-PluginStore
        Write-Color "`n✅ Plugin manager initialized" "Success"
    }
    
    "list" {
        Initialize-PluginStore
        Get-PluginList -Category $Category
    }
    
    "search" {
        Initialize-PluginStore
        if (-not $Query) {
            $Query = Read-Host "Enter search query"
        }
        Search-Plugins -Query $Query
    }
    
    "info" {
        Initialize-PluginStore
        if (-not $PluginId) {
            $PluginId = Read-Host "Enter plugin ID"
        }
        Get-PluginInfo -PluginId $PluginId
    }
    
    "install" {
        Initialize-PluginStore
        if (-not $PluginId) {
            $PluginId = Read-Host "Enter plugin ID to install"
        }
        Install-Plugin -PluginId $PluginId -Force:$Force
    }
    
    "uninstall" {
        Initialize-PluginStore
        if (-not $PluginId) {
            $PluginId = Read-Host "Enter plugin ID to uninstall"
        }
        Uninstall-Plugin -PluginId $PluginId
    }
    
    "update" {
        Initialize-PluginStore
        if ($PluginId) {
            Install-Plugin -PluginId $PluginId -Force
        } else {
            Update-Plugins
        }
    }
}

Write-Color ""
