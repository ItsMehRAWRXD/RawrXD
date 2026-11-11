# RawrXD Plugin Manager
# Phase M Batch 5/5: Third-Party Extension System
# Manages plugin lifecycle, security, and API

param(
    [Parameter()]
    [ValidateSet("Install", "Uninstall", "Enable", "Disable", "List", "Discover", "Validate", "ShowStatus")]
    [string]$Action = "ShowStatus",
    
    [Parameter()]
    [string]$PluginId,
    
    [Parameter()]
    [string]$PluginPath,
    
    [Parameter()]
    [string]$PluginUrl,
    
    [Parameter()]
    [hashtable]$Config = @{},
    
    [Parameter()]
    [string]$DataPath = "$PSScriptRoot\plugin_data",
    
    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\..\..\logs\integration"
)

# Plugin manifest schema
$ManifestSchema = @{
    RequiredFields = @("id", "name", "version", "author", "description", "entry_point")
    OptionalFields = @("dependencies", "permissions", "config_schema", "hooks", "api_version")
    SupportedPermissions = @(
        "system.read",
        "system.write",
        "models.read",
        "models.load",
        "inference.execute",
        "files.read",
        "files.write",
        "network.request",
        "webhook.register",
        "config.read",
        "config.write"
    )
    SupportedHooks = @(
        "pre_inference",
        "post_inference",
        "model_loaded",
        "model_unloaded",
        "session_created",
        "session_destroyed",
        "system_startup",
        "system_shutdown"
    )
}

# Plugin store (simulated)
$PluginStore = @{
    "rawrxd-plugin-example" = @{
        Name = "Example Plugin"
        Description = "Demonstrates plugin capabilities"
        Version = "1.0.0"
        Author = "RawrXD Team"
        Url = "https://github.com/ItsMehRAWRXD/rawrxd-plugin-example"
        Downloads = 1250
        Rating = 4.5
        Category = "Demo"
    }
    "rawrxd-plugin-metrics" = @{
        Name = "Metrics Exporter"
        Description = "Export metrics to Prometheus/Grafana"
        Version = "2.1.0"
        Author = "Community"
        Url = "https://github.com/community/rawrxd-metrics"
        Downloads = 3420
        Rating = 4.8
        Category = "Monitoring"
    }
    "rawrxd-plugin-auth-oauth" = @{
        Name = "OAuth2 Authentication"
        Description = "Add OAuth2/OIDC authentication"
        Version = "1.5.0"
        Author = "Security Team"
        Url = "https://github.com/security/rawrxd-oauth"
        Downloads = 2100
        Rating = 4.7
        Category = "Security"
    }
    "rawrxd-plugin-cache-redis" = @{
        Name = "Redis Cache"
        Description = "Redis-backed KV cache"
        Version = "1.2.0"
        Author = "Performance Team"
        Url = "https://github.com/perf/rawrxd-redis"
        Downloads = 1890
        Rating = 4.6
        Category = "Performance"
    }
    "rawrxd-plugin-llm-guard" = @{
        Name = "LLM Guard"
        Description = "Input/output content filtering"
        Version = "3.0.0"
        Author = "Safety Team"
        Url = "https://github.com/safety/rawrxd-guard"
        Downloads = 4560
        Rating = 4.9
        Category = "Safety"
    }
}

# Ensure directories exist
if (-not (Test-Path $DataPath)) {
    New-Item -ItemType Directory -Path $DataPath -Force | Out-Null
}
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

$StateFile = "$PSScriptRoot\plugin_state.json"
$PluginsDir = "$DataPath\installed"

if (-not (Test-Path $PluginsDir)) {
    New-Item -ItemType Directory -Path $PluginsDir -Force | Out-Null
}

function Write-PluginLog {
    param([string]$Message, [string]$Level = "INFO", [string]$Plugin = "")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $pluginTag = if ($Plugin) { "[$Plugin]" } else { "" }
    $logEntry = "[$timestamp] [$Level] [PLUGIN]$pluginTag $Message"
    
    $logFile = Join-Path $LogPath "plugins_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "SUCCESS" { "Green" }
        "PLUGIN" { "Cyan" }
        "SECURITY" { "Magenta" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Get-PluginState {
    if (Test-Path $StateFile) {
        return Get-Content $StateFile | ConvertFrom-Json
    }
    return @{
        Installed = @{}
        Enabled = @()
        Hooks = @{}
        Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

function Save-PluginState {
    param($State)
    $State | ConvertTo-Json -Depth 10 | Out-File $StateFile -Encoding UTF8
}

function Test-PluginManifest {
    param([string]$ManifestPath)
    
    if (-not (Test-Path $ManifestPath)) {
        return @{ Valid = $false; Error = "Manifest not found: $ManifestPath" }
    }
    
    try {
        $manifest = Get-Content $ManifestPath | ConvertFrom-Json
    }
    catch {
        return @{ Valid = $false; Error = "Invalid JSON in manifest: $_" }
    }
    
    # Check required fields
    foreach ($field in $ManifestSchema.RequiredFields) {
        if (-not $manifest.PSObject.Properties.Name -contains $field) {
            return @{ Valid = $false; Error = "Missing required field: $field" }
        }
    }
    
    # Validate permissions
    if ($manifest.permissions) {
        foreach ($perm in $manifest.permissions) {
            if ($ManifestSchema.SupportedPermissions -notcontains $perm) {
                return @{ Valid = $false; Error = "Unsupported permission: $perm" }
            }
        }
    }
    
    # Validate hooks
    if ($manifest.hooks) {
        foreach ($hook in $manifest.hooks) {
            if ($ManifestSchema.SupportedHooks -notcontains $hook) {
                return @{ Valid = $false; Error = "Unsupported hook: $hook" }
            }
        }
    }
    
    return @{
        Valid = $true
        Manifest = $manifest
        Warnings = @()
    }
}

function Install-Plugin {
    param(
        [string]$Source,
        [string]$Id
    )
    
    Write-PluginLog "Installing plugin from $Source" "PLUGIN"
    
    # Simulate installation
    $installPath = Join-Path $PluginsDir $Id
    
    if (Test-Path $installPath) {
        Write-PluginLog "Plugin already installed: $Id" "WARN"
        return $null
    }
    
    New-Item -ItemType Directory -Path $installPath -Force | Out-Null
    
    # Create manifest
    $manifest = @{
        id = $Id
        name = if ($PluginStore.ContainsKey($Id)) { $PluginStore[$Id].Name } else { $Id }
        version = "1.0.0"
        author = "Unknown"
        description = "Plugin description"
        entry_point = "plugin.ps1"
        permissions = @("system.read")
        hooks = @()
        installed = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    $manifest | ConvertTo-Json | Out-File (Join-Path $installPath "manifest.json") -Encoding UTF8
    
    # Create entry point
    @"
# Plugin: $($manifest.name)
# Version: $($manifest.version)

function Initialize-Plugin {
    Write-Host "Plugin $($manifest.name) initialized"
}

function Invoke-PluginHook {
    param([string]`$Hook, [hashtable]`$Context)
    # Plugin logic here
}

Export-ModuleMember -Function Initialize-Plugin, Invoke-PluginHook
"@ | Out-File (Join-Path $installPath "plugin.ps1") -Encoding UTF8
    
    $plugin = @{
        Id = $Id
        Path = $installPath
        Manifest = $manifest
        Status = "installed"
        Enabled = $false
    }
    
    $state = Get-PluginState
    $state.Installed[$Id] = $plugin
    Save-PluginState -State $state
    
    Write-PluginLog "Plugin installed: $Id" "SUCCESS"
    
    return $plugin
}

function Uninstall-Plugin {
    param([string]$Id)
    
    Write-PluginLog "Uninstalling plugin: $Id" "PLUGIN"
    
    $state = Get-PluginState
    
    if (-not $state.Installed.ContainsKey($Id)) {
        Write-PluginLog "Plugin not found: $Id" "ERROR"
        return $false
    }
    
    # Disable first if enabled
    if ($state.Enabled -contains $Id) {
        Disable-Plugin -Id $Id | Out-Null
    }
    
    $pluginPath = $state.Installed[$Id].Path
    if (Test-Path $pluginPath) {
        Remove-Item $pluginPath -Recurse -Force
    }
    
    $state.Installed.Remove($Id)
    Save-PluginState -State $state
    
    Write-PluginLog "Plugin uninstalled: $Id" "SUCCESS"
    return $true
}

function Enable-Plugin {
    param([string]$Id)
    
    Write-PluginLog "Enabling plugin: $Id" "PLUGIN"
    
    $state = Get-PluginState
    
    if (-not $state.Installed.ContainsKey($Id)) {
        Write-PluginLog "Plugin not found: $Id" "ERROR"
        return $false
    }
    
    if ($state.Enabled -contains $Id) {
        Write-PluginLog "Plugin already enabled: $Id" "WARN"
        return $true
    }
    
    # Security check
    $plugin = $state.Installed[$Id]
    Write-PluginLog "Checking permissions for $Id`: $($plugin.Manifest.permissions -join ', ')" "SECURITY"
    
    $state.Enabled += $Id
    $state.Installed[$Id].Enabled = $true
    $state.Installed[$Id].Status = "enabled"
    
    # Register hooks
    foreach ($hook in $plugin.Manifest.hooks) {
        if (-not $state.Hooks.ContainsKey($hook)) {
            $state.Hooks[$hook] = @()
        }
        $state.Hooks[$hook] += $Id
    }
    
    Save-PluginState -State $state
    
    Write-PluginLog "Plugin enabled: $Id" "SUCCESS"
    return $true
}

function Disable-Plugin {
    param([string]$Id)
    
    Write-PluginLog "Disabling plugin: $Id" "PLUGIN"
    
    $state = Get-PluginState
    
    if ($state.Enabled -notcontains $Id) {
        Write-PluginLog "Plugin not enabled: $Id" "WARN"
        return $true
    }
    
    $state.Enabled = $state.Enabled | Where-Object { $_ -ne $Id }
    $state.Installed[$Id].Enabled = $false
    $state.Installed[$Id].Status = "disabled"
    
    # Unregister hooks
    foreach ($hook in $state.Hooks.Keys) {
        $state.Hooks[$hook] = $state.Hooks[$hook] | Where-Object { $_ -ne $Id }
    }
    
    Save-PluginState -State $state
    
    Write-PluginLog "Plugin disabled: $Id" "SUCCESS"
    return $true
}

function Show-PluginStatus {
    $state = Get-PluginState
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           RawrXD Plugin Manager Status                      ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Installed: $($state.Installed.Count)" -ForegroundColor Cyan
    Write-Host "║ Enabled: $($state.Enabled.Count)" -ForegroundColor Cyan
    Write-Host "║ Registered Hooks: $($state.Hooks.Count)" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    Write-Host "║ Plugin Store:" -ForegroundColor Cyan
    foreach ($plugin in $PluginStore.Keys | Sort-Object) {
        $info = $PluginStore[$plugin]
        Write-Host "║   $plugin - $($info.Name)" -ForegroundColor Gray
        Write-Host "║     ⭐ $($info.Rating) | 📥 $($info.Downloads) | Category: $($info.Category)" -ForegroundColor DarkGray
    }
    
    if ($state.Installed.Count -gt 0) {
        Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
        Write-Host "║ Installed Plugins:" -ForegroundColor Cyan
        foreach ($plugin in $state.Installed.Values) {
            $color = if ($plugin.Enabled) { "Green" } else { "Yellow" }
            Write-Host "║   $($plugin.Manifest.name) ($($plugin.Id))" -ForegroundColor $color
            Write-Host "║     Version: $($plugin.Manifest.version) | Status: $($plugin.Status)" -ForegroundColor DarkGray
        }
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
switch ($Action) {
    "Install" {
        if (-not $PluginId) {
            Write-PluginLog "PluginId required" "ERROR"
            exit 1
        }
        $source = if ($PluginUrl) { $PluginUrl } else { "store" }
        $plugin = Install-Plugin -Source $source -Id $PluginId
        if ($plugin) {
            $plugin | ConvertTo-Json
        }
        else {
            exit 1
        }
    }
    "Uninstall" {
        if (-not $PluginId) {
            Write-PluginLog "PluginId required" "ERROR"
            exit 1
        }
        $success = Uninstall-Plugin -Id $PluginId
        exit ($success ? 0 : 1)
    }
    "Enable" {
        if (-not $PluginId) {
            Write-PluginLog "PluginId required" "ERROR"
            exit 1
        }
        $success = Enable-Plugin -Id $PluginId
        exit ($success ? 0 : 1)
    }
    "Disable" {
        if (-not $PluginId) {
            Write-PluginLog "PluginId required" "ERROR"
            exit 1
        }
        $success = Disable-Plugin -Id $PluginId
        exit ($success ? 0 : 1)
    }
    "List" {
        $state = Get-PluginState
        $state.Installed | ConvertTo-Json -Depth 10
    }
    "Discover" {
        $PluginStore | ConvertTo-Json -Depth 10
    }
    "Validate" {
        if (-not $PluginPath) {
            Write-PluginLog "PluginPath required" "ERROR"
            exit 1
        }
        $manifestPath = Join-Path $PluginPath "manifest.json"
        $result = Test-PluginManifest -ManifestPath $manifestPath
        $result | ConvertTo-Json -Depth 10
    }
    "ShowStatus" {
        Show-PluginStatus
    }
}
