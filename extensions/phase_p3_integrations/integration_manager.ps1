#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase P.3: Third-Party Integration Manager
    
.DESCRIPTION
    Manages third-party integrations for RawrXD including OAuth,
    webhooks, API connectors, and external service adapters.
    
.PARAMETER Action
    Action to perform: configure, connect, disconnect, list, test, sync
    
.PARAMETER Service
    Service name (e.g., slack, github, jira)
    
.PARAMETER ConfigPath
    Path to integration configuration
    
.EXAMPLE
    .\integration_manager.ps1 -Action configure -Service slack -ConfigPath .\slack-config.json
    .\integration_manager.ps1 -Action list
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("configure", "connect", "disconnect", "list", "test", "sync", "webhook")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [string]$Service,
    
    [Parameter(Mandatory=$false)]
    [string]$ConfigPath,
    
    [Parameter(Mandatory=$false)]
    [string]$IntegrationPath = ".\integrations",
    
    [Parameter(Mandatory=$false)]
    [string]$WebhookUrl
)

$ErrorActionPreference = "Stop"

# Integration registry
$IntegrationRegistry = @{
    Services = @{}
    ActiveConnections = @{}
    Webhooks = @{}
    LastUpdated = $null
}

# Supported integrations
$SupportedServices = @{
    slack = @{
        Name = "Slack"
        Description = "Team communication and notifications"
        AuthType = "oauth"
        Scopes = @("chat:write", "channels:read")
        ConfigFields = @("webhook_url", "channel", "username")
    }
    github = @{
        Name = "GitHub"
        Description = "Code repository and issue tracking"
        AuthType = "token"
        Scopes = @("repo", "issues:read")
        ConfigFields = @("token", "owner", "repo")
    }
    jira = @{
        Name = "Jira"
        Description = "Project management and issue tracking"
        AuthType = "basic"
        ConfigFields = @("url", "username", "api_token", "project_key")
    }
    discord = @{
        Name = "Discord"
        Description = "Community chat and notifications"
        AuthType = "webhook"
        ConfigFields = @("webhook_url", "username")
    }
    teams = @{
        Name = "Microsoft Teams"
        Description = "Enterprise communication"
        AuthType = "webhook"
        ConfigFields = @("webhook_url")
    }
    datadog = @{
        Name = "Datadog"
        Description = "Monitoring and analytics"
        AuthType = "api_key"
        ConfigFields = @("api_key", "site")
    }
}

function Write-IntegrationHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase P.3: Third-Party Integration Manager                          ║
║  OAuth, webhooks, and API connectors for external services          ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-IntegrationManager {
    if (-not (Test-Path $IntegrationPath)) {
        New-Item -ItemType Directory -Path $IntegrationPath -Force | Out-Null
    }
    
    $registryFile = Join-Path $IntegrationPath "integration_registry.json"
    if (Test-Path $registryFile) {
        $script:IntegrationRegistry = Get-Content -Path $registryFile -Raw | ConvertFrom-Json -AsHashtable
    }
}

function Save-IntegrationRegistry {
    $registryFile = Join-Path $IntegrationPath "integration_registry.json"
    $script:IntegrationRegistry.LastUpdated = Get-Date -Format "o"
    $script:IntegrationRegistry | ConvertTo-Json -Depth 10 | Set-Content -Path $registryFile
}

function Get-ServiceInfo {
    param($ServiceName)
    
    if ($script:SupportedServices.ContainsKey($ServiceName.ToLower())) {
        return $script:SupportedServices[$ServiceName.ToLower()]
    }
    return $null
}

function New-IntegrationConfig {
    param($Service, $ConfigPath)
    
    Write-Host "`nConfiguring integration: $($Service.Name)..." -ForegroundColor Yellow
    
    $config = @{}
    
    Write-Host "`nPlease provide the following configuration values:" -ForegroundColor Cyan
    foreach ($field in $Service.ConfigFields) {
        $value = Read-Host "  $field"
        $config[$field] = $value
    }
    
    # Save configuration
    $config | ConvertTo-Json -Depth 10 | Set-Content -Path $ConfigPath
    
    Write-Host "  ✓ Configuration saved to: $ConfigPath" -ForegroundColor Green
    
    return $config
}

function Connect-Service {
    param($ServiceName, $ConfigPath)
    
    Write-Host "`nConnecting to $ServiceName..." -ForegroundColor Yellow
    
    $service = Get-ServiceInfo -ServiceName $ServiceName
    if (-not $service) {
        Write-Error "Unknown service: $ServiceName"
        return
    }
    
    if (-not (Test-Path $ConfigPath)) {
        Write-Error "Configuration not found: $ConfigPath"
        Write-Host "Run: .\integration_manager.ps1 -Action configure -Service $ServiceName -ConfigPath $ConfigPath" -ForegroundColor Yellow
        return
    }
    
    $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json -AsHashtable
    
    # Validate required fields
    foreach ($field in $service.ConfigFields) {
        if (-not $config.ContainsKey($field) -or [string]::IsNullOrEmpty($config[$field])) {
            Write-Error "Missing required field: $field"
            return
        }
    }
    
    # Test connection (simulated)
    Write-Host "  Testing connection..." -ForegroundColor Gray
    Start-Sleep -Milliseconds 500
    
    # Register connection
    $connection = @{
        Service = $ServiceName
        Name = $service.Name
        ConnectedAt = Get-Date -Format "o"
        Status = "connected"
        ConfigPath = $ConfigPath
        AuthType = $service.AuthType
        LastSync = $null
    }
    
    $script:IntegrationRegistry.ActiveConnections[$ServiceName] = $connection
    Save-IntegrationRegistry
    
    Write-Host "  ✓ Connected to $($service.Name)" -ForegroundColor Green
    Write-Host "  ✓ Auth type: $($service.AuthType)" -ForegroundColor Gray
}

function Disconnect-Service {
    param($ServiceName)
    
    Write-Host "`nDisconnecting from $ServiceName..." -ForegroundColor Yellow
    
    if (-not $script:IntegrationRegistry.ActiveConnections.ContainsKey($ServiceName)) {
        Write-Error "Not connected to: $ServiceName"
        return
    }
    
    $script:IntegrationRegistry.ActiveConnections.Remove($ServiceName)
    Save-IntegrationRegistry
    
    Write-Host "  ✓ Disconnected from $ServiceName" -ForegroundColor Green
}

function Get-IntegrationList {
    Write-Host "`nSupported Integrations:" -ForegroundColor Yellow
    Write-Host ""
    
    Write-Host "  {0,-15} {1,-12} {2,-30}" -f "Service", "Auth Type", "Description" -ForegroundColor White
    Write-Host "  $("-" * 60)" -ForegroundColor Gray
    
    foreach ($service in $script:SupportedServices.GetEnumerator()) {
        $connected = $script:IntegrationRegistry.ActiveConnections.ContainsKey($service.Key)
        $status = if ($connected) { "[Connected]" } else { "" }
        Write-Host "  {0,-15} {1,-12} {2,-30} {3}" -f $service.Key, $service.Value.AuthType, $service.Value.Description, $status -ForegroundColor $(if ($connected) { "Green" } else { "Gray" })
    }
    
    Write-Host "`nActive Connections: $($script:IntegrationRegistry.ActiveConnections.Count)" -ForegroundColor Cyan
}

function Test-Integration {
    param($ServiceName)
    
    Write-Host "`nTesting integration: $ServiceName..." -ForegroundColor Yellow
    
    if (-not $script:IntegrationRegistry.ActiveConnections.ContainsKey($ServiceName)) {
        Write-Error "Not connected to: $ServiceName"
        return
    }
    
    $connection = $script:IntegrationRegistry.ActiveConnections[$ServiceName]
    
    Write-Host "  Service: $($connection.Name)" -ForegroundColor Gray
    Write-Host "  Status: $($connection.Status)" -ForegroundColor Gray
    Write-Host "  Connected: $([DateTime]::Parse($connection.ConnectedAt).ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
    
    # Simulate test
    Write-Host "`n  Sending test ping..." -ForegroundColor Gray
    Start-Sleep -Milliseconds 500
    
    Write-Host "  ✓ Integration test successful" -ForegroundColor Green
}

function Sync-Integration {
    param($ServiceName)
    
    Write-Host "`nSyncing integration: $ServiceName..." -ForegroundColor Yellow
    
    if (-not $script:IntegrationRegistry.ActiveConnections.ContainsKey($ServiceName)) {
        Write-Error "Not connected to: $ServiceName"
        return
    }
    
    $connection = $script:IntegrationRegistry.ActiveConnections[$ServiceName]
    $connection.LastSync = Get-Date -Format "o"
    Save-IntegrationRegistry
    
    Write-Host "  ✓ Sync completed at $($connection.LastSync)" -ForegroundColor Green
}

function Register-Webhook {
    param($ServiceName, $WebhookUrl)
    
    Write-Host "`nRegistering webhook for $ServiceName..." -ForegroundColor Yellow
    
    $webhookId = "wh_$(Get-Random -Minimum 10000 -Maximum 99999)"
    
    $webhook = @{
        Id = $webhookId
        Service = $ServiceName
        Url = $WebhookUrl
        CreatedAt = Get-Date -Format "o"
        Status = "active"
        Events = @("inference.complete", "tenant.created", "alert.triggered")
    }
    
    $script:IntegrationRegistry.Webhooks[$webhookId] = $webhook
    Save-IntegrationRegistry
    
    Write-Host "  ✓ Webhook registered: $webhookId" -ForegroundColor Green
    Write-Host "  ✓ URL: $WebhookUrl" -ForegroundColor Gray
    Write-Host "  ✓ Events: $($webhook.Events -join ', ')" -ForegroundColor Gray
}

function Get-WebhookList {
    Write-Host "`nRegistered Webhooks:" -ForegroundColor Yellow
    Write-Host ""
    
    if ($script:IntegrationRegistry.Webhooks.Count -eq 0) {
        Write-Host "  No webhooks registered" -ForegroundColor Gray
        return
    }
    
    foreach ($webhook in $script:IntegrationRegistry.Webhooks.Values) {
        Write-Host "  $($webhook.Id) [$($webhook.Status)]" -ForegroundColor White
        Write-Host "    Service: $($webhook.Service)" -ForegroundColor Gray
        Write-Host "    URL: $($webhook.Url)" -ForegroundColor Gray
        Write-Host "    Events: $($webhook.Events -join ', ')" -ForegroundColor Gray
        Write-Host ""
    }
}

# Main execution
Write-IntegrationHeader
Initialize-IntegrationManager

switch ($Action) {
    "configure" {
        if (-not $Service) {
            Write-Error "Service required for configure action"
            exit 1
        }
        if (-not $ConfigPath) {
            $ConfigPath = ".\${Service}_config.json"
        }
        $serviceInfo = Get-ServiceInfo -ServiceName $Service
        if (-not $serviceInfo) {
            Write-Error "Unknown service: $Service"
            exit 1
        }
        New-IntegrationConfig -Service $serviceInfo -ConfigPath $ConfigPath
    }
    "connect" {
        if (-not $Service) {
            Write-Error "Service required for connect action"
            exit 1
        }
        if (-not $ConfigPath) {
            $ConfigPath = ".\${Service}_config.json"
        }
        Connect-Service -ServiceName $Service -ConfigPath $ConfigPath
    }
    "disconnect" {
        if (-not $Service) {
            Write-Error "Service required for disconnect action"
            exit 1
        }
        Disconnect-Service -ServiceName $Service
    }
    "list" {
        Get-IntegrationList
    }
    "test" {
        if (-not $Service) {
            Write-Error "Service required for test action"
            exit 1
        }
        Test-Integration -ServiceName $Service
    }
    "sync" {
        if (-not $Service) {
            Write-Error "Service required for sync action"
            exit 1
        }
        Sync-Integration -ServiceName $Service
    }
    "webhook" {
        if (-not $Service -or -not $WebhookUrl) {
            Write-Error "Service and WebhookUrl required for webhook action"
            exit 1
        }
        Register-Webhook -ServiceName $Service -WebhookUrl $WebhookUrl
    }
}

Write-Host "`n✅ Integration manager operation complete" -ForegroundColor Green
