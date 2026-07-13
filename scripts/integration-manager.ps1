# RawrXD Integration Manager
# Manages third-party integrations and connectors

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("List", "Configure", "Test", "Enable", "Disable", "Status")]
    [string]$Action = "List",
    
    [string]$Integration = "",
    [string]$ConfigFile = "",
    [hashtable]$Parameters = @{},
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$script:IntegrationDir = "integrations"
$script:IntegrationConfig = "$script:IntegrationDir/config.json"

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

function Initialize-IntegrationManager {
    if (-not (Test-Path $script:IntegrationDir)) {
        New-Item -ItemType Directory -Path $script:IntegrationDir -Force | Out-Null
    }
    
    if (-not (Test-Path $script:IntegrationConfig)) {
        @{} | ConvertTo-Json | Out-File $script:IntegrationConfig
    }
    
    Write-Status "Integration Manager initialized"
}

function Get-AvailableIntegrations {
    return @{
        OpenAI = @{
            Name = "OpenAI"
            Description = "OpenAI API integration for GPT models"
            RequiredParams = @("api_key", "base_url")
            OptionalParams = @("organization", "timeout")
            TestEndpoint = "/models"
        }
        Anthropic = @{
            Name = "Anthropic"
            Description = "Anthropic Claude API integration"
            RequiredParams = @("api_key")
            OptionalParams = @("api_version", "timeout")
            TestEndpoint = "/v1/models"
        }
        HuggingFace = @{
            Name = "HuggingFace"
            Description = "Hugging Face Hub integration"
            RequiredParams = @("token")
            OptionalParams = @("cache_dir", "endpoint")
            TestEndpoint = "/api/whoami"
        }
        AWS = @{
            Name = "AWS"
            Description = "Amazon Web Services integration"
            RequiredParams = @("access_key_id", "secret_access_key", "region")
            OptionalParams = @("session_token", "profile")
            TestEndpoint = "sts:GetCallerIdentity"
        }
        Azure = @{
            Name = "Azure"
            Description = "Microsoft Azure integration"
            RequiredParams = @("subscription_id", "tenant_id", "client_id", "client_secret")
            OptionalParams = @("resource_group", "location")
            TestEndpoint = "/subscriptions"
        }
        GoogleCloud = @{
            Name = "GoogleCloud"
            Description = "Google Cloud Platform integration"
            RequiredParams = @("project_id", "credentials_path")
            OptionalParams = @("region", "zone")
            TestEndpoint = "/v1/projects"
        }
        Discord = @{
            Name = "Discord"
            Description = "Discord bot integration"
            RequiredParams = @("bot_token")
            OptionalParams = @("guild_id", "channel_id")
            TestEndpoint = "/users/@me"
        }
        Slack = @{
            Name = "Slack"
            Description = "Slack workspace integration"
            RequiredParams = @("bot_token")
            OptionalParams = @("signing_secret", "channel")
            TestEndpoint = "/auth.test"
        }
        GitHub = @{
            Name = "GitHub"
            Description = "GitHub API integration"
            RequiredParams = @("token")
            OptionalParams = @("enterprise_url", "org")
            TestEndpoint = "/user"
        }
        Webhook = @{
            Name = "Webhook"
            Description = "Generic webhook integration"
            RequiredParams = @("url")
            OptionalParams = @("headers", "retry_count", "timeout")
            TestEndpoint = ""
        }
    }
}

function Get-IntegrationConfig {
    if (Test-Path $script:IntegrationConfig) {
        return Get-Content $script:IntegrationConfig | ConvertFrom-Json
    }
    return @{}
}

function Save-IntegrationConfig {
    param([hashtable]$Config)
    $Config | ConvertTo-Json -Depth 5 | Out-File $script:IntegrationConfig
}

function Show-IntegrationList {
    $available = Get-AvailableIntegrations
    $configured = Get-IntegrationConfig
    
    Write-Host ""
    Write-Host "Available Integrations" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    
    foreach ($integration in $available.GetEnumerator()) {
        $info = $integration.Value
        $isConfigured = $configured.($integration.Key) -ne $null
        $status = if ($isConfigured) { "Configured" } else { "Not Configured" }
        $statusColor = if ($isConfigured) { "Green" } else { "Yellow" }
        
        Write-Host "  $($info.Name)" -ForegroundColor Cyan
        Write-Host "    Description: $($info.Description)"
        Write-Host "    Status: $status" -ForegroundColor $statusColor
        Write-Host ""
    }
}

function Configure-Integration {
    param([string]$Name, [hashtable]$Params)
    
    $available = Get-AvailableIntegrations
    
    if (-not $available[$Name]) {
        Write-Error "Unknown integration: $Name"
        return
    }
    
    $integration = $available[$Name]
    $config = Get-IntegrationConfig
    
    Write-Status "Configuring $Name integration"
    
    # Validate required parameters
    foreach ($param in $integration.RequiredParams) {
        if (-not $Params[$param]) {
            Write-Error "Missing required parameter: $param"
            return
        }
    }
    
    # Store configuration
    $config.$Name = @{
        enabled = $true
        configured = Get-Date -Format "o"
        parameters = $Params
    }
    
    Save-IntegrationConfig -Config $config
    Write-Success "$Name integration configured"
}

function Test-IntegrationConnection {
    param([string]$Name)
    
    $config = Get-IntegrationConfig
    
    if (-not $config.$Name) {
        Write-Error "Integration not configured: $Name"
        return $false
    }
    
    Write-Status "Testing $Name integration..."
    
    $available = Get-AvailableIntegrations
    $integration = $available[$Name]
    $params = $config.$Name.parameters
    
    try {
        switch ($Name) {
            "OpenAI" {
                $headers = @{ "Authorization" = "Bearer $($params.api_key)" }
                $response = Invoke-RestMethod -Uri "$($params.base_url)/v1/models" -Headers $headers -Method Get
                Write-Success "OpenAI API connection successful"
            }
            "Discord" {
                $headers = @{ "Authorization" = "Bot $($params.bot_token)" }
                $response = Invoke-RestMethod -Uri "https://discord.com/api/v10/users/@me" -Headers $headers -Method Get
                Write-Success "Discord bot connection successful (Bot: $($response.username))"
            }
            "GitHub" {
                $headers = @{ 
                    "Authorization" = "Bearer $($params.token)"
                    "Accept" = "application/vnd.github.v3+json"
                }
                $response = Invoke-RestMethod -Uri "https://api.github.com/user" -Headers $headers -Method Get
                Write-Success "GitHub API connection successful (User: $($response.login))"
            }
            default {
                Write-Warning "Test not implemented for $Name"
            }
        }
        
        return $true
    }
    catch {
        Write-Error "Connection test failed: $_"
        return $false
    }
}

function Set-IntegrationState {
    param([string]$Name, [bool]$Enabled)
    
    $config = Get-IntegrationConfig
    
    if (-not $config.$Name) {
        Write-Error "Integration not configured: $Name"
        return
    }
    
    $config.$Name.enabled = $Enabled
    Save-IntegrationConfig -Config $config
    
    $action = if ($Enabled) { "enabled" } else { "disabled" }
    Write-Success "Integration $action: $Name"
}

function Show-IntegrationStatus {
    $config = Get-IntegrationConfig
    
    Write-Host ""
    Write-Host "Integration Status" -ForegroundColor Cyan
    Write-Host "=================" -ForegroundColor Cyan
    
    if ($config.Count -eq 0) {
        Write-Warning "No integrations configured"
        return
    }
    
    foreach ($integration in $config.PSObject.Properties) {
        $info = $integration.Value
        $status = if ($info.enabled) { "Enabled" } else { "Disabled" }
        $statusColor = if ($info.enabled) { "Green" } else { "Yellow" }
        
        Write-Host "  $($integration.Name)" -ForegroundColor Cyan
        Write-Host "    Status: $status" -ForegroundColor $statusColor
        Write-Host "    Configured: $($info.configured)"
        Write-Host ""
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Integration Manager" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-IntegrationManager
    
    switch ($Action) {
        "List" { Show-IntegrationList }
        "Configure" { Configure-Integration -Name $Integration -Params $Parameters }
        "Test" { Test-IntegrationConnection -Name $Integration }
        "Enable" { Set-IntegrationState -Name $Integration -Enabled $true }
        "Disable" { Set-IntegrationState -Name $Integration -Enabled $false }
        "Status" { Show-IntegrationStatus }
    }
    
    Write-Host ""
}

Main
