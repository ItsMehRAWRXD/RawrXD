# RawrXD API Gateway Configurator
# Configures API gateway routes, rate limits, and policies
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [ValidateSet("List", "AddRoute", "RemoveRoute", "UpdatePolicy", "Export")]
    [string]$Action = "List",
    
    [Parameter()]
    [string]$RouteName,
    
    [Parameter()]
    [string]$Path,
    
    [Parameter()]
    [string]$BackendUrl,
    
    [Parameter()]
    [hashtable]$RateLimit = @{ RequestsPerMinute = 100 },
    
    [Parameter()]
    [string[]]$RequiredScopes = @(),
    
    [Parameter()]
    [string]$OutputPath = "gateway-config.json"
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }

function Get-GatewayConfig {
    $path = "$PSScriptRoot\.gateway-config.json"
    if (Test-Path $path) {
        return Get-Content $path | ConvertFrom-Json
    }
    return @{
        Version = "1.0"
        Routes = @()
        GlobalPolicies = @{
            CORS = @{ Enabled = $true; Origins = @("*") }
            Authentication = @{ Required = $true; Provider = "JWT" }
            RateLimiting = @{ Enabled = $true; DefaultRequestsPerMinute = 100 }
        }
    }
}

function Save-GatewayConfig {
    param([hashtable]$Config)
    $Config | ConvertTo-Json -Depth 10 | Set-Content "$PSScriptRoot\.gateway-config.json"
}

function Show-Routes {
    $config = Get-GatewayConfig
    
    Write-Host "`nAPI Gateway Configuration" -ForegroundColor Cyan
    Write-Host "==========================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Global Policies:" -ForegroundColor Yellow
    Write-Host "  CORS: $(if ($config.GlobalPolicies.CORS.Enabled) { 'Enabled' } else { 'Disabled' })"
    Write-Host "  Authentication: $($config.GlobalPolicies.Authentication.Provider)"
    Write-Host "  Default Rate Limit: $($config.GlobalPolicies.RateLimiting.DefaultRequestsPerMinute) req/min"
    Write-Host ""
    
    if ($config.Routes.Count -eq 0) {
        Write-Status "No routes configured"
        return
    }
    
    Write-Host "Configured Routes:" -ForegroundColor Yellow
    Write-Host "Name              Path                      Backend                   Rate Limit    Auth"
    Write-Host "----              ----                      -------                   ----------    ----"
    
    foreach ($route in $config.Routes) {
        $authRequired = if ($route.RequireAuth) { "Yes" } else { "No" }
        Write-Host ($route.Name).PadRight(18) -NoNewline
        Write-Host ($route.Path).PadRight(26) -NoNewline
        Write-Host ($route.BackendUrl).PadRight(26) -NoNewline
        Write-Host "$($route.RateLimit.RequestsPerMinute)/min".PadRight(14) -NoNewline
        Write-Host $authRequired
    }
    Write-Host ""
    Write-Status "Total routes: $($config.Routes.Count)"
}

function Add-Route {
    if (-not $RouteName -or -not $Path -or -not $BackendUrl) {
        throw "RouteName, Path, and BackendUrl parameters required"
    }
    
    $config = Get-GatewayConfig
    
    # Check for duplicate
    $existing = $config.Routes | Where-Object { $_.Name -eq $RouteName }
    if ($existing) {
        throw "Route '$RouteName' already exists"
    }
    
    $route = @{
        Name = $RouteName
        Path = $Path
        BackendUrl = $BackendUrl
        RateLimit = $RateLimit
        RequireAuth = $RequiredScopes.Count -gt 0
        RequiredScopes = $RequiredScopes
        CreatedAt = (Get-Date).ToString("o")
    }
    
    $config.Routes += $route
    Save-GatewayConfig -Config $config
    
    Write-Success "Route '$RouteName' added successfully"
    Write-Status "Path: $Path -> $BackendUrl"
    Write-Status "Rate Limit: $($RateLimit.RequestsPerMinute) requests/minute"
}

function Remove-Route {
    if (-not $RouteName) {
        throw "RouteName parameter required"
    }
    
    $config = Get-GatewayConfig
    $originalCount = $config.Routes.Count
    
    $config.Routes = $config.Routes | Where-Object { $_.Name -ne $RouteName }
    
    if ($config.Routes.Count -eq $originalCount) {
        Write-Warning "Route '$RouteName' not found"
        return
    }
    
    Save-GatewayConfig -Config $config
    Write-Success "Route '$RouteName' removed"
}

function Update-Policy {
    Write-Host "`nUpdate Gateway Policy" -ForegroundColor Cyan
    Write-Host "======================" -ForegroundColor Cyan
    Write-Host ""
    
    $config = Get-GatewayConfig
    
    # In a real implementation, this would accept policy parameters
    Write-Status "Current global policies:"
    Write-Host "  CORS Origins: $($config.GlobalPolicies.CORS.Origins -join ', ')"
    Write-Host "  Auth Provider: $($config.GlobalPolicies.Authentication.Provider)"
    Write-Host "  Default Rate Limit: $($config.GlobalPolicies.RateLimiting.DefaultRequestsPerMinute) req/min"
    Write-Host ""
    
    Write-Success "Policy update interface ready"
}

function Export-Configuration {
    $config = Get-GatewayConfig
    $config | ConvertTo-Json -Depth 10 | Set-Content $OutputPath
    Write-Success "Gateway configuration exported to: $OutputPath"
}

# Main execution
try {
    switch ($Action) {
        "List" { Show-Routes }
        "AddRoute" { Add-Route }
        "RemoveRoute" { Remove-Route }
        "UpdatePolicy" { Update-Policy }
        "Export" { Export-Configuration }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
