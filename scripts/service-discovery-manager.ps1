# RawrXD Service Discovery Manager
# Manages service registration and discovery
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [ValidateSet("List", "Register", "Deregister", "Health", "Discover")]
    [string]$Action = "List",
    
    [Parameter()]
    [string]$ServiceName,
    
    [Parameter()]
    [string]$ServiceUrl,
    
    [Parameter()]
    [hashtable]$Metadata = @{},
    
    [Parameter()]
    [string]$Environment = "production"
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }

function Get-ServiceRegistry {
    $path = "$PSScriptRoot\.service-registry.json"
    if (Test-Path $path) {
        return Get-Content $path | ConvertFrom-Json
    }
    return @{ Services = @(); LastUpdated = (Get-Date).ToString("o") }
}

function Save-ServiceRegistry {
    param([hashtable]$Data)
    $Data.LastUpdated = (Get-Date).ToString("o")
    $Data | ConvertTo-Json -Depth 10 | Set-Content "$PSScriptRoot\.service-registry.json"
}

function Show-ServiceList {
    $registry = Get-ServiceRegistry
    
    Write-Host "`nService Discovery Registry" -ForegroundColor Cyan
    Write-Host "==========================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($registry.Services.Count -eq 0) {
        Write-Status "No services registered"
        return
    }
    
    Write-Host "Service Name          Environment    URL                           Health    Last Check"
    Write-Host "------------          -----------    ---                           ------    ----------"
    
    foreach ($service in $registry.Services) {
        $healthColor = switch ($service.Health) {
            "Healthy" { "Green" }
            "Degraded" { "Yellow" }
            "Unhealthy" { "Red" }
            default { "White" }
        }
        
        Write-Host ($service.Name).PadRight(22) -NoNewline
        Write-Host ($service.Environment).PadRight(15) -NoNewline
        Write-Host ($service.Url).PadRight(30) -NoNewline
        Write-Host ($service.Health).PadRight(10) -ForegroundColor $healthColor -NoNewline
        Write-Host $service.LastCheck
    }
    Write-Host ""
    Write-Status "Total services: $($registry.Services.Count)"
}

function Register-Service {
    if (-not $ServiceName -or -not $ServiceUrl) {
        throw "ServiceName and ServiceUrl parameters required"
    }
    
    $registry = Get-ServiceRegistry
    
    # Check if service already exists
    $existing = $registry.Services | Where-Object { $_.Name -eq $ServiceName -and $_.Environment -eq $Environment }
    
    $service = @{
        Name = $ServiceName
        Url = $ServiceUrl
        Environment = $Environment
        Health = "Healthy"
        LastCheck = (Get-Date).ToString("o")
        Metadata = $Metadata
    }
    
    if ($existing) {
        # Update existing
        $registry.Services = $registry.Services | Where-Object { -not ($_.Name -eq $ServiceName -and $_.Environment -eq $Environment) }
        Write-Status "Updating existing service registration"
    }
    
    $registry.Services += $service
    Save-ServiceRegistry -Data $registry
    
    Write-Success "Service '$ServiceName' registered successfully"
    Write-Status "Environment: $Environment"
    Write-Status "URL: $ServiceUrl"
}

function Deregister-Service {
    if (-not $ServiceName) {
        throw "ServiceName parameter required"
    }
    
    $registry = Get-ServiceRegistry
    $originalCount = $registry.Services.Count
    
    $registry.Services = $registry.Services | Where-Object { $_.Name -ne $ServiceName }
    
    if ($registry.Services.Count -eq $originalCount) {
        Write-Warning "Service '$ServiceName' not found"
        return
    }
    
    Save-ServiceRegistry -Data $registry
    Write-Success "Service '$ServiceName' deregistered"
}

function Check-ServiceHealth {
    if (-not $ServiceName) {
        throw "ServiceName parameter required"
    }
    
    $registry = Get-ServiceRegistry
    $service = $registry.Services | Where-Object { $_.Name -eq $ServiceName } | Select-Object -First 1
    
    if (-not $service) {
        throw "Service '$ServiceName' not found"
    }
    
    Write-Host "`nHealth Check: $ServiceName" -ForegroundColor Cyan
    Write-Host "========================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Service: $($service.Name)"
    Write-Host "URL: $($service.Url)"
    Write-Host "Environment: $($service.Environment)"
    Write-Host "Current Health: $($service.Health)" -ForegroundColor $(
        switch ($service.Health) {
            "Healthy" { "Green" }
            "Degraded" { "Yellow" }
            "Unhealthy" { "Red" }
        }
    )
    Write-Host "Last Check: $($service.LastCheck)"
    Write-Host ""
    
    Write-Status "Performing health check..."
    Start-Sleep -Seconds 1
    
    # Simulate health check
    $healthStatus = @("Healthy", "Healthy", "Healthy", "Degraded", "Healthy") | Get-Random
    
    $service.Health = $healthStatus
    $service.LastCheck = (Get-Date).ToString("o")
    
    Save-ServiceRegistry -Data $registry
    
    Write-Success "Health check complete: $healthStatus"
}

function Discover-Services {
    Write-Host "`nService Discovery" -ForegroundColor Cyan
    Write-Host "=================" -ForegroundColor Cyan
    Write-Host ""
    
    $registry = Get-ServiceRegistry
    
    if ($Environment -ne "all") {
        $services = $registry.Services | Where-Object { $_.Environment -eq $Environment }
        Write-Status "Discovering services in environment: $Environment"
    } else {
        $services = $registry.Services
        Write-Status "Discovering all services"
    }
    
    Write-Host ""
    Write-Host "Found $($services.Count) service(s):"
    
    foreach ($service in $services) {
        Write-Host "  - $($service.Name) @ $($service.Url) [$($service.Health)]"
    }
    Write-Host ""
}

# Main execution
try {
    switch ($Action) {
        "List" { Show-ServiceList }
        "Register" { Register-Service }
        "Deregister" { Deregister-Service }
        "Health" { Check-ServiceHealth }
        "Discover" { Discover-Services }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
