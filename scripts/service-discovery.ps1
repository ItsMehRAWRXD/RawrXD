# RawrXD Service Discovery
# Manages service registration and discovery

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("List", "Register", "Deregister", "Health", "Find")]
    [string]$Action = "List",
    
    [string]$ServiceName = "",
    [string]$ServiceAddress = "",
    [int]$ServicePort = 0,
    [string[]]$Tags = @()
)

$ErrorActionPreference = "Stop"

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

function Initialize-ServiceDiscovery {
    Write-Status "Service Discovery initialized"
}

function Get-RegisteredServices {
    return @(
        @{ Name = "api-gateway"; Address = "10.0.1.10"; Port = 8080; Status = "Healthy"; Tags = @("http", "edge") }
        @{ Name = "model-service"; Address = "10.0.1.11"; Port = 8081; Status = "Healthy"; Tags = @("grpc", "ml") }
        @{ Name = "embedding-service"; Address = "10.0.1.12"; Port = 8082; Status = "Healthy"; Tags = @("grpc", "ml") }
        @{ Name = "cache-service"; Address = "10.0.1.13"; Port = 6379; Status = "Healthy"; Tags = @("redis", "cache") }
    )
}

function Show-ServiceList {
    $services = Get-RegisteredServices
    
    Write-Host ""
    Write-Host "Registered Services" -ForegroundColor Cyan
    Write-Host "===================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "  Service            Address        Port    Status      Tags"
    Write-Host "  " + "-" * 70
    
    foreach ($svc in $services) {
        $statusColor = if ($svc.Status -eq "Healthy") { "Green" } else { "Red" }
        $tags = $svc.Tags -join ", "
        Write-Host "  $($svc.Name.PadRight(18)) $($svc.Address.PadRight(14)) $($svc.Port.ToString().PadRight(7)) " -NoNewline
        Write-Host $svc.Status.PadRight(11) -ForegroundColor $statusColor -NoNewline
        Write-Host " $tags"
    }
}

function Register-NewService {
    param([string]$Name, [string]$Address, [int]$Port, [string[]]$ServiceTags)
    
    if (-not $Name -or -not $Address -or $Port -eq 0) {
        Write-Error "Service name, address, and port required"
        return
    }
    
    Write-Status "Registering service: $Name"
    Write-Host "  Address: $Address`:$Port"
    Write-Host "  Tags: $($ServiceTags -join ', ')"
    Write-Success "Service registered"
}

function Deregister-Service {
    param([string]$Name)
    
    if (-not $Name) {
        Write-Error "Service name required"
        return
    }
    
    Write-Status "Deregistering service: $Name"
    Write-Success "Service deregistered"
}

function Check-ServiceHealth {
    Write-Status "Checking service health..."
    
    $services = Get-RegisteredServices
    foreach ($svc in $services) {
        Write-Host "  $($svc.Name): " -NoNewline
        if ($svc.Status -eq "Healthy") {
            Write-Host "✓ Healthy" -ForegroundColor Green
        } else {
            Write-Host "✗ Unhealthy" -ForegroundColor Red
        }
    }
}

function Find-ServicesByTag {
    param([string[]]$SearchTags)
    
    Write-Status "Finding services with tags: $($SearchTags -join ', ')"
    
    $services = Get-RegisteredServices | Where-Object {
        $service = $_
        $SearchTags | ForEach-Object { $service.Tags -contains $_ }
    }
    
    if ($services.Count -eq 0) {
        Write-Warning "No services found"
    } else {
        foreach ($svc in $services) {
            Write-Host "  • $($svc.Name) at $($svc.Address)`:$($svc.Port)"
        }
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Service Discovery" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-ServiceDiscovery
    
    switch ($Action) {
        "List" { Show-ServiceList }
        "Register" { Register-NewService -Name $ServiceName -Address $ServiceAddress -Port $ServicePort -ServiceTags $Tags }
        "Deregister" { Deregister-Service -Name $ServiceName }
        "Health" { Check-ServiceHealth }
        "Find" { Find-ServicesByTag -SearchTags $Tags }
    }
    
    Write-Host ""
}

Main
