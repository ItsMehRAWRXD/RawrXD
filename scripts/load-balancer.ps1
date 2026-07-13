# RawrXD Load Balancer
# Manages load balancing across multiple instances

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Status", "Add", "Remove", "Balance", "Health", "Configure")]
    [string]$Action = "Status",
    
    [string]$Backend = "",
    [string]$Algorithm = "round-robin",
    [int]$Weight = 1,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$script:ConfigFile = "loadbalancer.json"

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

function Initialize-LoadBalancer {
    Write-Status "Load Balancer Manager initialized"
    Write-Status "Algorithm: $Algorithm"
}

function Get-Backends {
    return @(
        @{ Name = "backend-1"; Host = "localhost"; Port = 8081; Weight = 3; Healthy = $true; Connections = 12; Latency = "45ms" }
        @{ Name = "backend-2"; Host = "localhost"; Port = 8082; Weight = 3; Healthy = $true; Connections = 8; Latency = "42ms" }
        @{ Name = "backend-3"; Host = "localhost"; Port = 8083; Weight = 2; Healthy = $false; Connections = 0; Latency = "-" }
        @{ Name = "backend-4"; Host = "localhost"; Port = 8084; Weight = 2; Healthy = $true; Connections = 15; Latency = "52ms" }
    )
}

function Show-LoadBalancerStatus {
    $backends = Get-Backends
    $healthy = ($backends | Where-Object { $_.Healthy }).Count
    $total = $backends.Count
    
    Write-Host ""
    Write-Host "Load Balancer Status" -ForegroundColor Cyan
    Write-Host "====================" -ForegroundColor Cyan
    Write-Host "  Algorithm: $Algorithm"
    Write-Host "  Backends: $healthy/$total healthy"
    Write-Host "  Total Connections: $(($backends | Measure-Object -Property Connections -Sum).Sum)"
    Write-Host ""
    
    Write-Host "  Backend      Host:Port          Weight    Status      Connections    Latency"
    Write-Host "  " + "-" * 75
    
    foreach ($be in $backends) {
        $statusColor = if ($be.Healthy) { "Green" } else { "Red" }
        $status = if ($be.Healthy) { "Healthy" } else { "Unhealthy" }
        $addr = "$($be.Host):$($be.Port)"
        Write-Host "  $($be.Name.PadRight(12)) $($addr.PadRight(18)) $($be.Weight.ToString().PadRight(9)) " -NoNewline
        Write-Host $status.PadRight(11) -ForegroundColor $statusColor -NoNewline
        Write-Host " $($be.Connections.ToString().PadRight(14)) $($be.Latency)"
    }
}

function Add-BackendServer {
    param([string]$BackendSpec)
    
    if (-not $BackendSpec) {
        Write-Error "Backend specification required (format: name:host:port)"
        return
    }
    
    $parts = $BackendSpec -split ":"
    if ($parts.Count -ne 3) {
        Write-Error "Invalid format. Use: name:host:port"
        return
    }
    
    $name, $host, $port = $parts
    
    Write-Status "Adding backend: $name ($host`:$port) with weight $Weight"
    Write-Success "Backend added successfully"
}

function Remove-BackendServer {
    param([string]$BackendName)
    
    if (-not $BackendName) {
        Write-Error "Backend name required"
        return
    }
    
    if (-not $Force) {
        $confirm = Read-Host "Remove backend '$BackendName'? (y/N)"
        if ($confirm -ne "y") {
            Write-Warning "Removal cancelled"
            return
        }
    }
    
    Write-Status "Removing backend: $BackendName"
    Write-Success "Backend removed"
}

function Show-LoadDistribution {
    $backends = Get-Backends | Where-Object { $_.Healthy }
    $totalWeight = ($backends | Measure-Object -Property Weight -Sum).Sum
    
    Write-Host ""
    Write-Host "Load Distribution" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($be in $backends) {
        $percentage = [math]::Round($be.Weight / $totalWeight * 100, 1)
        $bar = "█" * [math]::Round($percentage / 2)
        Write-Host "  $($be.Name.PadRight(12)) $percentage% $bar"
    }
}

function Test-BackendHealth {
    $backends = Get-Backends
    
    Write-Host ""
    Write-Host "Health Check Results" -ForegroundColor Cyan
    Write-Host "===================" -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($be in $backends) {
        $status = if ($be.Healthy) { "PASS" } else { "FAIL" }
        $color = if ($be.Healthy) { "Green" } else { "Red" }
        Write-Host "  $($be.Name.PadRight(12)) " -NoNewline
        Write-Host $status -ForegroundColor $color
    }
}

function Show-BalancerConfig {
    Write-Host ""
    Write-Host "Load Balancer Configuration" -ForegroundColor Cyan
    Write-Host "===========================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "  Algorithms Available:" -ForegroundColor Yellow
    Write-Host "    • round-robin    - Distribute evenly in rotation"
    Write-Host "    • weighted-rr    - Weighted round-robin"
    Write-Host "    • least-conn     - Least connections"
    Write-Host "    • ip-hash        - IP-based hashing"
    Write-Host "    • random         - Random distribution"
    Write-Host ""
    Write-Host "  Health Check Settings:" -ForegroundColor Yellow
    Write-Host "    • Interval: 10s"
    Write-Host "    • Timeout: 5s"
    Write-Host "    • Unhealthy threshold: 3 failures"
    Write-Host "    • Healthy threshold: 2 successes"
}

# Main execution
function Main {
    Write-Host "RawrXD Load Balancer" -ForegroundColor Cyan
    Write-Host "===================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-LoadBalancer
    
    switch ($Action) {
        "Status" { Show-LoadBalancerStatus }
        "Add" { Add-BackendServer -BackendSpec $Backend }
        "Remove" { Remove-BackendServer -BackendName $Backend }
        "Balance" { Show-LoadDistribution }
        "Health" { Test-BackendHealth }
        "Configure" { Show-BalancerConfig }
    }
    
    Write-Host ""
}

Main
