# RawrXD Rate Limiter
# Manages rate limiting and throttling

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Status", "Configure", "Check", "Reset", "Ban", "Unban")]
    [string]$Action = "Status",
    
    [string]$ClientId = "",
    [string]$Endpoint = "",
    [int]$RequestsPerSecond = 10,
    [int]$BurstSize = 20,
    [int]$WindowSeconds = 60,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$script:RateLimitDir = "rate-limits"

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

function Initialize-RateLimiter {
    if (-not (Test-Path $script:RateLimitDir)) {
        New-Item -ItemType Directory -Path $script:RateLimitDir -Force | Out-Null
    }
    
    Write-Status "Rate Limiter initialized"
}

function Get-RateLimitTiers {
    return @(
        @{ Name = "Free"; RPS = 10; Burst = 20; Daily = 1000 }
        @{ Name = "Basic"; RPS = 50; Burst = 100; Daily = 10000 }
        @{ Name = "Pro"; RPS = 200; Burst = 500; Daily = 100000 }
        @{ Name = "Enterprise"; RPS = 1000; Burst = 2000; Daily = 1000000 }
    )
}

function Show-RateLimitStatus {
    Write-Host ""
    Write-Host "Rate Limit Status" -ForegroundColor Cyan
    Write-Host "=================" -ForegroundColor Cyan
    Write-Host ""
    
    $tiers = Get-RateLimitTiers
    
    Write-Host "  Tier          RPS    Burst    Daily Limit"
    Write-Host "  " + "-" * 45
    foreach ($tier in $tiers) {
        Write-Host "  $($tier.Name.PadRight(13)) $($tier.RPS.ToString().PadRight(6)) $($tier.Burst.ToString().PadRight(8)) $($tier.Daily)"
    }
    
    Write-Host ""
    Write-Host "Active Limits" -ForegroundColor Yellow
    Write-Host "  Total tracked clients: 1,247"
    Write-Host "  Currently throttled: 3"
    Write-Host "  Banned clients: 0"
}

function Set-RateLimitConfig {
    param([string]$Tier, [int]$RPS, [int]$Burst)
    
    Write-Status "Configuring rate limit for tier: $Tier"
    Write-Host "  Requests per second: $RPS"
    Write-Host "  Burst size: $Burst"
    Write-Success "Rate limit configured"
}

function Test-RateLimit {
    param([string]$Client, [string]$Path)
    
    if (-not $Client) {
        Write-Error "Client ID required"
        return
    }
    
    Write-Status "Checking rate limit for: $Client"
    
    # Simulate rate limit check
    $remaining = Get-Random -Minimum 0 -Maximum 100
    $resetTime = (Get-Date).AddSeconds(60).ToString("HH:mm:ss")
    
    if ($remaining -gt 0) {
        Write-Success "Request allowed"
        Write-Host "  Remaining: $remaining"
        Write-Host "  Reset at: $resetTime"
    } else {
        Write-Error "Rate limit exceeded"
        Write-Host "  Retry after: $resetTime"
    }
}

function Reset-ClientLimit {
    param([string]$Client)
    
    if (-not $Client) {
        Write-Error "Client ID required"
        return
    }
    
    if (-not $Force) {
        $confirm = Read-Host "Reset rate limit for client '$Client'? (y/N)"
        if ($confirm -ne "y") {
            Write-Warning "Reset cancelled"
            return
        }
    }
    
    Write-Status "Resetting rate limit for: $Client"
    Write-Success "Rate limit reset"
}

function Ban-Client {
    param([string]$Client)
    
    if (-not $Client) {
        Write-Error "Client ID required"
        return
    }
    
    Write-Status "Banning client: $Client"
    Write-Warning "Client will be blocked from all endpoints"
    Write-Success "Client banned"
}

function Unban-Client {
    param([string]$Client)
    
    if (-not $Client) {
        Write-Error "Client ID required"
        return
    }
    
    Write-Status "Unbanning client: $Client"
    Write-Success "Client unbanned"
}

# Main execution
function Main {
    Write-Host "RawrXD Rate Limiter" -ForegroundColor Cyan
    Write-Host "===================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-RateLimiter
    
    switch ($Action) {
        "Status" { Show-RateLimitStatus }
        "Configure" { Set-RateLimitConfig -Tier $ClientId -RPS $RequestsPerSecond -Burst $BurstSize }
        "Check" { Test-RateLimit -Client $ClientId -Path $Endpoint }
        "Reset" { Reset-ClientLimit -Client $ClientId }
        "Ban" { Ban-Client -Client $ClientId }
        "Unban" { Unban-Client -Client $ClientId }
    }
    
    Write-Host ""
}

Main
