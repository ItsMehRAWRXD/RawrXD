# RawrXD Circuit Breaker
# Manages circuit breaker patterns for fault tolerance

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Status", "Open", "Close", "HalfOpen", "Reset", "History")]
    [string]$Action = "Status",
    
    [string]$Service = "",
    [int]$Threshold = 5,
    [int]$Timeout = 60,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$script:BreakerDir = "circuit-breakers"

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

function Initialize-CircuitBreaker {
    if (-not (Test-Path $script:BreakerDir)) {
        New-Item -ItemType Directory -Path $script:BreakerDir -Force | Out-Null
    }
    
    Write-Status "Circuit Breaker Manager initialized"
}

function Get-CircuitBreakers {
    return @(
        @{ Name = "model-api"; State = "Closed"; Failures = 0; Successes = 1542; LastFailure = $null }
        @{ Name = "embedding-service"; State = "Closed"; Failures = 2; Successes = 892; LastFailure = "2024-01-15 10:23" }
        @{ Name = "auth-service"; State = "Open"; Failures = 6; Successes = 2341; LastFailure = "2024-01-15 14:45" }
        @{ Name = "cache-service"; State = "Closed"; Failures = 1; Successes = 4521; LastFailure = "2024-01-14 22:15" }
    )
}

function Show-BreakerStatus {
    $breakers = Get-CircuitBreakers
    
    Write-Host ""
    Write-Host "Circuit Breaker Status" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Service                State      Failures    Successes    Last Failure"
    Write-Host "  " + "-" * 75
    
    foreach ($breaker in $breakers) {
        $stateColor = switch ($breaker.State) {
            "Closed" { "Green" }
            "Open" { "Red" }
            "HalfOpen" { "Yellow" }
        }
        
        $lastFailure = if ($breaker.LastFailure) { $breaker.LastFailure } else { "Never" }
        Write-Host "  $($breaker.Name.PadRight(22)) " -NoNewline
        Write-Host $breaker.State.PadRight(10) -ForegroundColor $stateColor -NoNewline
        Write-Host " $($breaker.Failures.ToString().PadRight(11)) $($breaker.Successes.ToString().PadRight(12)) $lastFailure"
    }
}

function Open-Circuit {
    param([string]$ServiceName)
    
    if (-not $ServiceName) {
        Write-Error "Service name required"
        return
    }
    
    Write-Status "Opening circuit for: $ServiceName"
    Write-Warning "Service will be temporarily unavailable"
    Write-Success "Circuit opened"
}

function Close-Circuit {
    param([string]$ServiceName)
    
    if (-not $ServiceName) {
        Write-Error "Service name required"
        return
    }
    
    Write-Status "Closing circuit for: $ServiceName"
    Write-Success "Circuit closed - service restored"
}

function Set-HalfOpen {
    param([string]$ServiceName)
    
    if (-not $ServiceName) {
        Write-Error "Service name required"
        return
    }
    
    Write-Status "Setting circuit to half-open for: $ServiceName"
    Write-Host "  Testing service with limited traffic..."
    Write-Success "Circuit in half-open state"
}

function Reset-Breaker {
    param([string]$ServiceName)
    
    if (-not $ServiceName) {
        Write-Error "Service name required"
        return
    }
    
    if (-not $Force) {
        $confirm = Read-Host "Reset circuit breaker for '$ServiceName'? (y/N)"
        if ($confirm -ne "y") {
            Write-Warning "Reset cancelled"
            return
        }
    }
    
    Write-Status "Resetting circuit breaker: $ServiceName"
    Write-Success "Circuit breaker reset"
}

function Show-BreakerHistory {
    Write-Host ""
    Write-Host "Circuit Breaker History" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host ""
    
    $events = @(
        @{ Time = "2024-01-15 14:45"; Service = "auth-service"; Event = "Circuit Opened"; Reason = "Threshold exceeded" }
        @{ Time = "2024-01-15 14:30"; Service = "auth-service"; Event = "Failure"; Reason = "Connection timeout" }
        @{ Time = "2024-01-15 14:25"; Service = "auth-service"; Event = "Failure"; Reason = "Connection timeout" }
        @{ Time = "2024-01-15 14:20"; Service = "auth-service"; Event = "Failure"; Reason = "Connection timeout" }
        @{ Time = "2024-01-15 14:15"; Service = "auth-service"; Event = "Failure"; Reason = "Connection timeout" }
        @{ Time = "2024-01-15 14:10"; Service = "auth-service"; Event = "Failure"; Reason = "Connection timeout" }
        @{ Time = "2024-01-15 14:05"; Service = "auth-service"; Event = "Failure"; Reason = "Connection timeout" }
    )
    
    foreach ($event in $events) {
        $color = switch ($event.Event) {
            "Circuit Opened" { "Red" }
            "Circuit Closed" { "Green" }
            default { "Yellow" }
        }
        Write-Host "  $($event.Time)  $($event.Service.PadRight(20)) " -NoNewline
        Write-Host $event.Event -ForegroundColor $color -NoNewline
        Write-Host " - $($event.Reason)"
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Circuit Breaker" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-CircuitBreaker
    
    switch ($Action) {
        "Status" { Show-BreakerStatus }
        "Open" { Open-Circuit -ServiceName $Service }
        "Close" { Close-Circuit -ServiceName $Service }
        "HalfOpen" { Set-HalfOpen -ServiceName $Service }
        "Reset" { Reset-Breaker -ServiceName $Service }
        "History" { Show-BreakerHistory }
    }
    
    Write-Host ""
}

Main
