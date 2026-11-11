# RawrXD Event Simulator
# Simulates various system events for testing

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Traffic", "Error", "Load", "Custom", "Scenario")]
    [string]$EventType = "Traffic",
    
    [int]$Intensity = 50,
    [int]$Duration = 60,
    [string]$Target = "",
    [hashtable]$Parameters = @{}
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

function Initialize-EventSimulator {
    Write-Status "Event Simulator initialized"
    Write-Status "Event Type: $EventType"
    Write-Status "Intensity: $Intensity%"
    Write-Status "Duration: $Duration seconds"
}

function Simulate-TrafficEvent {
    param([int]$Intens, [int]$Dur)
    
    Write-Host ""
    Write-Host "Simulating Traffic Event" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Intensity: $Intens% of normal traffic"
    Write-Host "  Duration: $Dur seconds"
    Write-Host ""
    
    for ($i = 0; $i -lt $Dur; $i += 5) {
        $rps = [math]::Round($Intens * 10 + (Get-Random -Minimum -20 -Maximum 20))
        Write-Host "  Sending $rps requests/second..."
        Start-Sleep -Seconds 5
    }
    
    Write-Success "Traffic simulation complete"
}

function Simulate-ErrorEvent {
    param([int]$Intens, [int]$Dur)
    
    Write-Host ""
    Write-Host "Simulating Error Event" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Error Rate: $Intens%"
    Write-Host "  Duration: $Dur seconds"
    Write-Host ""
    Write-Warning "Injecting errors into system"
    Start-Sleep -Seconds $Dur
    Write-Success "Error simulation complete"
}

function Simulate-LoadEvent {
    param([int]$Intens, [int]$Dur)
    
    Write-Host ""
    Write-Host "Simulating Load Event" -ForegroundColor Cyan
    Write-Host "====================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  CPU Load: $Intens%"
    Write-Host "  Duration: $Dur seconds"
    Write-Host ""
    
    for ($i = 0; $i -le 100; $i += 10) {
        Write-Host "  Load: $i%" -NoNewline
        Start-Sleep -Milliseconds 200
        Write-Host "`r" -NoNewline
    }
    Write-Host "  Load: 100%"
    
    Start-Sleep -Seconds $Dur
    Write-Success "Load simulation complete"
}

function Simulate-CustomEvent {
    param([hashtable]$Params)
    
    Write-Host ""
    Write-Host "Simulating Custom Event" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Parameters:"
    foreach ($param in $Params.GetEnumerator()) {
        Write-Host "    $($param.Key): $($param.Value)"
    }
    Write-Success "Custom simulation complete"
}

function Run-EventScenario {
    Write-Host ""
    Write-Host "Running Event Scenario" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host ""
    
    $scenarios = @(
        @{ Name = "Normal Traffic"; Duration = 30 }
        @{ Name = "Traffic Spike"; Duration = 60 }
        @{ Name = "System Recovery"; Duration = 30 }
    )
    
    foreach ($scenario in $scenarios) {
        Write-Status "Running: $($scenario.Name)"
        Start-Sleep -Seconds $scenario.Duration
        Write-Success "Scenario complete"
        Write-Host ""
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Event Simulator" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-EventSimulator
    
    switch ($EventType) {
        "Traffic" { Simulate-TrafficEvent -Intens $Intensity -Dur $Duration }
        "Error" { Simulate-ErrorEvent -Intens $Intensity -Dur $Duration }
        "Load" { Simulate-LoadEvent -Intens $Intensity -Dur $Duration }
        "Custom" { Simulate-CustomEvent -Params $Parameters }
        "Scenario" { Run-EventScenario }
    }
    
    Write-Host ""
}

Main
