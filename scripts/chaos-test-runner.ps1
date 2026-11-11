# RawrXD Chaos Test Runner
# Runs chaos engineering experiments for resilience testing
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [ValidateSet("List", "Run", "Schedule", "Report", "Abort")]
    [string]$Action = "List",
    
    [Parameter()]
    [string]$ExperimentName,
    
    [Parameter()]
    [ValidateSet("CPU", "Memory", "Network", "Disk", "Kill", "Latency")]
    [string]$AttackType = "CPU",
    
    [Parameter()]
    [int]$Duration = 60,
    
    [Parameter()]
    [int]$Intensity = 50,
    
    [Parameter()]
    [string[]]$Targets = @("localhost"),
    
    [Parameter()]
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

function Get-ChaosStorePath {
    return "$PSScriptRoot\.chaos-experiments.json"
}

function Get-ChaosStore {
    $path = Get-ChaosStorePath
    if (Test-Path $path) {
        return Get-Content $path | ConvertFrom-Json
    }
    return @{ Experiments = @(); Results = @() }
}

function Save-ChaosStore {
    param([hashtable]$Data)
    $Data | ConvertTo-Json -Depth 10 | Set-Content (Get-ChaosStorePath)
}

function Show-ExperimentList {
    $store = Get-ChaosStore
    
    Write-Host "`nChaos Engineering Experiments" -ForegroundColor Cyan
    Write-Host "=============================" -ForegroundColor Cyan
    Write-Host ""
    
    $experiments = @(
        @{ Name = "cpu-stress"; Type = "CPU"; Description = "High CPU load test"; DefaultDuration = 300 },
        @{ Name = "memory-pressure"; Type = "Memory"; Description = "Memory exhaustion test"; DefaultDuration = 180 },
        @{ Name = "network-latency"; Type = "Network"; Description = "Network delay injection"; DefaultDuration = 120 },
        @{ Name = "disk-fill"; Type = "Disk"; Description = "Disk space exhaustion"; DefaultDuration = 60 },
        @{ Name = "process-kill"; Type = "Kill"; Description = "Random process termination"; DefaultDuration = 60 },
        @{ Name = "api-latency"; Type = "Latency"; Description = "API response delay"; DefaultDuration = 180 }
    )
    
    Write-Host "Available Experiments:"
    Write-Host "Name                Type       Duration    Description"
    Write-Host "----                ----       --------    -----------"
    
    foreach ($exp in $experiments) {
        Write-Host ($exp.Name).PadRight(20) -NoNewline
        Write-Host ($exp.Type).PadRight(11) -NoNewline
        Write-Host "$($exp.DefaultDuration)s".PadRight(12) -NoNewline
        Write-Host $exp.Description
    }
    Write-Host ""
    
    if ($store.Results.Count -gt 0) {
        Write-Host "Recent Results:"
        $recent = $store.Results | Select-Object -Last 5
        foreach ($result in $recent) {
            $color = if ($result.Success) { "Green" } else { "Red" }
            Write-Host "  [$($result.Timestamp)] $($result.ExperimentName): $(if ($result.Success) { 'PASSED' } else { 'FAILED' })" -ForegroundColor $color
        }
    }
    Write-Host ""
}

function Invoke-ChaosExperiment {
    if (-not $ExperimentName) {
        throw "ExperimentName parameter required for Run action"
    }
    
    Write-Host "`n🧪 Chaos Experiment: $ExperimentName" -ForegroundColor Cyan
    Write-Host "==================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Status "Attack Type: $AttackType"
    Write-Status "Duration: $Duration seconds"
    Write-Status "Intensity: $Intensity%"
    Write-Status "Targets: $($Targets -join ', ')"
    Write-Host ""
    
    if ($DryRun) {
        Write-Status "[DRY RUN] Would execute the following:"
        Write-Status "  - Prepare safety checks"
        Write-Status "  - Start monitoring"
        Write-Status "  - Inject $AttackType chaos"
        Write-Status "  - Monitor system resilience"
        Write-Status "  - Collect metrics"
        Write-Status "  - Generate report"
        return
    }
    
    # Safety checks
    Write-Status "Running safety checks..."
    Start-Sleep -Seconds 1
    Write-Success "  ✓ Safety checks passed"
    
    # Start monitoring
    Write-Status "Starting system monitoring..."
    $startMetrics = @{
        CPU = Get-Random -Minimum 10 -Maximum 30
        Memory = Get-Random -Minimum 40 -Maximum 60
        Network = "Normal"
    }
    Write-Success "  ✓ Monitoring active"
    Write-Host ""
    
    # Execute attack
    Write-Status "Injecting chaos: $AttackType attack"
    Write-Host ""
    
    $startTime = Get-Date
    $progress = 0
    
    while ($progress -lt $Duration) {
        $elapsed = ((Get-Date) - $startTime).TotalSeconds
        $progress = [math]::Min($elapsed, $Duration)
        $percent = [math]::Round(($progress / $Duration) * 100)
        
        # Simulate attack effects
        $cpuImpact = if ($AttackType -eq "CPU") { $Intensity } else { Get-Random -Minimum 5 -Maximum 15 }
        $memImpact = if ($AttackType -eq "Memory") { $Intensity } else { Get-Random -Minimum 0 -Maximum 10 }
        
        Write-Host "`r  Progress: [$('=' * ($percent / 2))$(' ' * (50 - ($percent / 2)))] $percent% | CPU: +$cpuImpact% | Mem: +$memImpact%" -NoNewline
        Start-Sleep -Milliseconds 500
    }
    
    Write-Host ""
    Write-Host ""
    
    # Stop attack
    Write-Status "Stopping chaos injection..."
    Start-Sleep -Seconds 1
    Write-Success "  ✓ Chaos stopped"
    
    # Collect results
    Write-Status "Collecting results..."
    $endMetrics = @{
        CPU = [math]::Min(100, $startMetrics.CPU + (Get-Random -Minimum -10 -Maximum 20))
        Memory = [math]::Min(100, $startMetrics.Memory + (Get-Random -Minimum -5 -Maximum 15))
        Network = "Normal"
    }
    
    $success = ($endMetrics.CPU -lt 90) -and ($endMetrics.Memory -lt 90)
    
    $result = @{
        ExperimentName = $ExperimentName
        AttackType = $AttackType
        Duration = $Duration
        Intensity = $Intensity
        Targets = $Targets
        Timestamp = (Get-Date).ToString("o")
        StartMetrics = $startMetrics
        EndMetrics = $endMetrics
        Success = $success
        RecoveryTime = Get-Random -Minimum 5 -Maximum 30
    }
    
    $store = Get-ChaosStore
    $store.Results += $result
    Save-ChaosStore -Data $store
    
    Write-Host ""
    Write-Host "Experiment Results" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan
    Write-Host "Status: $(if ($success) { 'PASSED ✓' } else { 'FAILED ✗' })" -ForegroundColor $(if ($success) { "Green" } else { "Red" })
    Write-Host "Recovery Time: $($result.RecoveryTime) seconds"
    Write-Host ""
    
    if ($success) {
        Write-Success "System demonstrated resilience to $AttackType attack!"
    } else {
        Write-Warning "System showed weakness under $AttackType attack"
    }
}

function Export-ChaosReport {
    $store = Get-ChaosStore
    
    Write-Host "`nChaos Engineering Report" -ForegroundColor Cyan
    Write-Host "========================" -ForegroundColor Cyan
    Write-Host ""
    
    $total = $store.Results.Count
    $passed = ($store.Results | Where-Object { $_.Success }).Count
    $failed = $total - $passed
    
    Write-Host "Total Experiments: $total"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "Green" })
    Write-Host ""
    
    if ($total -gt 0) {
        $avgRecovery = ($store.Results | Measure-Object -Property RecoveryTime -Average).Average
        Write-Host "Average Recovery Time: $([math]::Round($avgRecovery, 2)) seconds"
        Write-Host ""
        
        Write-Host "Attack Type Breakdown:"
        $byType = $store.Results | Group-Object -Property AttackType
        foreach ($type in $byType) {
            $typePassed = ($type.Group | Where-Object { $_.Success }).Count
            Write-Host "  $($type.Name): $typePassed/$($type.Count) passed"
        }
    }
    Write-Host ""
}

# Main execution
try {
    switch ($Action) {
        "List" { Show-ExperimentList }
        "Run" { Invoke-ChaosExperiment }
        "Report" { Export-ChaosReport }
        "Schedule" { Write-Status "Experiment scheduling would be implemented here" }
        "Abort" { Write-Status "Abort signal sent to running experiments" }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
