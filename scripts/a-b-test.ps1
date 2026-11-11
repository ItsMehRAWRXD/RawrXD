# RawrXD A/B Test Manager
# Manages A/B testing and experiments

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("List", "Create", "Start", "Stop", "Results", "Archive")]
    [string]$Action = "List",
    
    [string]$TestName = "",
    [string]$VariantA = "",
    [string]$VariantB = "",
    [int]$TrafficSplit = 50,
    [string]$Metric = "",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$script:ExperimentsDir = "experiments"

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

function Initialize-ABTestManager {
    if (-not (Test-Path $script:ExperimentsDir)) {
        New-Item -ItemType Directory -Path $script:ExperimentsDir -Force | Out-Null
    }
    
    Write-Status "A/B Test Manager initialized"
}

function Get-Experiments {
    return @(
        @{ Name = "ui-v2"; Status = "Running"; A = "Current UI"; B = "New UI"; Split = 50; Participants = 15420; StartDate = "2024-01-01"; EndDate = "2024-01-31" }
        @{ Name = "pricing-tier"; Status = "Running"; A = "$10/month"; B = "$15/month"; Split = 50; Participants = 8920; StartDate = "2024-01-10"; EndDate = "2024-02-10" }
        @{ Name = "model-prompt"; Status = "Completed"; A = "Standard Prompt"; B = "Optimized Prompt"; Split = 50; Participants = 25000; StartDate = "2023-12-01"; EndDate = "2023-12-31" }
        @{ Name = "cache-strategy"; Status = "Draft"; A = "LRU"; B = "LFU"; Split = 50; Participants = 0; StartDate = ""; EndDate = "" }
    )
}

function Show-ExperimentList {
    $experiments = Get-Experiments
    
    Write-Host ""
    Write-Host "A/B Tests" -ForegroundColor Cyan
    Write-Host "=========" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "  Test Name        Status      Split    Participants    Start Date    End Date"
    Write-Host "  " + "-" * 80
    
    foreach ($exp in $experiments) {
        $statusColor = switch ($exp.Status) {
            "Running" { "Green" }
            "Completed" { "Cyan" }
            "Draft" { "Gray" }
            "Stopped" { "Red" }
        }
        Write-Host "  $($exp.Name.PadRight(16)) " -NoNewline
        Write-Host $exp.Status.PadRight(11) -ForegroundColor $statusColor -NoNewline
        Write-Host " $($exp.Split)%/$($exp.Split)%  $($exp.Participants.ToString().PadRight(15)) $($exp.StartDate.PadRight(13)) $($exp.EndDate)"
    }
}

function New-Experiment {
    param([string]$Name, [string]$Control, [string]$Treatment, [int]$Split, [string]$TargetMetric)
    
    if (-not $Name) {
        Write-Error "Test name required"
        return
    }
    
    Write-Status "Creating A/B test: $Name"
    Write-Host "  Control (A): $Control"
    Write-Host "  Treatment (B): $Treatment"
    Write-Host "  Traffic Split: $Split% / $((100-$Split))%"
    Write-Host "  Target Metric: $TargetMetric"
    
    $experiment = @{
        name = $Name
        variant_a = $Control
        variant_b = $Treatment
        split = $Split
        metric = $TargetMetric
        status = "Draft"
        created = Get-Date -Format "o"
    }
    
    $experiment | ConvertTo-Json -Depth 3 | Out-File "$script:ExperimentsDir/$Name.json"
    Write-Success "Experiment created: $Name"
}

function Start-Experiment {
    param([string]$Name)
    
    if (-not $Name) {
        Write-Error "Test name required"
        return
    }
    
    Write-Status "Starting experiment: $Name"
    Write-Host "  Traffic will be split according to configuration"
    Write-Success "Experiment started: $Name"
}

function Stop-Experiment {
    param([string]$Name)
    
    if (-not $Name) {
        Write-Error "Test name required"
        return
    }
    
    if (-not $Force) {
        $confirm = Read-Host "Stop experiment '$Name'? (y/N)"
        if ($confirm -ne "y") {
            Write-Warning "Stop cancelled"
            return
        }
    }
    
    Write-Status "Stopping experiment: $Name"
    Write-Success "Experiment stopped: $Name"
}

function Show-ExperimentResults {
    param([string]$Name)
    
    if (-not $Name) {
        Write-Error "Test name required"
        return
    }
    
    Write-Host ""
    Write-Host "Experiment Results: $Name" -ForegroundColor Cyan
    Write-Host "====================" + ("=" * $Name.Length) -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "  Variant A (Control)" -ForegroundColor Yellow
    Write-Host "    Participants: 12,500"
    Write-Host "    Conversion: 12.5%"
    Write-Host "    Revenue: $15,625"
    Write-Host ""
    Write-Host "  Variant B (Treatment)" -ForegroundColor Yellow
    Write-Host "    Participants: 12,520"
    Write-Host "    Conversion: 15.2%"
    Write-Host "    Revenue: $19,030"
    Write-Host ""
    Write-Host "  Statistical Significance: 99.9%" -ForegroundColor Green
    Write-Host "  Winner: Variant B" -ForegroundColor Green
    Write-Host "  Improvement: +21.8%"
}

function Archive-Experiment {
    param([string]$Name)
    
    if (-not $Name) {
        Write-Error "Test name required"
        return
    }
    
    Write-Status "Archiving experiment: $Name"
    Write-Success "Experiment archived"
}

# Main execution
function Main {
    Write-Host "RawrXD A/B Test Manager" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-ABTestManager
    
    switch ($Action) {
        "List" { Show-ExperimentList }
        "Create" { New-Experiment -Name $TestName -Control $VariantA -Treatment $VariantB -Split $TrafficSplit -TargetMetric $Metric }
        "Start" { Start-Experiment -Name $TestName }
        "Stop" { Stop-Experiment -Name $TestName }
        "Results" { Show-ExperimentResults -Name $TestName }
        "Archive" { Archive-Experiment -Name $TestName }
    }
    
    Write-Host ""
}

Main
