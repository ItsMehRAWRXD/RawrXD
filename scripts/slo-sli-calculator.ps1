# RawrXD SLO/SLI Calculator
# Calculates and tracks Service Level Objectives and Indicators
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [ValidateSet("Calculate", "Track", "Report", "Alert")]
    [string]$Action = "Calculate",
    
    [Parameter()]
    [string]$ServiceName,
    
    [Parameter()]
    [ValidateSet("Availability", "Latency", "ErrorRate", "Throughput")]
    [string]$SLIType = "Availability",
    
    [Parameter()]
    [double]$Target = 99.9,
    
    [Parameter()]
    [int]$TimeWindow = 30,
    
    [Parameter()]
    [string]$OutputPath = "slo-report.json"
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

function Get-SLIData {
    param([string]$Type, [int]$Days)
    
    $dataPoints = @()
    $baseDate = (Get-Date).AddDays(-$Days)
    
    for ($i = 0; $i -lt $Days; $i++) {
        $date = $baseDate.AddDays($i)
        
        $value = switch ($Type) {
            "Availability" { Get-Random -Minimum 99.0 -Maximum 100.0 }
            "Latency" { Get-Random -Minimum 50 -Maximum 200 }
            "ErrorRate" { Get-Random -Minimum 0.01 -Maximum 1.0 }
            "Throughput" { Get-Random -Minimum 800 -Maximum 1200 }
            default { 0 }
        }
        
        $dataPoints += [PSCustomObject]@{
            Date = $date.ToString("yyyy-MM-dd")
            Value = [math]::Round($value, 3)
            GoodEvents = if ($Type -eq "Availability") { Get-Random -Minimum 99000 -Maximum 100000 } else { 0 }
            TotalEvents = if ($Type -eq "Availability") { 100000 } else { 0 }
        }
    }
    
    return $dataPoints
}

function Measure-SLOCompliance {
    param([array]$Data, [double]$Target, [string]$Type)
    
    $compliant = 0
    $breached = 0
    $total = $Data.Count
    
    foreach ($point in $Data) {
        $isCompliant = switch ($Type) {
            "Availability" { $point.Value -ge $Target }
            "Latency" { $point.Value -le $Target }
            "ErrorRate" { $point.Value -le (100 - $Target) }
            "Throughput" { $point.Value -ge $Target }
            default { $true }
        }
        
        if ($isCompliant) {
            $compliant++
        } else {
            $breached++
        }
    }
    
    $actualSLO = if ($total -gt 0) { ($compliant / $total) * 100 } else { 0 }
    
    return [PSCustomObject]@{
        CompliantDays = $compliant
        BreachedDays = $breached
        TotalDays = $total
        ActualSLO = [math]::Round($actualSLO, 2)
        TargetSLO = $Target
        Status = if ($actualSLO -ge $Target) { "Met" } else { "Missed" }
    }
}

function Invoke-SLOCalculation {
    if (-not $ServiceName) {
        throw "ServiceName parameter required"
    }
    
    Write-Status "Calculating SLO for $ServiceName"
    Write-Status "SLI Type: $SLIType"
    Write-Status "Target: $Target%"
    Write-Status "Time Window: $TimeWindow days"
    Write-Host ""
    
    $sliData = Get-SLIData -Type $SLIType -Days $TimeWindow
    $compliance = Measure-SLOCompliance -Data $sliData -Target $Target -Type $SLIType
    
    # Calculate error budget
    $errorBudget = 100 - $Target
    $consumedBudget = 100 - $compliance.ActualSLO
    $remainingBudget = [math]::Max(0, $errorBudget - $consumedBudget)
    
    Write-Host "SLO Report: $ServiceName" -ForegroundColor Cyan
    Write-Host "======================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "SLI Type: $SLIType"
    Write-Host "Target SLO: $Target%"
    Write-Host "Actual SLO: $($compliance.ActualSLO)%" -ForegroundColor $(if ($compliance.Status -eq "Met") { "Green" } else { "Red" })
    Write-Host "Status: $($compliance.Status)" -ForegroundColor $(if ($compliance.Status -eq "Met") { "Green" } else { "Red" })
    Write-Host ""
    Write-Host "Compliance Details:"
    Write-Host "  Compliant Days: $($compliance.CompliantDays)"
    Write-Host "  Breached Days: $($compliance.BreachedDays)"
    Write-Host "  Total Days: $($compliance.TotalDays)"
    Write-Host ""
    Write-Host "Error Budget:"
    Write-Host "  Total Budget: $errorBudget%"
    Write-Host "  Consumed: $([math]::Round($consumedBudget, 2))%"
    Write-Host "  Remaining: $([math]::Round($remainingBudget, 2))%" -ForegroundColor $(if ($remainingBudget -gt 0) { "Green" } else { "Red" })
    Write-Host ""
    
    # Show recent data
    Write-Host "Recent SLI Data:" -ForegroundColor Cyan
    Write-Host "---------------"
    Write-Host "Date          Value"
    Write-Host "----          -----"
    
    foreach ($point in ($sliData | Select-Object -Last 7)) {
        $color = switch ($SLIType) {
            "Availability" { if ($point.Value -ge $Target) { "Green" } else { "Red" } }
            "Latency" { if ($point.Value -le $Target) { "Green" } else { "Red" } }
            default { "White" }
        }
        
        Write-Host $point.Date.PadRight(14) -NoNewline
        Write-Host $point.Value -ForegroundColor $color
    }
    Write-Host ""
    
    # Export report
    $report = @{
        ServiceName = $ServiceName
        SLIType = $SLIType
        Target = $Target
        TimeWindow = $TimeWindow
        GeneratedAt = (Get-Date).ToString("o")
        Compliance = $compliance
        ErrorBudget = @{
            Total = $errorBudget
            Consumed = [math]::Round($consumedBudget, 2)
            Remaining = [math]::Round($remainingBudget, 2)
        }
        DataPoints = $sliData
    }
    
    $report | ConvertTo-Json -Depth 5 | Set-Content $OutputPath
    Write-Success "SLO report saved to: $OutputPath"
}

function Track-SLOProgress {
    if (-not $ServiceName) {
        throw "ServiceName parameter required"
    }
    
    Write-Status "Tracking SLO progress for $ServiceName..."
    
    # Simulate tracking multiple SLOs
    $slos = @(
        @{ Type = "Availability"; Target = 99.9; Current = 99.95 }
        @{ Type = "Latency"; Target = 100; Current = 85 }
        @{ Type = "ErrorRate"; Target = 0.1; Current = 0.05 }
    )
    
    Write-Host "`nSLO Tracking: $ServiceName" -ForegroundColor Cyan
    Write-Host "======================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Type          Target      Current     Status"
    Write-Host "----          ------      -------     ------"
    
    foreach ($slo in $slos) {
        $status = if ($slo.Current -ge $slo.Target) { "✓ Met" } else { "✗ Missed" }
        $color = if ($slo.Current -ge $slo.Target) { "Green" } else { "Red" }
        
        Write-Host ($slo.Type).PadRight(14) -NoNewline
        Write-Host "$($slo.Target)%".PadRight(12) -NoNewline
        Write-Host "$($slo.Current)%".PadRight(12) -NoNewline
        Write-Host $status -ForegroundColor $color
    }
    Write-Host ""
}

function Export-SLOReport {
    if (-not (Test-Path $OutputPath)) {
        Write-Warning "No SLO report found at $OutputPath"
        return
    }
    
    $report = Get-Content $OutputPath | ConvertFrom-Json
    
    Write-Host "SLO Report Summary" -ForegroundColor Cyan
    Write-Host "=================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Service: $($report.ServiceName)"
    Write-Host "SLI Type: $($report.SLIType)"
    Write-Host "Target: $($report.Target)%"
    Write-Host "Actual: $($report.Compliance.ActualSLO)%"
    Write-Host "Status: $($report.Compliance.Status)"
    Write-Host "Error Budget Remaining: $($report.ErrorBudget.Remaining)%"
    Write-Host ""
}

function Test-SLOAlert {
    if (-not (Test-Path $OutputPath)) {
        Write-Warning "No SLO report found. Run Calculate first."
        return
    }
    
    $report = Get-Content $OutputPath | ConvertFrom-Json
    
    if ($report.Compliance.Status -eq "Missed") {
        Write-Warning "SLO ALERT: $($report.ServiceName) has missed its SLO target!"
        Write-Status "Current: $($report.Compliance.ActualSLO)% (Target: $($report.Target)%)"
        Write-Status "Error budget remaining: $($report.ErrorBudget.Remaining)%"
    } else {
        Write-Success "SLO target is being met"
    }
}

# Main execution
try {
    switch ($Action) {
        "Calculate" { Invoke-SLOCalculation }
        "Track" { Track-SLOProgress }
        "Report" { Export-SLOReport }
        "Alert" { Test-SLOAlert }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
