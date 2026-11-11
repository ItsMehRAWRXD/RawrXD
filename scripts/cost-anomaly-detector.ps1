# RawrXD Cost Anomaly Detector
# Detects unusual cloud spending patterns and cost spikes
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [ValidateSet("Analyze", "Baseline", "Report", "Alert")]
    [string]$Action = "Analyze",
    
    [Parameter()]
    [int]$Days = 30,
    
    [Parameter()]
    [double]$Threshold = 20.0,
    
    [Parameter()]
    [string[]]$Services = @("Compute", "Storage", "Network", "Database"),
    
    [Parameter()]
    [string]$OutputPath = "cost-anomaly-report.json",
    
    [Parameter()]
    [switch]$DailyReport
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

function Get-CostData {
    param([int]$NumDays)
    
    $data = @()
    $baseDate = (Get-Date).AddDays(-$NumDays)
    
    for ($i = 0; $i -lt $NumDays; $i++) {
        $date = $baseDate.AddDays($i)
        
        # Generate simulated cost data with occasional anomalies
        $dailyCost = @{
            Date = $date.ToString("yyyy-MM-dd")
            Total = 0
            Services = @{}
        }
        
        foreach ($service in $Services) {
            $baseAmount = switch ($service) {
                "Compute" { 500 }
                "Storage" { 200 }
                "Network" { 150 }
                "Database" { 300 }
                default { 100 }
            }
            
            # Add random variation
            $variation = Get-Random -Minimum -20 -Maximum 20
            $amount = $baseAmount + $variation
            
            # Inject occasional anomaly
            if ((Get-Random -Maximum 100) -lt 5) {
                $amount = $amount * (1 + (Get-Random -Minimum 0.3 -Maximum 0.8))
            }
            
            $dailyCost.Services[$service] = [math]::Round($amount, 2)
            $dailyCost.Total += $amount
        }
        
        $dailyCost.Total = [math]::Round($dailyCost.Total, 2)
        $data += $dailyCost
    }
    
    return $data
}

function Find-CostAnomalies {
    param([array]$CostData, [double]$AnomalyThreshold)
    
    $anomalies = @()
    
    # Calculate moving average
    $windowSize = 7
    for ($i = $windowSize; $i -lt $CostData.Count; $i++) {
        $current = $CostData[$i]
        $window = $CostData[($i - $windowSize)..($i - 1)]
        $avg = ($window | Measure-Object -Property Total -Average).Average
        $stdDev = [math]::Sqrt((($window | ForEach-Object { [math]::Pow($_.Total - $avg, 2) }) | Measure-Object -Average).Average)
        
        $deviation = [math]::Abs($current.Total - $avg)
        $percentChange = if ($avg -gt 0) { ($deviation / $avg) * 100 } else { 0 }
        
        if ($percentChange -gt $AnomalyThreshold) {
            $anomalies += [PSCustomObject]@{
                Date = $current.Date
                Amount = $current.Total
                Average = [math]::Round($avg, 2)
                Deviation = [math]::Round($deviation, 2)
                PercentChange = [math]::Round($percentChange, 2)
                Severity = if ($percentChange -gt 50) { "Critical" } elseif ($percentChange -gt 30) { "High" } else { "Medium" }
                Services = $current.Services
            }
        }
    }
    
    return $anomalies
}

function Invoke-CostAnalysis {
    Write-Status "Analyzing costs for last $Days days..."
    Write-Status "Anomaly threshold: $Threshold%"
    Write-Host ""
    
    $costData = Get-CostData -NumDays $Days
    $anomalies = Find-CostAnomalies -CostData $costData -AnomalyThreshold $Threshold
    
    # Calculate statistics
    $totalSpend = ($costData | Measure-Object -Property Total -Sum).Sum
    $avgDaily = ($costData | Measure-Object -Property Total -Average).Average
    $maxDay = ($costData | Sort-Object Total -Descending | Select-Object -First 1)
    $minDay = ($costData | Sort-Object Total | Select-Object -First 1)
    
    # Display summary
    Write-Host "Cost Analysis Summary" -ForegroundColor Cyan
    Write-Host "====================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Period: Last $Days days"
    Write-Host "Total Spend: `$([math]::Round($totalSpend, 2))"
    Write-Host "Daily Average: `$([math]::Round($avgDaily, 2))"
    Write-Host "Highest Day: $($maxDay.Date) (`$$($maxDay.Total))"
    Write-Host "Lowest Day: $($minDay.Date) (`$$($minDay.Total))"
    Write-Host "Anomalies Detected: $($anomalies.Count)" -ForegroundColor $(if ($anomalies.Count -gt 0) { "Red" } else { "Green" })
    Write-Host ""
    
    # Service breakdown
    Write-Host "Service Breakdown (Average Daily):" -ForegroundColor Cyan
    Write-Host "---------------------------------"
    foreach ($service in $Services) {
        $serviceAvg = ($costData | ForEach-Object { $_.Services[$service] } | Measure-Object -Average).Average
        $percentOfTotal = if ($avgDaily -gt 0) { ($serviceAvg / $avgDaily) * 100 } else { 0 }
        Write-Host "  $service`: `$([math]::Round($serviceAvg, 2)) ($([math]::Round($percentOfTotal, 1))%)"
    }
    Write-Host ""
    
    # Show anomalies
    if ($anomalies.Count -gt 0) {
        Write-Host "Cost Anomalies Detected:" -ForegroundColor Red
        Write-Host "-----------------------"
        Write-Host "Date          Amount      Average     Change      Severity"
        Write-Host "----          ------      -------     ------      --------"
        
        foreach ($anomaly in ($anomalies | Sort-Object Date -Descending)) {
            $color = switch ($anomaly.Severity) {
                "Critical" { "Red" }
                "High" { "Yellow" }
                default { "White" }
            }
            
            Write-Host $anomaly.Date.PadRight(14) -NoNewline
            Write-Host "`$$($anomaly.Amount)".PadRight(12) -NoNewline
            Write-Host "`$$($anomaly.Average)".PadRight(12) -NoNewline
            Write-Host "+$($anomaly.PercentChange)%".PadRight(12) -NoNewline
            Write-Host $anomaly.Severity -ForegroundColor $color
        }
        Write-Host ""
    }
    
    # Export report
    $report = @{
        GeneratedAt = (Get-Date).ToString("o")
        Period = @{ Days = $Days; StartDate = $costData[0].Date; EndDate = $costData[-1].Date }
        Summary = @{
            TotalSpend = [math]::Round($totalSpend, 2)
            DailyAverage = [math]::Round($avgDaily, 2)
            AnomalyCount = $anomalies.Count
        }
        ServiceBreakdown = @{}
        Anomalies = $anomalies
        DailyCosts = $costData
    }
    
    foreach ($service in $Services) {
        $serviceAvg = ($costData | ForEach-Object { $_.Services[$service] } | Measure-Object -Average).Average
        $report.ServiceBreakdown[$service] = [math]::Round($serviceAvg, 2)
    }
    
    $report | ConvertTo-Json -Depth 5 | Set-Content $OutputPath
    Write-Success "Cost analysis report saved to: $OutputPath"
}

function Set-CostBaseline {
    Write-Status "Setting cost baseline..."
    
    $baseline = @{
        SetAt = (Get-Date).ToString("o")
        ExpectedDaily = @{}
        AlertThreshold = $Threshold
    }
    
    foreach ($service in $Services) {
        $baseAmount = switch ($service) {
            "Compute" { 500 }
            "Storage" { 200 }
            "Network" { 150 }
            "Database" { 300 }
            default { 100 }
        }
        $baseline.ExpectedDaily[$service] = $baseAmount
    }
    
    $baseline | ConvertTo-Json | Set-Content "cost-baseline.json"
    Write-Success "Cost baseline saved to cost-baseline.json"
}

function Export-CostReport {
    if (-not (Test-Path $OutputPath)) {
        Write-Warning "No cost report found at $OutputPath"
        return
    }
    
    $report = Get-Content $OutputPath | ConvertFrom-Json
    
    Write-Host "Cost Report Summary" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Period: $($report.Period.StartDate) to $($report.Period.EndDate)"
    Write-Host "Total Spend: `$$($report.Summary.TotalSpend)"
    Write-Host "Daily Average: `$$($report.Summary.DailyAverage)"
    Write-Host "Anomalies: $($report.Summary.AnomalyCount)"
    Write-Host ""
}

function Send-CostAlert {
    if (-not (Test-Path $OutputPath)) {
        Write-Warning "No cost report found. Run Analyze first."
        return
    }
    
    $report = Get-Content $OutputPath | ConvertFrom-Json
    
    if ($report.Summary.AnomalyCount -gt 0) {
        Write-Warning "COST ALERT: $($report.Summary.AnomalyCount) cost anomalies detected!"
        Write-Status "Would send notification to cost management team"
    } else {
        Write-Success "No cost alerts to send"
    }
}

# Main execution
try {
    switch ($Action) {
        "Analyze" { Invoke-CostAnalysis }
        "Baseline" { Set-CostBaseline }
        "Report" { Export-CostReport }
        "Alert" { Send-CostAlert }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
