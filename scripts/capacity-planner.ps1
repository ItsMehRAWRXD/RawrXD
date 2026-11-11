# RawrXD Capacity Planner
# Plans infrastructure capacity

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Analyze", "Forecast", "Recommend")]
    [string]$Action = "Analyze",
    
    [int]$GrowthRate = 15,
    [int]$TimeHorizon = 12
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

function Initialize-CapacityPlanner {
    Write-Status "Capacity Planner initialized"
}

function Show-CapacityAnalysis {
    Write-Host ""
    Write-Host "Capacity Analysis" -ForegroundColor Cyan
    Write-Host "=================" -ForegroundColor Cyan
    Write-Host ""
    
    $current = @{
        "CPU Utilization" = "65%"
        "Memory Usage" = "78%"
        "Storage Used" = "450 GB / 1 TB"
        "Network I/O" = "45%"
    }
    
    foreach ($metric in $current.GetEnumerator()) {
        Write-Host "  $($metric.Key.PadRight(20)): $($metric.Value)"
    }
}

function Show-CapacityForecast {
    param([int]$Growth, [int]$Months)
    
    Write-Host ""
    Write-Host "Capacity Forecast ($Months months, $Growth% growth)" -ForegroundColor Cyan
    Write-Host "======================================================" -ForegroundColor Cyan
    Write-Host ""
    
    $currentCPU = 65
    for ($i = 1; $i -le $Months; $i++) {
        $projected = [math]::Min(100, $currentCPU * [math]::Pow(1 + $Growth/100, $i/12))
        $color = if ($projected -gt 90) { "Red" } elseif ($projected -gt 75) { "Yellow" } else { "Green" }
        Write-Host "  Month $i`: $($projected.ToString("F1"))%" -ForegroundColor $color
    }
}

function Show-CapacityRecommendations {
    Write-Host ""
    Write-Host "Capacity Recommendations" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "  Short Term (0-3 months):"
    Write-Host "    • Add 2 CPU cores to API servers"
    Write-Host "    • Increase memory by 16GB"
    Write-Host ""
    Write-Host "  Medium Term (3-6 months):"
    Write-Host "    • Scale database cluster"
    Write-Host "    • Add CDN capacity"
    Write-Host ""
    Write-Host "  Long Term (6-12 months):"
    Write-Host "    • Consider multi-region deployment"
    Write-Host "    • Implement auto-scaling"
}

# Main execution
function Main {
    Write-Host "RawrXD Capacity Planner" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-CapacityPlanner
    
    switch ($Action) {
        "Analyze" { Show-CapacityAnalysis }
        "Forecast" { Show-CapacityForecast -Growth $GrowthRate -Months $TimeHorizon }
        "Recommend" { Show-CapacityRecommendations }
    }
    
    Write-Host ""
}

Main
