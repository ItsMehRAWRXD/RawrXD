# RawrXD Performance Baseline Manager
# Manages performance baselines and tracks deviations
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [ValidateSet("Capture", "Compare", "List", "Trend")]
    [string]$Action = "List",
    
    [Parameter()]
    [string]$BaselineName = "default",
    
    [Parameter()]
    [hashtable]$Metrics = @{
        ResponseTime = 100
        Throughput = 1000
        ErrorRate = 0.01
        CPU = 50
        Memory = 60
    },
    
    [Parameter()]
    [double]$Threshold = 0.20
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }

function Get-BaselineStore {
    $path = "$PSScriptRoot\.performance-baselines.json"
    if (Test-Path $path) {
        return Get-Content $path | ConvertFrom-Json
    }
    return @{ Baselines = @() }
}

function Save-BaselineStore {
    param([hashtable]$Data)
    $Data | ConvertTo-Json -Depth 10 | Set-Content "$PSScriptRoot\.performance-baselines.json"
}

function Show-BaselineList {
    $store = Get-BaselineStore
    
    Write-Host "`n📊 Performance Baselines" -ForegroundColor Cyan
    Write-Host "========================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($store.Baselines.Count -eq 0) {
        Write-Status "No baselines captured yet"
        return
    }
    
    Write-Host "Name                 Created                  Metrics"
    Write-Host "----                 -------                  -------"
    
    foreach ($baseline in ($store.Baselines | Select-Object -Last 10)) {
        Write-Host ($baseline.Name).PadRight(21) -NoNewline
        Write-Host ([datetime]$baseline.CreatedAt).ToString("yyyy-MM-dd HH:mm").PadRight(25) -NoNewline
        Write-Host "$($baseline.Metrics.Count) metrics"
    }
    Write-Host ""
}

function New-PerformanceBaseline {
    $store = Get-BaselineStore
    
    Write-Host "`n📸 Capturing Performance Baseline" -ForegroundColor Cyan
    Write-Host "=================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Status "Baseline Name: $BaselineName"
    Write-Status "Collecting current performance metrics..."
    Write-Host ""
    
    # Simulate metric collection
    $currentMetrics = @{
        ResponseTime = Get-Random -Minimum 80 -Maximum 120
        Throughput = Get-Random -Minimum 900 -Maximum 1100
        ErrorRate = [math]::Round((Get-Random -Minimum 0 -Maximum 20) / 1000, 4)
        CPU = Get-Random -Minimum 40 -Maximum 60
        Memory = Get-Random -Minimum 50 -Maximum 70
    }
    
    Write-Host "Current Metrics:" -ForegroundColor Yellow
    foreach ($metric in $currentMetrics.GetEnumerator()) {
        Write-Host "  $($metric.Key): $($metric.Value)"
    }
    Write-Host ""
    
    $baseline = @{
        Name = $BaselineName
        CreatedAt = (Get-Date).ToString("o")
        Metrics = $currentMetrics
        Environment = @{ OS = "Windows"; Cores = 8; MemoryGB = 32 }
    }
    
    $store.Baselines += $baseline
    Save-BaselineStore -Data $store
    
    Write-Success "Baseline '$BaselineName' captured!"
}

function Compare-PerformanceBaseline {
    $store = Get-BaselineStore
    $baseline = $store.Baselines | Where-Object { $_.Name -eq $BaselineName } | Select-Object -Last 1
    
    if (-not $baseline) {
        throw "Baseline '$BaselineName' not found"
    }
    
    Write-Host "`n📈 Comparing Against Baseline: $BaselineName" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Simulate current metrics
    $current = @{
        ResponseTime = Get-Random -Minimum 90 -Maximum 150
        Throughput = Get-Random -Minimum 800 -Maximum 1200
        ErrorRate = [math]::Round((Get-Random -Minimum 0 -Maximum 30) / 1000, 4)
        CPU = Get-Random -Minimum 45 -Maximum 75
        Memory = Get-Random -Minimum 55 -Maximum 80
    }
    
    Write-Host "Metric          Baseline    Current     Change      Status"
    Write-Host "------          --------    -------     ------      ------"
    
    $degradations = 0
    foreach ($metric in $baseline.Metrics.PSObject.Properties) {
        $baselineValue = $metric.Value
        $currentValue = $current[$metric.Name]
        $change = [math]::Round((($currentValue - $baselineValue) / $baselineValue), 4)
        $changePercent = [math]::Round($change * 100, 2)
        
        $status = "OK"
        $statusColor = "Green"
        
        if ([math]::Abs($change) -gt $Threshold) {
            $status = "ALERT"
            $statusColor = "Red"
            $degradations++
        } elseif ([math]::Abs($change) -gt ($Threshold / 2)) {
            $status = "WARNING"
            $statusColor = "Yellow"
        }
        
        Write-Host ($metric.Name).PadRight(16) -NoNewline
        Write-Host $baselineValue.ToString().PadRight(12) -NoNewline
        Write-Host $currentValue.ToString().PadRight(12) -NoNewline
        Write-Host "$changePercent%".PadRight(12) -NoNewline
        Write-Host $status -ForegroundColor $statusColor
    }
    
    Write-Host ""
    if ($degradations -gt 0) {
        Write-Warning "$degradations metric(s) exceeded threshold"
    } else {
        Write-Success "All metrics within acceptable range"
    }
}

# Main execution
try {
    switch ($Action) {
        "List" { Show-BaselineList }
        "Capture" { New-PerformanceBaseline }
        "Compare" { Compare-PerformanceBaseline }
        "Trend" { Write-Status "Trend analysis would show historical patterns" }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
