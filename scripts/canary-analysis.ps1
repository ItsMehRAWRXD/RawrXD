# RawrXD Canary Analysis
# Analyzes canary deployment health before full rollout

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("analyze", "baseline", "compare", "promote")]
    [string]$Action = "analyze",
    
    [string]$CanaryId,
    [int]$CanaryPercentage = 5,
    [double]$ErrorThreshold = 0.01,
    [double]$LatencyThreshold = 1.2, # 1.2x baseline
    [int]$MinSampleSize = 100,
    [string]$MetricsEndpoint = "http://localhost:9090",
    [switch]$AutoPromote
)

$ErrorActionPreference = "Stop"

$CanaryConfig = @{
    AnalysisWindow = 300  # 5 minutes
    Metrics = @(
        @{ Name = "ErrorRate"; Threshold = 0.01; Comparison = "absolute" }
        @{ Name = "LatencyP95"; Threshold = 1.2; Comparison = "relative" }
        @{ Name = "LatencyP99"; Threshold = 1.3; Comparison = "relative" }
        @{ Name = "Throughput"; Threshold = 0.9; Comparison = "relative" }
    )
    PromotionSteps = @(5, 10, 25, 50, 100)
}

$script:CanaryState = @{
    StartTime = Get-Date
    AnalysisComplete = $false
    HealthScore = 0
    Recommendations = @()
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Alert { param([string]$Message) Write-Host "[🚨] $Message" -ForegroundColor Red }

function Get-CanaryMetrics {
    param([string]$Id)
    
    # Simulate metrics retrieval
    return @{
        CanaryId = $Id
        Timestamp = Get-Date
        ErrorRate = Get-Random -Minimum 0.001 -Maximum 0.015
        LatencyP95 = Get-Random -Minimum 80 -Maximum 150
        LatencyP99 = Get-Random -Minimum 100 -Maximum 200
        Throughput = Get-Random -Minimum 800 -Maximum 1200
        RequestCount = Get-Random -Minimum $MinSampleSize -Maximum ($MinSampleSize * 5)
    }
}

function Get-BaselineMetrics {
    # Simulate baseline from stable version
    return @{
        ErrorRate = 0.005
        LatencyP95 = 100
        LatencyP99 = 130
        Throughput = 1000
    }
}

function Invoke-CanaryAnalysis {
    if (-not $CanaryId) {
        $CanaryId = "canary-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    }
    
    Write-Status "Analyzing canary: $CanaryId ($CanaryPercentage% traffic)"
    
    $canary = Get-CanaryMetrics -Id $CanaryId
    $baseline = Get-BaselineMetrics
    
    Write-Host ""
    Write-Host "Sample Size: $($canary.RequestCount) requests" -ForegroundColor Gray
    Write-Host ""
    
    $results = @()
    $violations = 0
    
    foreach ($metric in $CanaryConfig.Metrics) {
        $canaryValue = $canary.($metric.Name)
        $baselineValue = $baseline.($metric.Name)
        
        if ($metric.Comparison -eq "absolute") {
            $diff = $canaryValue - $baselineValue
            $isViolation = $canaryValue -gt $metric.Threshold
        } else {
            $ratio = $canaryValue / $baselineValue
            $diff = ($ratio - 1) * 100
            $isViolation = $ratio -gt $metric.Threshold
        }
        
        $results += @{
            Metric = $metric.Name
            Baseline = $baselineValue
            Canary = $canaryValue
            Diff = $diff
            IsViolation = $isViolation
        }
        
        if ($isViolation) { $violations++ }
    }
    
    Show-AnalysisResults -Results $results -Violations $violations
    
    $script:CanaryState.HealthScore = (($results.Count - $violations) / $results.Count) * 100
    $script:CanaryState.AnalysisComplete = $true
    
    if ($violations -eq 0) {
        Write-Success "Canary health check PASSED"
        
        if ($AutoPromote) {
            Invoke-CanaryPromotion -CanaryId $CanaryId
        }
    } else {
        Write-Alert "Canary health check FAILED - $violations violations detected"
    }
}

function Show-AnalysisResults {
    param($Results, $Violations)
    
    Write-Host "Canary Analysis Results:" -ForegroundColor White
    Write-Host "Metric      Baseline    Canary      Diff        Status" -ForegroundColor White
    Write-Host "------      --------    ------      ----        ------" -ForegroundColor White
    
    foreach ($r in $Results) {
        $status = if ($r.IsViolation) { "✗ FAIL" } else { "✓ PASS" }
        $color = if ($r.IsViolation) { "Red" } else { "Green" }
        
        $diffStr = if ($r.Diff -gt 0) { "+$([math]::Round($r.Diff, 2))" } else { "$([math]::Round($r.Diff, 2))" }
        
        Write-Host "$($r.Metric.PadRight(11)) $($r.Baseline.ToString().PadRight(11)) $($r.Canary.ToString().PadRight(11)) $($diffStr.PadRight(11)) $status" -ForegroundColor $color
    }
}

function Invoke-CanaryPromotion {
    param([string]$CanaryId)
    
    Write-Status "Promoting canary: $CanaryId"
    
    $currentPct = $CanaryPercentage
    
    foreach ($step in $CanaryConfig.PromotionSteps | Where-Object { $_ -gt $currentPct }) {
        Write-Status "Scaling to $step% traffic..."
        
        # Simulate promotion
        Start-Sleep -Seconds 2
        
        # Re-analyze at each step
        $metrics = Get-CanaryMetrics -Id $CanaryId
        if ($metrics.ErrorRate -gt $ErrorThreshold) {
            Write-Alert "Health check failed at $step% - rolling back"
            return
        }
        
        Write-Success "Successfully scaled to $step%"
    }
    
    Write-Success "Canary promotion complete - now at 100%"
}

function Set-CanaryBaseline {
    Write-Status "Setting new canary baseline..."
    
    $baseline = Get-BaselineMetrics
    $baseline.Timestamp = Get-Date -Format "o"
    $baseline.Version = "stable"
    
    $baseline | ConvertTo-Json -Depth 3 | Out-File "canary-baseline.json"
    
    Write-Success "Baseline saved"
}

function Compare-Canaries {
    Write-Status "Comparing multiple canary versions..."
    
    $canaries = @(
        @{ Id = "canary-v2.1"; Traffic = 5; ErrorRate = 0.008 }
        @{ Id = "canary-v2.2"; Traffic = 5; ErrorRate = 0.004 }
    )
    
    Write-Host ""
    Write-Host "Canary Comparison:" -ForegroundColor White
    Write-Host "Version      Traffic    Error Rate    Health" -ForegroundColor White
    Write-Host "-------      -------    ----------    ------" -ForegroundColor White
    
    foreach ($c in $canaries) {
        $health = if ($c.ErrorRate -lt $ErrorThreshold) { "✓ Healthy" } else { "✗ Degraded" }
        $color = if ($c.ErrorRate -lt $ErrorThreshold) { "Green" } else { "Red" }
        
        Write-Host "$($c.Id.PadRight(12)) $($c.Traffic.ToString().PadRight(9)) $($c.ErrorRate.ToString().PadRight(12)) $health" -ForegroundColor $color
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Canary Analysis" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host ""
    
    switch ($Action) {
        "analyze" { Invoke-CanaryAnalysis }
        "baseline" { Set-CanaryBaseline }
        "compare" { Compare-Canaries }
        "promote" { Invoke-CanaryPromotion -CanaryId $CanaryId }
    }
    
    Write-Host ""
    Write-Success "Canary analysis complete!"
}

Main
