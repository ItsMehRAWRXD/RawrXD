# RawrXD A/B Testing Framework
# Statistical A/B testing for model variants and configurations

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("create", "run", "analyze", "report")]
    [string]$Action = "create",
    
    [string]$TestName,
    [string]$VariantA,
    [string]$VariantB,
    [int]$SampleSize = 1000,
    [double]$ConfidenceLevel = 0.95,
    [string]$Metric = "accuracy", # accuracy, latency, throughput, perplexity
    [switch]$AutoStop,
    [string]$OutputDir = "ab-tests"
)

$ErrorActionPreference = "Stop"

$ABConfig = @{
    ConfidenceLevels = @{
        0.90 = @{ ZScore = 1.645 }
        0.95 = @{ ZScore = 1.96 }
        0.99 = @{ ZScore = 2.576 }
    }
    MinSampleSize = 100
    MaxSampleSize = 100000
    EarlyStoppingThreshold = 0.99
}

$script:ABState = @{
    StartTime = Get-Date
    CurrentTest = $null
    Results = @()
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }

function New-ABTest {
    if (-not $TestName) {
        $TestName = "ab-test-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    }
    
    Write-Status "Creating A/B test: $TestName"
    
    $test = @{
        Name = $TestName
        VariantA = if ($VariantA) { $VariantA } else { "control" }
        VariantB = if ($VariantB) { $VariantB } else { "treatment" }
        SampleSize = $SampleSize
        ConfidenceLevel = $ConfidenceLevel
        Metric = $Metric
        CreatedAt = Get-Date
        Status = "created"
        Results = @{
            A = @()
            B = @()
        }
    }
    
    $script:ABState.CurrentTest = $test
    
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
    
    $test | ConvertTo-Json -Depth 3 | Out-File "$OutputDir\$TestName.json"
    
    Write-Host ""
    Write-Host "A/B Test Created:" -ForegroundColor White
    Write-Host "  Name: $TestName" -ForegroundColor Gray
    Write-Host "  Variant A: $($test.VariantA)" -ForegroundColor Gray
    Write-Host "  Variant B: $($test.VariantB)" -ForegroundColor Gray
    Write-Host "  Sample Size: $SampleSize" -ForegroundColor Gray
    Write-Host "  Confidence: $($ConfidenceLevel * 100)%" -ForegroundColor Gray
    Write-Host "  Metric: $Metric" -ForegroundColor Gray
    
    Write-Success "Test configuration saved"
}

function Invoke-ABTest {
    if (-not $TestName) {
        Write-Error "TestName required for running test"
        return
    }
    
    $testFile = "$OutputDir\$TestName.json"
    if (-not (Test-Path $testFile)) {
        Write-Error "Test not found: $TestName"
        return
    }
    
    $test = Get-Content $testFile | ConvertFrom-Json
    Write-Status "Running A/B test: $TestName"
    
    $resultsA = @()
    $resultsB = @()
    
    for ($i = 0; $i -lt $test.SampleSize; $i++) {
        Write-Progress -Activity "A/B Testing" -Status "Sample $i of $($test.SampleSize)" -PercentComplete (($i / $test.SampleSize) * 100)
        
        # Simulate measurements
        switch ($test.Metric) {
            "accuracy" {
                $resultsA += (Get-Random -Minimum 85 -Maximum 95) / 100
                $resultsB += (Get-Random -Minimum 87 -Maximum 97) / 100
            }
            "latency" {
                $resultsA += Get-Random -Minimum 80 -Maximum 120
                $resultsB += Get-Random -Minimum 75 -Maximum 115
            }
            "throughput" {
                $resultsA += Get-Random -Minimum 100 -Maximum 150
                $resultsB += Get-Random -Minimum 110 -Maximum 160
            }
            "perplexity" {
                $resultsA += Get-Random -Minimum 2 -Maximum 5
                $resultsB += Get-Random -Minimum 1.8 -Maximum 4.5
            }
        }
        
        # Early stopping check
        if ($AutoStop -and $i -gt $ABConfig.MinSampleSize -and ($i % 100 -eq 0)) {
            $significance = Test-Significance -ResultsA $resultsA -ResultsB $resultsB -Confidence $test.ConfidenceLevel
            if ($significance.Confidence -gt $ABConfig.EarlyStoppingThreshold) {
                Write-Status "Early stopping triggered at sample $i"
                break
            }
        }
    }
    
    Write-Progress -Activity "A/B Testing" -Completed
    
    $test.Results.A = $resultsA
    $test.Results.B = $resultsB
    $test.Status = "completed"
    $test.CompletedAt = Get-Date
    
    $test | ConvertTo-Json -Depth 5 | Out-File $testFile
    
    Write-Success "Test completed"
}

function Test-Significance {
    param($ResultsA, $ResultsB, $Confidence)
    
    $meanA = ($ResultsA | Measure-Object -Average).Average
    $meanB = ($ResultsB | Measure-Object -Average).Average
    $stdA = [math]::Sqrt(($ResultsA | ForEach-Object { [math]::Pow($_ - $meanA, 2) } | Measure-Object -Average).Average)
    $stdB = [math]::Sqrt(($ResultsB | ForEach-Object { [math]::Pow($_ - $meanB, 2) } | Measure-Object -Average).Average)
    
    $nA = $ResultsA.Count
    $nB = $ResultsB.Count
    
    $se = [math]::Sqrt(($stdA * $stdA / $nA) + ($stdB * $stdB / $nB))
    $zScore = ($meanB - $meanA) / $se
    
    $zCritical = $ABConfig.ConfidenceLevels[$Confidence].ZScore
    $isSignificant = [math]::Abs($zScore) -gt $zCritical
    
    $pValue = 2 * (1 - [math]::Min(1, [math]::Abs($zScore) / 10)) # Simplified
    
    return @{
        MeanA = [math]::Round($meanA, 4)
        MeanB = [math]::Round($meanB, 4)
        StdDevA = [math]::Round($stdA, 4)
        StdDevB = [math]::Round($stdB, 4)
        ZScore = [math]::Round($zScore, 4)
        PValue = [math]::Round($pValue, 4)
        IsSignificant = $isSignificant
        Confidence = if ($isSignificant) { $Confidence } else { 0 }
        Lift = [math]::Round((($meanB - $meanA) / $meanA) * 100, 2)
    }
}

function Show-ABReport {
    if (-not $TestName) {
        Write-Error "TestName required for report"
        return
    }
    
    $testFile = "$OutputDir\$TestName.json"
    if (-not (Test-Path $testFile)) {
        Write-Error "Test not found: $TestName"
        return
    }
    
    $test = Get-Content $testFile | ConvertFrom-Json
    
    if ($test.Status -ne "completed") {
        Write-Warning "Test not yet completed"
        return
    }
    
    $stats = Test-Significance -ResultsA $test.Results.A -ResultsB $test.Results.B -Confidence $test.ConfidenceLevel
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "A/B Test Report: $TestName" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Test Configuration:" -ForegroundColor White
    Write-Host "  Metric: $($test.Metric)" -ForegroundColor Gray
    Write-Host "  Sample Size: $($test.Results.A.Count)" -ForegroundColor Gray
    Write-Host "  Confidence Level: $($test.ConfidenceLevel * 100)%" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "Results:" -ForegroundColor White
    Write-Host "  Variant A ($($test.VariantA)):" -ForegroundColor Gray
    Write-Host "    Mean: $($stats.MeanA)" -ForegroundColor Gray
    Write-Host "    StdDev: $($stats.StdDevA)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Variant B ($($test.VariantB)):" -ForegroundColor Gray
    Write-Host "    Mean: $($stats.MeanB)" -ForegroundColor Gray
    Write-Host "    StdDev: $($stats.StdDevB)" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "Statistical Analysis:" -ForegroundColor White
    Write-Host "  Lift: $($stats.Lift)%" -ForegroundColor $(if($stats.Lift -gt 0){'Green'}else{'Red'})
    Write-Host "  Z-Score: $($stats.ZScore)" -ForegroundColor Gray
    Write-Host "  P-Value: $($stats.PValue)" -ForegroundColor Gray
    Write-Host "  Significant: $(if($stats.IsSignificant){'Yes ✓'}else{'No ✗'})" -ForegroundColor $(if($stats.IsSignificant){'Green'}else{'Red'})
    
    Write-Host ""
    if ($stats.IsSignificant) {
        $winner = if ($stats.MeanB -gt $stats.MeanA) { $test.VariantB } else { $test.VariantA }
        Write-Success "Winner: $winner with $($stats.Lift)% lift"
    } else {
        Write-Warning "No statistically significant difference detected"
    }
}

# Main execution
function Main {
    Write-Host "RawrXD A/B Testing Framework" -ForegroundColor Cyan
    Write-Host "============================" -ForegroundColor Cyan
    Write-Host ""
    
    switch ($Action) {
        "create" { New-ABTest }
        "run" { Invoke-ABTest }
        "analyze" { Show-ABReport }
        "report" { Show-ABReport }
    }
    
    Write-Host ""
    Write-Success "A/B Testing Framework complete!"
}

Main
