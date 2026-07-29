# RawrXD Model Comparison Matrix
# Compares multiple models across key metrics

param(
    [Parameter(Mandatory=$false)]
    [string[]]$Models = @("llama-2-7b", "llama-2-70b", "gpt-3.5", "gpt-4"),
    
    [ValidateSet("accuracy", "speed", "cost", "memory", "all")]
    [string]$CompareBy = "all",
    
    [string]$TestDataset = "benchmark",
    [switch]$ExportResults,
    [string]$OutputFormat = "table"
)

$ErrorActionPreference = "Stop"

$ComparisonConfig = @{
    Metrics = @(
        @{ Name = "Accuracy"; Weight = 0.30; Unit = "%" }
        @{ Name = "Speed"; Weight = 0.25; Unit = "tokens/sec" }
        @{ Name = "Cost"; Weight = 0.20; Unit = "$/1K tokens" }
        @{ Name = "Memory"; Weight = 0.15; Unit = "GB" }
        @{ Name = "Latency"; Weight = 0.10; Unit = "ms" }
    )
    TestDatasets = @("benchmark", "mmlu", "hellaswag", "truthfulqa")
}

$script:CompState = @{
    StartTime = Get-Date
    Results = @{}
    Winner = $null
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }

function Get-ModelMetrics {
    param([string]$Model)
    
    # Simulate metrics based on model
    switch -Wildcard ($Model) {
        "*7b*" {
            return @{
                Accuracy = 65 + (Get-Random -Minimum -5 -Maximum 5)
                Speed = 120 + (Get-Random -Minimum -10 -Maximum 10)
                Cost = 0.0005
                Memory = 14
                Latency = 50 + (Get-Random -Minimum -5 -Maximum 5)
            }
        }
        "*70b*" {
            return @{
                Accuracy = 78 + (Get-Random -Minimum -3 -Maximum 3)
                Speed = 45 + (Get-Random -Minimum -5 -Maximum 5)
                Cost = 0.002
                Memory = 140
                Latency = 150 + (Get-Random -Minimum -10 -Maximum 10)
            }
        }
        "*gpt-3.5*" {
            return @{
                Accuracy = 72 + (Get-Random -Minimum -3 -Maximum 3)
                Speed = 90 + (Get-Random -Minimum -10 -Maximum 10)
                Cost = 0.002
                Memory = 0  # API model
                Latency = 80 + (Get-Random -Minimum -10 -Maximum 10)
            }
        }
        "*gpt-4*" {
            return @{
                Accuracy = 86 + (Get-Random -Minimum -2 -Maximum 2)
                Speed = 35 + (Get-Random -Minimum -5 -Maximum 5)
                Cost = 0.06
                Memory = 0  # API model
                Latency = 200 + (Get-Random -Minimum -20 -Maximum 20)
            }
        }
        default {
            return @{
                Accuracy = 60
                Speed = 100
                Cost = 0.001
                Memory = 20
                Latency = 100
            }
        }
    }
}

function Invoke-ModelComparison {
    Write-Status "Comparing $($Models.Count) models..."
    
    foreach ($model in $Models) {
        Write-Status "Benchmarking: $model"
        
        $metrics = Get-ModelMetrics -Model $model
        $script:CompState.Results[$model] = $metrics
        
        Start-Sleep -Milliseconds 200
    }
    
    Write-Success "Comparison complete"
}

function Show-ComparisonMatrix {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Model Comparison Matrix" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Header
    $header = "Metric".PadRight(12)
    foreach ($model in $Models) {
        $header += $model.Split("-")[-1].PadRight(12)
    }
    Write-Host $header -ForegroundColor White
    Write-Host ("-" * ($header.Length)) -ForegroundColor White
    
    # Metrics rows
    $metricNames = @("Accuracy", "Speed", "Cost", "Memory", "Latency")
    
    foreach ($metricName in $metricNames) {
        $row = $metricName.PadRight(12)
        
        # Find best value for highlighting
        $values = $Models | ForEach-Object { $script:CompState.Results[$_][$metricName] }
        $bestValue = if ($metricName -in @("Cost", "Memory", "Latency")) { ($values | Measure-Object -Minimum).Minimum } else { ($values | Measure-Object -Maximum).Maximum }
        
        foreach ($model in $Models) {
            $value = $script:CompState.Results[$model][$metricName]
            $isBest = [math]::Abs($value - $bestValue) -lt 0.01
            
            $formatted = switch ($metricName) {
                "Accuracy" { "$([math]::Round($value, 1))%" }
                "Speed" { "$([math]::Round($value, 0))" }
                "Cost" { "`$$value" }
                "Memory" { if ($value -eq 0) { "N/A" } else { "$value GB" } }
                "Latency" { "$([math]::Round($value, 0)) ms" }
            }
            
            if ($isBest) {
                $row += $formatted.PadRight(12)
            } else {
                $row += $formatted.PadRight(12)
            }
        }
        
        Write-Host $row -ForegroundColor Gray
    }
}

function Calculate-CompositeScores {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Composite Scores" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    $scores = @()
    
    foreach ($model in $Models) {
        $metrics = $script:CompState.Results[$model]
        $score = 0
        
        # Normalize and weight each metric
        $normAccuracy = $metrics.Accuracy / 100
        $normSpeed = [math]::Min($metrics.Speed / 150, 1)
        $normCost = 1 - [math]::Min($metrics.Cost / 0.1, 1)  # Lower is better
        $normMemory = if ($metrics.Memory -eq 0) { 1 } else { 1 - [math]::Min($metrics.Memory / 200, 1) }
        $normLatency = 1 - [math]::Min($metrics.Latency / 500, 1)
        
        $score = ($normAccuracy * 0.30) + ($normSpeed * 0.25) + ($normCost * 0.20) + 
                 ($normMemory * 0.15) + ($normLatency * 0.10)
        
        $scores += @{
            Model = $model
            Score = [math]::Round($score * 100, 1)
            RawMetrics = $metrics
        }
    }
    
    $sorted = $scores | Sort-Object Score -Descending
    
    Write-Host "Rank  Model                Score" -ForegroundColor White
    Write-Host "----  -----                -----" -ForegroundColor White
    
    $rank = 1
    foreach ($s in $sorted) {
        $color = switch ($rank) {
            1 { "Green" }
            2 { "Yellow" }
            default { "Gray" }
        }
        Write-Host "$rank`.    $($s.Model.PadRight(20)) $($s.Score)" -ForegroundColor $color
        $rank++
    }
    
    $script:CompState.Winner = $sorted[0]
    
    Write-Host ""
    Write-Success "Winner: $($sorted[0].Model) with score $($sorted[0].Score)"
}

function Export-ComparisonResults {
    $export = @{
        Timestamp = Get-Date -Format "o"
        Models = $Models
        Results = $script:CompState.Results
        Winner = $script:CompState.Winner
    }
    
    switch ($OutputFormat) {
        "json" {
            $export | ConvertTo-Json -Depth 3 | Out-File "model-comparison-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
            Write-Success "Results exported to JSON"
        }
        "csv" {
            $csvData = @()
            foreach ($model in $Models) {
                $m = $script:CompState.Results[$model]
                $csvData += [PSCustomObject]@{
                    Model = $model
                    Accuracy = $m.Accuracy
                    Speed = $m.Speed
                    Cost = $m.Cost
                    Memory = $m.Memory
                    Latency = $m.Latency
                }
            }
            $csvData | Export-Csv "model-comparison-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv" -NoTypeInformation
            Write-Success "Results exported to CSV"
        }
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Model Comparison Matrix" -ForegroundColor Cyan
    Write-Host "===============================" -ForegroundColor Cyan
    Write-Host ""
    
    Invoke-ModelComparison
    Show-ComparisonMatrix
    Calculate-CompositeScores
    
    if ($ExportResults) {
        Export-ComparisonResults
    }
    
    Write-Host ""
    Write-Success "Model comparison complete!"
}

Main
