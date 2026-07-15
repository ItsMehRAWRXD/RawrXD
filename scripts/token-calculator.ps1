# RawrXD Token Calculator
# Calculates tokens and estimates costs

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Count", "Estimate", "Compare", "Budget")]
    [string]$Action = "Count",
    
    [string]$Text = "",
    [string]$FilePath = "",
    [string]$Model = "gpt-3.5-turbo",
    [int]$InputTokens = 0,
    [int]$OutputTokens = 0,
    [int]$RequestsPerDay = 1000,
    [ValidateSet("gpt-3.5-turbo", "gpt-4", "gpt-4-turbo", "claude-3-haiku", "claude-3-sonnet", "claude-3-opus")]
    [string]$PricingModel = "gpt-3.5-turbo"
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

function Get-ModelPricing {
    return @{
        "gpt-3.5-turbo" = @{ Input = 0.0005; Output = 0.0015; Name = "GPT-3.5 Turbo" }
        "gpt-4" = @{ Input = 0.03; Output = 0.06; Name = "GPT-4" }
        "gpt-4-turbo" = @{ Input = 0.01; Output = 0.03; Name = "GPT-4 Turbo" }
        "claude-3-haiku" = @{ Input = 0.00025; Output = 0.00125; Name = "Claude 3 Haiku" }
        "claude-3-sonnet" = @{ Input = 0.003; Output = 0.015; Name = "Claude 3 Sonnet" }
        "claude-3-opus" = @{ Input = 0.015; Output = 0.075; Name = "Claude 3 Opus" }
    }
}

function Estimate-TokenCount {
    param([string]$InputText)
    
    # Rough estimation: ~4 characters per token on average
    $charCount = $InputText.Length
    $wordCount = ($InputText -split '\s+').Count
    
    # More accurate estimation
    $estimatedTokens = [math]::Ceiling($charCount / 4)
    
    return [PSCustomObject]@{
        Characters = $charCount
        Words = $wordCount
        EstimatedTokens = $estimatedTokens
        EstimatedTokensHigh = [math]::Ceiling($charCount / 3.5)
        EstimatedTokensLow = [math]::Ceiling($charCount / 4.5)
    }
}

function Show-TokenCount {
    param([string]$InputText)
    
    $estimate = Estimate-TokenCount -InputText $InputText
    
    Write-Host ""
    Write-Host "Token Estimate" -ForegroundColor Cyan
    Write-Host "=============" -ForegroundColor Cyan
    Write-Host "  Characters: $($estimate.Characters)"
    Write-Host "  Words: $($estimate.Words)"
    Write-Host "  Estimated Tokens: $($estimate.EstimatedTokens)"
    Write-Host "  Range: $($estimate.EstimatedTokensLow) - $($estimate.EstimatedTokensHigh)"
    Write-Host ""
    
    # Context window comparison
    $contextWindows = @{
        "4K" = 4096
        "8K" = 8192
        "16K" = 16384
        "32K" = 32768
        "100K" = 100000
        "200K" = 200000
    }
    
    Write-Host "Context Window Fit" -ForegroundColor Yellow
    foreach ($window in $contextWindows.GetEnumerator()) {
        $percent = [math]::Round($estimate.EstimatedTokens / $window.Value * 100, 1)
        $status = if ($percent -gt 100) { "EXCEEDS" } else { "$percent%" }
        $color = if ($percent -gt 100) { "Red" } elseif ($percent -gt 75) { "Yellow" } else { "Green" }
        Write-Host "  $($window.Key.PadRight(6)): $status" -ForegroundColor $color
    }
}

function Calculate-CostEstimate {
    param([int]$InputTok, [int]$OutputTok, [string]$ModelName)
    
    $pricing = Get-ModelPricing
    $modelPrice = $pricing[$ModelName]
    
    if (-not $modelPrice) {
        Write-Error "Unknown model: $ModelName"
        return
    }
    
    $inputCost = ($InputTok / 1000) * $modelPrice.Input
    $outputCost = ($OutputTok / 1000) * $modelPrice.Output
    $totalCost = $inputCost + $outputCost
    
    return [PSCustomObject]@{
        Model = $modelPrice.Name
        InputTokens = $InputTok
        OutputTokens = $OutputTok
        InputCost = $inputCost
        OutputCost = $outputCost
        TotalCost = $totalCost
        InputRate = $modelPrice.Input
        OutputRate = $modelPrice.Output
    }
}

function Show-CostEstimate {
    param([int]$InputTok, [int]$OutputTok, [string]$ModelName)
    
    $estimate = Calculate-CostEstimate -InputTok $InputTok -OutputTok $OutputTok -ModelName $ModelName
    
    Write-Host ""
    Write-Host "Cost Estimate" -ForegroundColor Cyan
    Write-Host "=============" -ForegroundColor Cyan
    Write-Host "  Model: $($estimate.Model)"
    Write-Host "  Input Tokens: $($estimate.InputTokens)"
    Write-Host "  Output Tokens: $($estimate.OutputTokens)"
    Write-Host ""
    Write-Host "  Pricing (per 1K tokens):" -ForegroundColor Yellow
    Write-Host "    Input: `$$($estimate.InputRate)"
    Write-Host "    Output: `$$($estimate.OutputRate)"
    Write-Host ""
    Write-Host "  Cost Breakdown:" -ForegroundColor Yellow
    Write-Host "    Input Cost: `$$([math]::Round($estimate.InputCost, 6))"
    Write-Host "    Output Cost: `$$([math]::Round($estimate.OutputCost, 6))"
    Write-Host "    Total Cost: `$$([math]::Round($estimate.TotalCost, 6))" -ForegroundColor Green
}

function Compare-ModelCosts {
    param([int]$InputTok, [int]$OutputTok)
    
    $pricing = Get-ModelPricing
    
    Write-Host ""
    Write-Host "Model Cost Comparison" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host "  Input: $InputTok tokens | Output: $OutputTok tokens"
    Write-Host ""
    
    $comparisons = @()
    foreach ($model in $pricing.GetEnumerator()) {
        $cost = Calculate-CostEstimate -InputTok $InputTok -OutputTok $OutputTok -ModelName $model.Key
        $comparisons += $cost
    }
    
    Write-Host "  Model                    Input Cost    Output Cost    Total Cost"
    Write-Host "  " + "-" * 65
    
    foreach ($comp in $comparisons | Sort-Object TotalCost) {
        $inCost = "`$$([math]::Round($comp.InputCost, 6))".PadRight(13)
        $outCost = "`$$([math]::Round($comp.OutputCost, 6))".PadRight(14)
        $totalCost = "`$$([math]::Round($comp.TotalCost, 6))"
        Write-Host "  $($comp.Model.PadRight(24)) $inCost $outCost $totalCost"
    }
}

function Show-BudgetProjection {
    param([int]$DailyRequests, [int]$AvgInputTokens, [int]$AvgOutputTokens, [string]$ModelName)
    
    $perRequest = Calculate-CostEstimate -InputTok $AvgInputTokens -OutputTok $AvgOutputTokens -ModelName $ModelName
    $dailyCost = $perRequest.TotalCost * $DailyRequests
    $monthlyCost = $dailyCost * 30
    $yearlyCost = $dailyCost * 365
    
    Write-Host ""
    Write-Host "Budget Projection" -ForegroundColor Cyan
    Write-Host "=================" -ForegroundColor Cyan
    Write-Host "  Model: $($perRequest.Model)"
    Write-Host "  Daily Requests: $DailyRequests"
    Write-Host "  Avg Input/Request: $AvgInputTokens tokens"
    Write-Host "  Avg Output/Request: $AvgOutputTokens tokens"
    Write-Host ""
    Write-Host "  Cost Projections:" -ForegroundColor Yellow
    Write-Host "    Per Request: `$$([math]::Round($perRequest.TotalCost, 6))"
    Write-Host "    Daily: `$$([math]::Round($dailyCost, 2))"
    Write-Host "    Monthly: `$$([math]::Round($monthlyCost, 2))"
    Write-Host "    Yearly: `$$([math]::Round($yearlyCost, 2))"
    Write-Host ""
    
    # Budget tiers
    Write-Host "  Budget Tiers (Monthly):" -ForegroundColor Yellow
    $tiers = @(10, 50, 100, 500, 1000, 5000)
    foreach ($tier in $tiers) {
        $requestsAtTier = [math]::Floor($tier / $perRequest.TotalCost / 30)
        $status = if ($monthlyCost -le $tier) { "✓ Within budget" } else { "✗ Exceeds budget" }
        $color = if ($monthlyCost -le $tier) { "Green" } else { "Red" }
        Write-Host "    `$$tier/month: ~$requestsAtTier requests/day $status" -ForegroundColor $color
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Token Calculator" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host ""
    
    # Load text from file if specified
    if ($FilePath -and (Test-Path $FilePath)) {
        $Text = Get-Content $FilePath -Raw
    }
    
    switch ($Action) {
        "Count" {
            if (-not $Text) {
                Write-Error "No text provided. Use -Text or -FilePath"
                return
            }
            Show-TokenCount -InputText $Text
        }
        "Estimate" {
            if ($InputTokens -eq 0) {
                Write-Error "Specify -InputTokens"
                return
            }
            if ($OutputTokens -eq 0) {
                $OutputTokens = [math]::Floor($InputTokens * 0.5)
                Write-Warning "Output tokens not specified, estimating as 50% of input"
            }
            Show-CostEstimate -InputTok $InputTokens -OutputTok $OutputTokens -ModelName $PricingModel
        }
        "Compare" {
            if ($InputTokens -eq 0) {
                $InputTokens = 1000
                Write-Warning "Using default: 1000 input tokens"
            }
            if ($OutputTokens -eq 0) {
                $OutputTokens = 500
                Write-Warning "Using default: 500 output tokens"
            }
            Compare-ModelCosts -InputTok $InputTokens -OutputTok $OutputTokens
        }
        "Budget" {
            if ($InputTokens -eq 0) { $InputTokens = 1000 }
            if ($OutputTokens -eq 0) { $OutputTokens = 500 }
            Show-BudgetProjection -DailyRequests $RequestsPerDay -AvgInputTokens $InputTokens -AvgOutputTokens $OutputTokens -ModelName $PricingModel
        }
    }
    
    Write-Host ""
}

Main
