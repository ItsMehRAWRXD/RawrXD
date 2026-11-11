#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase O.2: Customer Insights Engine
    
.DESCRIPTION
    Customer behavior analysis and health scoring for RawrXD SaaS.
    Identifies churn risks, expansion opportunities, and engagement patterns.
    
.PARAMETER Action
    Action to perform: score, health, churn, expansion
    
.PARAMETER TenantId
    Specific tenant to analyze
    
.EXAMPLE
    .\customer_insights.ps1 -Action score
    .\customer_insights.ps1 -Action health -TenantId "acme-corp"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("score", "health", "churn", "expansion", "segments")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\insights_data"
)

$ErrorActionPreference = "Stop"

# Health score weights
$HealthWeights = @{
    UsageFrequency = 0.30
    TokenGrowth = 0.25
    FeatureAdoption = 0.20
    SupportTickets = 0.15
    Uptime = 0.10
}

# Insights cache
$InsightsCache = @{
    LastUpdate = $null
    Scores = @{}
    Segments = @()
}

function Write-InsightsHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase O.2: Customer Insights Engine                               ║
║  Behavior analysis and health scoring for SaaS customers             ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-Insights {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $cacheFile = Join-Path $OutputPath "insights_cache.json"
    if (Test-Path $cacheFile) {
        $script:InsightsCache = Get-Content -Path $cacheFile -Raw | ConvertFrom-Json -AsHashtable
    }
}

function Save-Insights {
    $cacheFile = Join-Path $OutputPath "insights_cache.json"
    $script:InsightsCache.LastUpdate = Get-Date -Format "o"
    $script:InsightsCache | ConvertTo-Json -Depth 10 | Set-Content -Path $cacheFile
}

function Get-TenantData {
    $meteringPath = "..\saas\phase_m2_usage_metering\metering_data\usage_db.json"
    if (Test-Path $meteringPath) {
        $data = Get-Content -Path $meteringPath -Raw | ConvertFrom-Json -AsHashtable
        return $data.Tenants
    }
    return @{}
}

function Measure-CustomerHealth {
    param($TenantId)
    
    Write-Host "`nCalculating customer health scores..." -ForegroundColor Yellow
    
    $tenants = Get-TenantData
    $scores = @{
        GeneratedAt = Get-Date -Format "o"
        TenantScores = @()
        Summary = @{
            Healthy = 0
            AtRisk = 0
            Critical = 0
            AverageScore = 0
        }
    }
    
    $tenantList = if ($TenantId) { @($TenantId) } else { $tenants.Keys }
    
    foreach ($id in $tenantList) {
        if (-not $tenants.ContainsKey($id)) { continue }
        
        $tenant = $tenants[$id]
        
        # Calculate usage frequency score (0-100)
        $daysActive = $tenant.DailyUsage.Count
        $usageFreqScore = [math]::Min(100, $daysActive * 10)
        
        # Calculate token growth score
        $dailyTokens = $tenant.DailyUsage.GetEnumerator() | Sort-Object Key | ForEach-Object { $_.Value.Tokens }
        $growthScore = 50
        if ($dailyTokens.Count -ge 7) {
            $firstWeek = ($dailyTokens | Select-Object -First 7 | Measure-Object -Average).Average
            $lastWeek = ($dailyTokens | Select-Object -Last 7 | Measure-Object -Average).Average
            if ($firstWeek -gt 0) {
                $growth = (($lastWeek - $firstWeek) / $firstWeek) * 100
                $growthScore = [math]::Min(100, [math]::Max(0, 50 + ($growth / 2)))
            }
        }
        
        # Feature adoption (placeholder - would check feature usage)
        $featureScore = 75  # Default to good
        
        # Support tickets (lower is better)
        $supportScore = 90  # Default to good
        
        # Uptime (placeholder)
        $uptimeScore = 99
        
        # Calculate weighted health score
        $healthScore = [math]::Round(
            ($usageFreqScore * $HealthWeights.UsageFrequency) +
            ($growthScore * $HealthWeights.TokenGrowth) +
            ($featureScore * $HealthWeights.FeatureAdoption) +
            ($supportScore * $HealthWeights.SupportTickets) +
            ($uptimeScore * $HealthWeights.Uptime),
            2
        )
        
        # Determine health status
        $status = if ($healthScore -ge 80) { "healthy" } elseif ($healthScore -ge 60) { "at-risk" } else { "critical" }
        
        $scores.TenantScores += @{
            TenantId = $id
            Tier = $tenant.Tier
            HealthScore = $healthScore
            Status = $status
            Components = @{
                UsageFrequency = $usageFreqScore
                TokenGrowth = $growthScore
                FeatureAdoption = $featureScore
                SupportTickets = $supportScore
                Uptime = $uptimeScore
            }
            LastActivity = ($tenant.DailyUsage.GetEnumerator() | Sort-Object Key -Descending | Select-Object -First 1).Key
        }
        
        $scores.Summary.$status++
    }
    
    # Calculate average
    if ($scores.TenantScores.Count -gt 0) {
        $scores.Summary.AverageScore = [math]::Round(($scores.TenantScores | Measure-Object -Property HealthScore -Average).Average, 2)
    }
    
    $script:InsightsCache.Scores = $scores
    Save-Insights
    
    return $scores
}

function Show-HealthScores {
    param($Scores)
    
    Write-Host "`nCustomer Health Report" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    
    Write-Host "`nSummary:" -ForegroundColor Yellow
    Write-Host "  Total Scored:    $($Scores.TenantScores.Count)" -ForegroundColor Gray
    Write-Host "  Average Score:   $($Scores.Summary.AverageScore)" -ForegroundColor Gray
    Write-Host "  Healthy:         $($Scores.Summary.Healthy)" -ForegroundColor Green
    Write-Host "  At Risk:         $($Scores.Summary.AtRisk)" -ForegroundColor Yellow
    Write-Host "  Critical:        $($Scores.Summary.Critical)" -ForegroundColor Red
    
    Write-Host "`nHealth Distribution:" -ForegroundColor Yellow
    foreach ($tenant in ($Scores.TenantScores | Sort-Object HealthScore -Descending)) {
        $color = switch ($tenant.Status) {
            "healthy" { "Green" }
            "at-risk" { "Yellow" }
            "critical" { "Red" }
        }
        $bar = "█" * [math]::Floor($tenant.HealthScore / 5)
        Write-Host "  $($tenant.TenantId.PadEnd(20)) [$($bar.PadRight(20))] $($tenant.HealthScore) [$($tenant.Status)]" -ForegroundColor $color
    }
}

function Identify-ChurnRisk {
    Write-Host "`nAnalyzing churn risk..." -ForegroundColor Yellow
    
    $tenants = Get-TenantData
    $churnRisks = @()
    
    foreach ($tenant in $tenants.GetEnumerator()) {
        $riskFactors = @()
        $riskScore = 0
        
        # Check for declining usage
        $dailyTokens = $tenant.Value.DailyUsage.GetEnumerator() | Sort-Object Key | ForEach-Object { $_.Value.Tokens }
        if ($dailyTokens.Count -ge 14) {
            $firstWeek = ($dailyTokens | Select-Object -First 7 | Measure-Object -Average).Average
            $lastWeek = ($dailyTokens | Select-Object -Last 7 | Measure-Object -Average).Average
            if ($firstWeek -gt 0 -and $lastWeek -lt $firstWeek * 0.5) {
                $riskFactors += "Usage declined >50%"
                $riskScore += 40
            }
        }
        
        # Check for inactivity
        $lastActivity = ($tenant.Value.DailyUsage.GetEnumerator() | Sort-Object Key -Descending | Select-Object -First 1).Key
        if ($lastActivity) {
            $daysSince = ([DateTime]::Now - [DateTime]::Parse($lastActivity)).Days
            if ($daysSince -gt 7) {
                $riskFactors += "Inactive for $daysSince days"
                $riskScore += 30
            }
        }
        
        # Check quota utilization
        $tokenPercent = ($tenant.Value.Usage.TokensThisMonth / $tenant.Value.Quota.MaxTokensPerMinute) * 100
        if ($tokenPercent -lt 10) {
            $riskFactors += "Low quota utilization ($([math]::Round($tokenPercent, 1))%)"
            $riskScore += 20
        }
        
        if ($riskScore -gt 0) {
            $churnRisks += @{
                TenantId = $tenant.Key
                RiskScore = $riskScore
                RiskLevel = if ($riskScore -ge 70) { "high" } elseif ($riskScore -ge 40) { "medium" } else { "low" }
                Factors = $riskFactors
                LastActivity = $lastActivity
            }
        }
    }
    
    return $churnRisks | Sort-Object RiskScore -Descending
}

function Show-ChurnRisks {
    param($Risks)
    
    Write-Host "`nChurn Risk Analysis" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    
    if ($Risks.Count -eq 0) {
        Write-Host "`n  No churn risks identified! 🎉" -ForegroundColor Green
        return
    }
    
    Write-Host "`nTenants at risk of churning:" -ForegroundColor Yellow
    
    foreach ($risk in $Risks) {
        $color = switch ($risk.RiskLevel) {
            "high" { "Red" }
            "medium" { "Yellow" }
            "low" { "Gray" }
        }
        
        Write-Host "`n  $($risk.TenantId) [Risk: $($risk.RiskLevel.ToUpper()) - $($risk.RiskScore)]" -ForegroundColor $color
        foreach ($factor in $risk.Factors) {
            Write-Host "    • $factor" -ForegroundColor Gray
        }
    }
    
    Write-Host "`nTotal at-risk tenants: $($Risks.Count)" -ForegroundColor Cyan
}

function Identify-ExpansionOpportunities {
    Write-Host "`nIdentifying expansion opportunities..." -ForegroundColor Yellow
    
    $tenants = Get-TenantData
    $opportunities = @()
    
    foreach ($tenant in $tenants.GetEnumerator()) {
        $signals = @()
        $score = 0
        
        # High quota utilization
        $tokenPercent = ($tenant.Value.Usage.TokensThisMonth / $tenant.Value.Quota.MaxTokensPerMinute) * 100
        if ($tokenPercent -gt 80) {
            $signals += "High quota utilization ($([math]::Round($tokenPercent, 1))%)"
            $score += 30
        }
        
        # Growing usage
        $dailyTokens = $tenant.Value.DailyUsage.GetEnumerator() | Sort-Object Key | ForEach-Object { $_.Value.Tokens }
        if ($dailyTokens.Count -ge 7) {
            $firstWeek = ($dailyTokens | Select-Object -First 7 | Measure-Object -Average).Average
            $lastWeek = ($dailyTokens | Select-Object -Last 7 | Measure-Object -Average).Average
            if ($firstWeek -gt 0 -and $lastWeek -gt $firstWeek * 1.5) {
                $signals += "Growing usage (>50% increase)"
                $score += 25
            }
        }
        
        # Daily active usage
        if ($tenant.Value.DailyUsage.Count -ge 20) {
            $signals += "Highly active (20+ days)"
            $score += 20
        }
        
        # Standard tier with high usage (upgrade candidate)
        if ($tenant.Value.Tier -eq "standard" -and $tokenPercent -gt 70) {
            $signals += "Upgrade candidate (Standard → Enterprise)"
            $score += 25
        }
        
        if ($score -gt 0) {
            $opportunities += @{
                TenantId = $tenant.Key
                CurrentTier = $tenant.Value.Tier
                Score = $score
                Priority = if ($score -ge 70) { "high" } elseif ($score -ge 40) { "medium" } else { "low" }
                Signals = $signals
            }
        }
    }
    
    return $opportunities | Sort-Object Score -Descending
}

function Show-ExpansionOpportunities {
    param($Opportunities)
    
    Write-Host "`nExpansion Opportunities" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    
    if ($Opportunities.Count -eq 0) {
        Write-Host "`n  No expansion opportunities identified" -ForegroundColor Gray
        return
    }
    
    Write-Host "`nPotential upsells and expansions:" -ForegroundColor Yellow
    
    foreach ($opp in $Opportunities) {
        $color = switch ($opp.Priority) {
            "high" { "Green" }
            "medium" { "Cyan" }
            "low" { "Gray" }
        }
        
        Write-Host "`n  $($opp.TenantId) [Priority: $($opp.Priority.ToUpper())]" -ForegroundColor $color
        Write-Host "    Current Tier: $($opp.CurrentTier)" -ForegroundColor Gray
        foreach ($signal in $opp.Signals) {
            Write-Host "    ✓ $signal" -ForegroundColor Gray
        }
    }
    
    Write-Host "`nTotal opportunities: $($Opportunities.Count)" -ForegroundColor Cyan
}

function Get-CustomerSegments {
    Write-Host "`nAnalyzing customer segments..." -ForegroundColor Yellow
    
    $tenants = Get-TenantData
    $segments = @{
        PowerUsers = @()
        RegularUsers = @()
        LightUsers = @()
        AtRisk = @()
        Champions = @()
    }
    
    foreach ($tenant in $tenants.GetEnumerator()) {
        $totalTokens = $tenant.Value.TotalTokens
        $daysActive = $tenant.Value.DailyUsage.Count
        
        # Segment classification
        if ($totalTokens -gt 1000000 -and $daysActive -gt 20) {
            $segments.PowerUsers += $tenant.Key
        } elseif ($totalTokens -gt 100000 -and $daysActive -gt 10) {
            $segments.RegularUsers += $tenant.Key
        } else {
            $segments.LightUsers += $tenant.Key
        }
        
        # Champions (high usage + long tenure)
        if ($totalTokens -gt 500000 -and $daysActive -gt 25) {
            $segments.Champions += $tenant.Key
        }
    }
    
    $script:InsightsCache.Segments = $segments
    Save-Insights
    
    return $segments
}

function Show-CustomerSegments {
    param($Segments)
    
    Write-Host "`nCustomer Segments" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    
    Write-Host "`nSegment Distribution:" -ForegroundColor Yellow
    Write-Host "  Champions:     $($Segments.Champions.Count) tenants" -ForegroundColor Green
    Write-Host "  Power Users:   $($Segments.PowerUsers.Count) tenants" -ForegroundColor Cyan
    Write-Host "  Regular Users: $($Segments.RegularUsers.Count) tenants" -ForegroundColor Gray
    Write-Host "  Light Users:   $($Segments.LightUsers.Count) tenants" -ForegroundColor DarkGray
    
    if ($Segments.Champions.Count -gt 0) {
        Write-Host "`nChampion Customers:" -ForegroundColor Yellow
        foreach ($champion in $Segments.Champions) {
            Write-Host "  ⭐ $champion" -ForegroundColor Green
        }
    }
}

# Main execution
Write-InsightsHeader
Initialize-Insights

switch ($Action) {
    "score" {
        $scores = Measure-CustomerHealth -TenantId $TenantId
        Show-HealthScores -Scores $scores
    }
    "health" {
        $scores = Measure-CustomerHealth -TenantId $TenantId
        Show-HealthScores -Scores $scores
    }
    "churn" {
        $risks = Identify-ChurnRisk
        Show-ChurnRisks -Risks $risks
    }
    "expansion" {
        $opportunities = Identify-ExpansionOpportunities
        Show-ExpansionOpportunities -Opportunities $opportunities
    }
    "segments" {
        $segments = Get-CustomerSegments
        Show-CustomerSegments -Segments $segments
    }
}

Write-Host "`n✅ Customer insights operation complete" -ForegroundColor Green
