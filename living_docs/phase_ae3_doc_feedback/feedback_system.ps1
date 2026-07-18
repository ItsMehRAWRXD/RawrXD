#!/usr/bin/env pwsh
#requires -Version 7.0
# Phase AE.3: Documentation Feedback System
# Collects and acts on documentation feedback

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("submit", "review", "trends", "improve", "metrics")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [string]$DocPath,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("helpful", "confusing", "outdated", "missing")]
    [string]$FeedbackType,
    
    [Parameter(Mandatory=$false)]
    [string]$Comment,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\feedback"
)

$ErrorActionPreference = "Stop"

# Feedback registry
$FeedbackRegistry = @{
    Submissions = @()
    Metrics = @{
        TotalSubmissions = 0
        AverageRating = 0
        HelpfulCount = 0
        ConfusingCount = 0
        OutdatedCount = 0
        MissingCount = 0
    }
    Improvements = @()
    LastUpdated = $null
}

function Write-FeedbackHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase AE.3: Documentation Feedback System                         ║
║  Continuous improvement through user feedback                      ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-FeedbackSystem {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    # Load registry
    $registryFile = Join-Path $OutputPath "feedback_registry.json"
    if (Test-Path $registryFile) {
        $script:FeedbackRegistry = Get-Content -Path $registryFile -Raw | ConvertFrom-Json -AsHashtable
    }
}

function Save-FeedbackRegistry {
    $script:FeedbackRegistry.LastUpdated = Get-Date -Format "o"
    $registryFile = Join-Path $OutputPath "feedback_registry.json"
    $script:FeedbackRegistry | ConvertTo-Json -Depth 10 | Set-Content -Path $registryFile
}

function Submit-Feedback {
    param($DocPath, $Type, $Comment)
    
    $feedback = @{
        Id = [Guid]::NewGuid().ToString()
        DocPath = $DocPath
        Type = $Type
        Comment = $Comment
        SubmittedAt = Get-Date -Format "o"
        Status = "open"
    }
    
    $script:FeedbackRegistry.Submissions += $feedback
    $script:FeedbackRegistry.Metrics.TotalSubmissions++
    
    switch ($Type) {
        "helpful" { $script:FeedbackRegistry.Metrics.HelpfulCount++ }
        "confusing" { $script:FeedbackRegistry.Metrics.ConfusingCount++ }
        "outdated" { $script:FeedbackRegistry.Metrics.OutdatedCount++ }
        "missing" { $script:FeedbackRegistry.Metrics.MissingCount++ }
    }
    
    Save-FeedbackRegistry
    
    Write-Host "✓ Feedback submitted (ID: $($feedback.Id))" -ForegroundColor Green
    Write-Host "  Thank you for helping improve our documentation!" -ForegroundColor Gray
}

function Get-FeedbackReview {
    Write-Host "`nDocumentation Feedback Review" -ForegroundColor Yellow
    Write-Host ""
    
    $open = $script:FeedbackRegistry.Submissions | Where-Object { $_.Status -eq "open" }
    $closed = $script:FeedbackRegistry.Submissions | Where-Object { $_.Status -eq "closed" }
    
    Write-Host "Open Feedback: $($open.Count)" -ForegroundColor White
    foreach ($item in ($open | Select-Object -Last 5)) {
        Write-Host "  [$($item.Type)] $($item.DocPath)" -ForegroundColor $(
            switch ($item.Type) {
                "helpful" { "Green" }
                "confusing" { "Yellow" }
                "outdated" { "Red" }
                default { "Gray" }
            }
        )
        if ($item.Comment) {
            Write-Host "    \"$($item.Comment)\"" -ForegroundColor DarkGray
        }
    }
    
    Write-Host "`nClosed Feedback: $($closed.Count)" -ForegroundColor Gray
}

function Get-FeedbackTrends {
    Write-Host "`nDocumentation Feedback Trends" -ForegroundColor Yellow
    Write-Host ""
    
    $metrics = $script:FeedbackRegistry.Metrics
    
    Write-Host "Total Submissions: $($metrics.TotalSubmissions)" -ForegroundColor White
    Write-Host ""
    
    Write-Host "By Type:" -ForegroundColor Cyan
    Write-Host "  👍 Helpful: $($metrics.HelpfulCount)" -ForegroundColor Green
    Write-Host "  😕 Confusing: $($metrics.ConfusingCount)" -ForegroundColor Yellow
    Write-Host "  📝 Outdated: $($metrics.OutdatedCount)" -ForegroundColor Red
    Write-Host "  ❓ Missing: $($metrics.MissingCount)" -ForegroundColor Gray
    
    if ($metrics.TotalSubmissions -gt 0) {
        $helpfulRate = [math]::Round(($metrics.HelpfulCount / $metrics.TotalSubmissions) * 100, 1)
        Write-Host "`nHelpfulness Rate: $helpfulRate%" -ForegroundColor $(if ($helpfulRate -gt 70) { "Green" } else { "Yellow" })
    }
    
    # Recent trend
    $recent = $script:FeedbackRegistry.Submissions | Where-Object { 
        [DateTime]::Parse($_.SubmittedAt) -gt (Get-Date).AddDays(-7) 
    }
    Write-Host "`nLast 7 Days: $($recent.Count) submissions" -ForegroundColor White
}

function Get-ImprovementPlan {
    Write-Host "`nDocumentation Improvement Plan" -ForegroundColor Yellow
    Write-Host ""
    
    $confusing = $script:FeedbackRegistry.Submissions | Where-Object { $_.Type -eq "confusing" -and $_.Status -eq "open" }
    $outdated = $script:FeedbackRegistry.Submissions | Where-Object { $_.Type -eq "outdated" -and $_.Status -eq "open" }
    $missing = $script:FeedbackRegistry.Submissions | Where-Object { $_.Type -eq "missing" -and $_.Status -eq "open" }
    
    if ($confusing.Count -gt 0) {
        Write-Host "Priority 1: Clarify Confusing Documentation" -ForegroundColor Red
        $grouped = $confusing | Group-Object -Property DocPath | Sort-Object Count -Descending
        foreach ($g in ($grouped | Select-Object -First 3)) {
            Write-Host "  - $($g.Name) ($($g.Count) reports)" -ForegroundColor Gray
        }
    }
    
    if ($outdated.Count -gt 0) {
        Write-Host "`nPriority 2: Update Outdated Content" -ForegroundColor Yellow
        $grouped = $outdated | Group-Object -Property DocPath | Sort-Object Count -Descending
        foreach ($g in ($grouped | Select-Object -First 3)) {
            Write-Host "  - $($g.Name) ($($g.Count) reports)" -ForegroundColor Gray
        }
    }
    
    if ($missing.Count -gt 0) {
        Write-Host "`nPriority 3: Add Missing Documentation" -ForegroundColor Cyan
        $grouped = $missing | Group-Object -Property DocPath | Sort-Object Count -Descending
        foreach ($g in ($grouped | Select-Object -First 3)) {
            Write-Host "  - $($g.Name) ($($g.Count) requests)" -ForegroundColor Gray
        }
    }
    
    if ($confusing.Count -eq 0 -and $outdated.Count -eq 0 -and $missing.Count -eq 0) {
        Write-Host "  ✓ No critical improvements needed" -ForegroundColor Green
    }
}

# Main execution
Write-FeedbackHeader
Initialize-FeedbackSystem

switch ($Action) {
    "submit" {
        if (-not $DocPath -or -not $FeedbackType) {
            Write-Error "DocPath and FeedbackType required for submit"
            exit 1
        }
        Submit-Feedback -DocPath $DocPath -Type $FeedbackType -Comment $Comment
    }
    "review" { Get-FeedbackReview }
    "trends" { Get-FeedbackTrends }
    "improve" { Get-ImprovementPlan }
    "metrics" { Get-FeedbackTrends }
    default { Get-FeedbackTrends }
}

Write-Host "`n✅ Documentation feedback operation complete" -ForegroundColor Green
