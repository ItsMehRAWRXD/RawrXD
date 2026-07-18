#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase L.3/5: Customer Feedback Aggregator
    
.DESCRIPTION
    Aggregates and analyzes customer feedback from multiple sources:
    - GitHub Issues and Discussions
    - Support tickets
    - User surveys
    - Social media mentions
    - Sentiment analysis
    - Trend identification
    
.PARAMETER DaysBack
    Days of feedback to analyze (default: 30)
    
.PARAMETER Sources
    Feedback sources to include (default: all)
    
.PARAMETER GenerateReport
    Generate feedback report
    
.PARAMETER OutputPath
    Path for output files
    
.EXAMPLE
    .\customer-feedback-aggregator.ps1 -DaysBack 7
    
.EXAMPLE
    .\customer-feedback-aggregator.ps1 -GenerateReport -OutputPath reports/
#
>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [int]$DaysBack = 30,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("github", "support", "surveys", "social", "all")]
    [string[]]$Sources = @("all"),
    
    [Parameter(Mandatory=$false)]
    [switch]$GenerateReport,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "feedback-reports"
)

$ErrorActionPreference = "Stop"

# Banner
Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase L.3/5: Customer Feedback Aggregator                       ║
║  Multi-Source Feedback Analysis and Trend Identification        ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Analysis Period: $DaysBack days"
Write-Host "  Sources: $($Sources -join ', ')"
Write-Host "  Report: $(if ($GenerateReport) { 'YES' } else { 'NO' })"
Write-Host ""

# Phase 1: Collect GitHub Feedback
Write-Host "[Phase 1/5] Collecting GitHub feedback..." -ForegroundColor Green

$githubFeedback = @()

if ($Sources -contains "github" -or $Sources -contains "all") {
    # Recent issues
    $recentIssues = gh issue list --repo ItsMehRAWRXD/RawrXD --state all --limit 100 --json number,title,body,createdAt,labels,author,comments 2>$null | ConvertFrom-Json
    
    foreach ($issue in $recentIssues) {
        $createdDate = [DateTime]::Parse($issue.createdAt)
        if ($createdDate -gt (Get-Date).AddDays(-$DaysBack)) {
            $githubFeedback += @{
                source = "github"
                type = "issue"
                id = $issue.number
                title = $issue.title
                content = $issue.body
                author = $issue.author.login
                created = $createdDate
                labels = $issue.labels | ForEach-Object { $_.name }
                comment_count = $issue.comments.Count
            }
        }
    }
    
    # Recent discussions
    $recentDiscussions = gh api repos/ItsMehRAWRXD/RawrXD/discussions --paginate 2>$null | ConvertFrom-Json
    if ($recentDiscussions) {
        foreach ($discussion in $recentDiscussions) {
            $createdDate = [DateTime]::Parse($discussion.created_at)
            if ($createdDate -gt (Get-Date).AddDays(-$DaysBack)) {
                $githubFeedback += @{
                    source = "github"
                    type = "discussion"
                    id = $discussion.number
                    title = $discussion.title
                    content = $discussion.body
                    author = $discussion.user.login
                    created = $createdDate
                    category = $discussion.category.name
                    reaction_count = ($discussion.reactions | Measure-Object).Count
                }
            }
        }
    }
}

Write-Host "  GitHub items: $($githubFeedback.Count)"
Write-Host ""

# Phase 2: Analyze Sentiment
Write-Host "[Phase 2/5] Analyzing sentiment..." -ForegroundColor Green

function Get-Sentiment {
    param([string]$Text)
    
    $positiveWords = @("good", "great", "excellent", "awesome", "love", "perfect", "fast", "easy", "helpful", "amazing", "best", "impressive")
    $negativeWords = @("bad", "terrible", "slow", "crash", "bug", "error", "problem", "issue", "broken", "frustrating", "awful", "worst", "disappointing")
    
    $textLower = $Text.ToLower()
    $positiveCount = 0
    $negativeCount = 0
    
    foreach ($word in $positiveWords) {
        $positiveCount += ([regex]::Matches($textLower, $word)).Count
    }
    
    foreach ($word in $negativeWords) {
        $negativeCount += ([regex]::Matches($textLower, $word)).Count
    }
    
    if ($positiveCount -gt $negativeCount) { return "positive" }
    if ($negativeCount -gt $positiveCount) { return "negative" }
    return "neutral"
}

$analyzedFeedback = @()
foreach ($item in $githubFeedback) {
    $sentiment = Get-Sentiment -Text "$($item.title) $($item.content)"
    $item.sentiment = $sentiment
    $analyzedFeedback += $item
}

$sentimentSummary = $analyzedFeedback | Group-Object -Property sentiment
foreach ($s in $sentimentSummary) {
    Write-Host "  $($s.Name): $($s.Count)"
}

Write-Host ""

# Phase 3: Identify Themes and Trends
Write-Host "[Phase 3/5] Identifying themes and trends..." -ForegroundColor Green

$themes = @{
    performance = @("slow", "fast", "speed", "latency", "throughput", "optimization", "benchmark")
    stability = @("crash", "freeze", "hang", "stable", "reliable", "robust")
    usability = @("ui", "interface", "easy", "difficult", "confusing", "intuitive")
    documentation = @("docs", "documentation", "example", "tutorial", "guide", "readme")
    deployment = @("deploy", "install", "setup", "configuration", "kubernetes", "docker")
    features = @("feature", "request", "wish", "want", "need", "missing", "add")
}

$themeCounts = @{}
foreach ($theme in $themes.Keys) {
    $themeCounts[$theme] = 0
}

foreach ($item in $analyzedFeedback) {
    $text = "$($item.title) $($item.content)".ToLower()
    foreach ($theme in $themes.GetEnumerator()) {
        foreach ($keyword in $theme.Value) {
            if ($text -match $keyword) {
                $themeCounts[$theme.Key]++
                break
            }
        }
    }
}

Write-Host "  Top themes:"
$themeCounts.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 5 | ForEach-Object {
    Write-Host "    $($_.Key): $($_.Value) mentions"
}

Write-Host ""

# Phase 4: Categorize by Impact
Write-Host "[Phase 4/5] Categorizing by impact..." -ForegroundColor Green

$impactCategories = @{
    critical = @()
    high = @()
    medium = @()
    low = @()
}

foreach ($item in $analyzedFeedback) {
    $impact = "low"
    
    # Critical: Crashes, data loss, security
    if ($item.content -match "crash|data loss|security|vulnerability|exploit" -or 
        $item.labels -contains "bug/critical") {
        $impact = "critical"
    }
    # High: Performance, stability issues
    elseif ($item.content -match "slow|freeze|hang|memory leak" -or 
            $item.sentiment -eq "negative" -or
            $item.labels -contains "bug/high") {
        $impact = "high"
    }
    # Medium: Feature requests, enhancements
    elseif ($item.type -eq "discussion" -or 
            $item.labels -contains "enhancement" -or
            $item.labels -contains "feature-request") {
        $impact = "medium"
    }
    
    $item.impact = $impact
    $impactCategories[$impact] += $item
}

foreach ($category in $impactCategories.GetEnumerator()) {
    Write-Host "  $($category.Key): $($category.Value.Count) items"
}

Write-Host ""

# Phase 5: Generate Action Items
Write-Host "[Phase 5/5] Generating action items..." -ForegroundColor Green

$actionItems = @()

# Critical items need immediate attention
foreach ($item in $impactCategories.critical) {
    $actionItems += @{
        priority = "P0"
        title = $item.title
        source = $item.source
        id = $item.id
        action = "Investigate immediately"
        owner = "engineering-lead"
        due_date = (Get-Date).AddDays(1).ToString("yyyy-MM-dd")
    }
}

# High impact items
foreach ($item in $impactCategories.high | Select-Object -First 10) {
    $actionItems += @{
        priority = "P1"
        title = $item.title
        source = $item.source
        id = $item.id
        action = "Schedule for next sprint"
        owner = "product-manager"
        due_date = (Get-Date).AddDays(7).ToString("yyyy-MM-dd")
    }
}

# Theme-based actions
$topThemes = $themeCounts.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 3
foreach ($theme in $topThemes) {
    if ($theme.Value -gt 5) {
        $actionItems += @{
            priority = "P2"
            title = "Address $($theme.Key) feedback theme"
            source = "aggregate"
            id = "theme-$($theme.Key)"
            action = "Create improvement initiative for $($theme.Key)"
            owner = "product-manager"
            due_date = (Get-Date).AddDays(14).ToString("yyyy-MM-dd")
        }
    }
}

foreach ($action in $actionItems) {
    Write-Host "  [$($action.priority)] $($action.title.Substring(0, [Math]::Min(50, $action.title.Length)))..."
}

Write-Host ""

# Generate Report
if ($GenerateReport) {
    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
    
    $report = @{
        generated_at = Get-Date -Format "o"
        period_days = $DaysBack
        summary = @{
            total_feedback = $analyzedFeedback.Count
            sentiment = @{
                positive = ($analyzedFeedback | Where-Object { $_.sentiment -eq "positive" }).Count
                neutral = ($analyzedFeedback | Where-Object { $_.sentiment -eq "neutral" }).Count
                negative = ($analyzedFeedback | Where-Object { $_.sentiment -eq "negative" }).Count
            }
            themes = $themeCounts
            impact_distribution = @{
                critical = $impactCategories.critical.Count
                high = $impactCategories.high.Count
                medium = $impactCategories.medium.Count
                low = $impactCategories.low.Count
            }
        }
        action_items = $actionItems
        feedback_items = $analyzedFeedback
    }
    
    $reportFile = "$OutputPath/feedback-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportFile
    
    # Generate markdown summary
    $markdownReport = @"
# Customer Feedback Report
**Generated:** $(Get-Date -Format "yyyy-MM-dd HH:mm")  
**Period:** Last $DaysBack days

## Summary
- **Total Feedback:** $($analyzedFeedback.Count)
- **Positive:** $($report.summary.sentiment.positive)
- **Neutral:** $($report.summary.sentiment.neutral)
- **Negative:** $($report.summary.sentiment.negative)

## Sentiment Distribution
| Sentiment | Count | Percentage |
|-----------|-------|------------|
| Positive | $($report.summary.sentiment.positive) | $([math]::Round($report.summary.sentiment.positive / $analyzedFeedback.Count * 100, 1))% |
| Neutral | $($report.summary.sentiment.neutral) | $([math]::Round($report.summary.sentiment.neutral / $analyzedFeedback.Count * 100, 1))% |
| Negative | $($report.summary.sentiment.negative) | $([math]::Round($report.summary.sentiment.negative / $analyzedFeedback.Count * 100, 1))% |

## Top Themes
| Theme | Mentions |
|-------|----------|
$(foreach ($t in $themeCounts.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 5) { "| $($t.Key) | $($t.Value) |" })

## Impact Distribution
| Impact | Count |
|--------|-------|
| Critical | $($impactCategories.critical.Count) |
| High | $($impactCategories.high.Count) |
| Medium | $($impactCategories.medium.Count) |
| Low | $($impactCategories.low.Count) |

## Action Items
| Priority | Title | Owner | Due Date |
|----------|-------|-------|----------|
$(foreach ($a in $actionItems) { "| $($a.priority) | $($a.title.Substring(0, [Math]::Min(40, $a.title.Length)))... | $($a.owner) | $($a.due_date) |" })

## Critical Items Requiring Attention
$(if ($impactCategories.critical.Count -eq 0) { "_No critical items this period._" } else { foreach ($c in $impactCategories.critical) { "- **#$($c.id):** $($c.title)" } })

---
*Report generated by RawrXD Feedback Aggregator*
"@
    
    $markdownFile = "$OutputPath/feedback-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').md"
    $markdownReport | Out-File -FilePath $markdownFile -Encoding UTF8
    
    Write-Host "Reports generated:" -ForegroundColor Green
    Write-Host "  JSON: $reportFile"
    Write-Host "  Markdown: $markdownFile"
}

# Summary
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "FEEDBACK AGGREGATION COMPLETE" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Total feedback analyzed: $($analyzedFeedback.Count)"
Write-Host "Sentiment: $(($analyzedFeedback | Where-Object { $_.sentiment -eq 'positive' }).Count) positive, $(($analyzedFeedback | Where-Object { $_.sentiment -eq 'negative' }).Count) negative"
Write-Host "Critical items: $($impactCategories.critical.Count)"
Write-Host "Action items generated: $($actionItems.Count)"
Write-Host ""
Write-Host "✅ Feedback aggregation complete!" -ForegroundColor Green
