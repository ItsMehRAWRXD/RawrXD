# RawrXD Feedback Collector
# Phase P.4 - Customer Feedback Management
# Collects and analyzes customer feedback for product improvement

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("collect", "analyze", "report", "export")]
    [string]$Action = "collect",

    [Parameter(Mandatory=$false)]
    [string]$CustomerId = "",

    [Parameter(Mandatory=$false)]
    [ValidateSet("feature", "bug", "performance", "documentation", "general")]
    [string]$Category = "general",

    [Parameter(Mandatory=$false)]
    [ValidateSet("1", "2", "3", "4", "5")]
    [string]$Rating = "",

    [Parameter(Mandatory=$false)]
    [string]$Feedback = "",

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"

# Feedback storage
$FeedbackDbPath = "$env:USERPROFILE\.rawrxd\feedback"
if (!(Test-Path $FeedbackDbPath)) {
    New-Item -ItemType Directory -Path $FeedbackDbPath -Force | Out-Null
}

# Logging
function Write-FeedbackLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{ "INFO" = "White"; "SUCCESS" = "Green"; "WARNING" = "Yellow"; "ERROR" = "Red"; "FEEDBACK" = "Cyan" }
    Write-Host "[$timestamp] [FEEDBACK] [$Level] $Message" -ForegroundColor $colors[$Level]
}

# Feedback entry class
class FeedbackEntry {
    [string]$Id
    [string]$CustomerId
    [string]$Category
    [int]$Rating
    [string]$Text
    [string]$Context
    [DateTime]$SubmittedAt
    [hashtable]$Metadata

    FeedbackEntry([string]$customerId, [string]$category, [int]$rating, [string]$text) {
        $this.Id = [Guid]::NewGuid().ToString()
        $this.CustomerId = $customerId
        $this.Category = $category
        $this.Rating = $rating
        $this.Text = $text
        $this.SubmittedAt = Get-Date
        $this.Metadata = @{
            version = "1.0.0"
            source = "powershell"
            platform = $env:OS
        }
    }

    [hashtable] ToHashtable() {
        return @{
            id = $this.Id
            customer_id = $this.CustomerId
            category = $this.Category
            rating = $this.Rating
            text = $this.Text
            context = $this.Context
            submitted_at = $this.SubmittedAt.ToString("o")
            metadata = $this.Metadata
        }
    }
}

# Save feedback
function Save-Feedback {
    param([FeedbackEntry]$Entry)

    $feedbackPath = Join-Path $FeedbackDbPath "$($Entry.Id).json"
    $Entry.ToHashtable() | ConvertTo-Json -Depth 10 | Out-File $feedbackPath -Encoding UTF8
}

# Get all feedback
function Get-AllFeedback {
    $feedback = @()
    $files = Get-ChildItem -Path $FeedbackDbPath -Filter "*.json"

    foreach ($file in $files) {
        $entry = Get-Content $file.FullName -Raw | ConvertFrom-Json
        $feedback += $entry
    }

    return $feedback | Sort-Object submitted_at -Descending
}

# Collect new feedback
function New-Feedback {
    param(
        [string]$CustomerId,
        [string]$Category,
        [int]$Rating,
        [string]$Text
    )

    Write-FeedbackLog "Collecting feedback from $CustomerId" "FEEDBACK"

    $entry = [FeedbackEntry]::new($CustomerId, $Category, $Rating, $Text)

    # Add system context
    $entry.Context = @"
Version: 1.0.0
Platform: $env:OS
Date: $(Get-Date -Format 'yyyy-MM-dd')
"@

    Save-Feedback -Entry $entry

    # Analyze sentiment (simple)
    $sentiment = if ($Rating -ge 4) { "positive" } elseif ($Rating -ge 3) { "neutral" } else { "negative" }

    Write-FeedbackLog "Feedback saved: $($entry.Id) (Sentiment: $sentiment)" "SUCCESS"

    # Trigger alerts for negative feedback
    if ($Rating -le 2) {
        Write-FeedbackLog "ALERT: Negative feedback received from $CustomerId" "WARNING"
        # In production, send notification to customer success team
    }

    return $entry
}

# Analyze feedback
function Get-FeedbackAnalysis {
    $feedback = Get-AllFeedback

    $analysis = @{
        total_count = $feedback.Count
        by_category = @{}
        by_rating = @{}
        average_rating = 0
        sentiment = @{
            positive = 0
            neutral = 0
            negative = 0
        }
        trends = @()
    }

    if ($feedback.Count -eq 0) {
        return $analysis
    }

    # Category breakdown
    $categories = $feedback | Group-Object category
    foreach ($cat in $categories) {
        $analysis.by_category[$cat.Name] = $cat.Count
    }

    # Rating breakdown
    $ratings = $feedback | Group-Object rating
    foreach ($rat in $ratings) {
        $analysis.by_rating[$rat.Name] = $rat.Count
    }

    # Average rating
    $analysis.average_rating = ($feedback | Measure-Object -Property rating -Average).Average

    # Sentiment analysis
    foreach ($entry in $feedback) {
        if ($entry.rating -ge 4) {
            $analysis.sentiment.positive++
        } elseif ($entry.rating -ge 3) {
            $analysis.sentiment.neutral++
        } else {
            $analysis.sentiment.negative++
        }
    }

    # Recent trends (last 30 days)
    $recent = $feedback | Where-Object {
        ([DateTime]$_.submitted_at) -gt (Get-Date).AddDays(-30)
    }
    $analysis.trends = @{
        recent_count = $recent.Count
        recent_average = if ($recent.Count -gt 0) { ($recent | Measure-Object -Property rating -Average).Average } else { 0 }
    }

    return $analysis
}

# Generate feedback report
function Export-FeedbackReport {
    param([string]$Path)

    $feedback = Get-AllFeedback
    $analysis = Get-FeedbackAnalysis

    $report = @{
        generated_at = Get-Date -Format "o"
        summary = $analysis
        recent_feedback = $feedback | Select-Object -First 50
        top_issues = $feedback |
            Where-Object { $_.rating -le 2 } |
            Group-Object category |
            Sort-Object Count -Descending |
            Select-Object -First 5
    }

    $report | ConvertTo-Json -Depth 10 | Out-File $Path -Encoding UTF8
    Write-FeedbackLog "Report exported to $Path" "SUCCESS"
}

# Display feedback dashboard
function Show-FeedbackDashboard {
    $analysis = Get-FeedbackAnalysis

    Clear-Host
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║              RawrXD Customer Feedback Dashboard                  ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    # Summary
    Write-Host "Summary" -ForegroundColor Yellow
    Write-Host "  Total Feedback: $($analysis.total_count)"
    Write-Host "  Average Rating: $([Math]::Round($analysis.average_rating, 2)) / 5"
    Write-Host ""

    # Sentiment
    Write-Host "Sentiment Distribution" -ForegroundColor Yellow
    $total = $analysis.total_count
    if ($total -gt 0) {
        $posPct = [Math]::Round(($analysis.sentiment.positive / $total) * 100, 1)
        $neuPct = [Math]::Round(($analysis.sentiment.neutral / $total) * 100, 1)
        $negPct = [Math]::Round(($analysis.sentiment.negative / $total) * 100, 1)

        Write-Host "  Positive: $posPct% ($($analysis.sentiment.positive))" -ForegroundColor Green
        Write-Host "  Neutral:  $neuPct% ($($analysis.sentiment.neutral))" -ForegroundColor Yellow
        Write-Host "  Negative: $negPct% ($($analysis.sentiment.negative))" -ForegroundColor Red
    }
    Write-Host ""

    # Categories
    Write-Host "Feedback by Category" -ForegroundColor Yellow
    foreach ($cat in $analysis.by_category.GetEnumerator() | Sort-Object Value -Descending) {
        Write-Host "  $($cat.Key): $($cat.Value)"
    }
    Write-Host ""

    # Recent trends
    Write-Host "Recent Trends (30 days)" -ForegroundColor Yellow
    Write-Host "  Count: $($analysis.trends.recent_count)"
    Write-Host "  Average: $([Math]::Round($analysis.trends.recent_average, 2))"
    Write-Host ""
}

# Main execution
switch ($Action) {
    "collect" {
        if (!$CustomerId -or !$Feedback) {
            Write-FeedbackLog "Required: CustomerId and Feedback" "ERROR"
            exit 1
        }

        $ratingInt = if ($Rating) { [int]$Rating } else { 0 }
        $entry = New-Feedback -CustomerId $CustomerId -Category $Category -Rating $ratingInt -Text $Feedback

        Write-Host "`nThank you for your feedback!" -ForegroundColor Green
        Write-Host "Reference ID: $($entry.Id)" -ForegroundColor Cyan
    }
    "analyze" {
        Show-FeedbackDashboard
    }
    "report" {
        $path = if ($OutputPath) { $OutputPath } else { "feedback_report_$(Get-Date -Format 'yyyyMMdd').json" }
        Export-FeedbackReport -Path $path
    }
    "export" {
        $allFeedback = Get-AllFeedback
        $path = if ($OutputPath) { $OutputPath } else { "feedback_export_$(Get-Date -Format 'yyyyMMdd').csv" }

        $allFeedback | Select-Object id, customer_id, category, rating, text, submitted_at |
            Export-Csv -Path $path -NoTypeInformation

        Write-FeedbackLog "Exported $($allFeedback.Count) entries to $path" "SUCCESS"
    }
}
