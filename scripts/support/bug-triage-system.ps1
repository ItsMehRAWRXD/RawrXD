#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase L.1/5: Bug Tracking & Triage System
    
.DESCRIPTION
    Automated bug triage and tracking system:
    - GitHub Issues integration
    - Severity classification
    - Auto-assignment based on component
    - SLA tracking and escalation
    - Duplicate detection
    
.PARAMETER Repo
    GitHub repository (default: ItsMehRAWRXD/RawrXD)
    
.PARAMETER Token
    GitHub API token
    
.PARAMETER DryRun
    Show actions without executing
    
.PARAMETER TriageOnly
    Only triage, don't assign
    
.EXAMPLE
    .\bug-triage-system.ps1 -Token $env:GITHUB_TOKEN
    
.EXAMPLE
    .\bug-triage-system.ps1 -Token $env:GITHUB_TOKEN -DryRun
#
>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Repo = "ItsMehRAWRXD/RawrXD",
    
    [Parameter(Mandatory=$true)]
    [string]$Token,
    
    [Parameter(Mandatory=$false)]
    [switch]$DryRun,
    
    [Parameter(Mandatory=$false)]
    [switch]$TriageOnly
)

$ErrorActionPreference = "Stop"

# Banner
Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase L.1/5: Bug Tracking & Triage System                        ║
║  Automated Issue Management and SLA Tracking                    ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

$headers = @{
    Authorization = "token $Token"
    Accept = "application/vnd.github.v3+json"
}

$baseUrl = "https://api.github.com/repos/$Repo"

# Component to owner mapping
$componentOwners = @{
    "inference" = @("inference-team", "lead-ml-engineer")
    "gpu" = @("gpu-team", "lead-systems-engineer")
    "api" = @("api-team", "lead-backend-engineer")
    "ui" = @("frontend-team", "lead-frontend-engineer")
    "deployment" = @("sre-team", "lead-sre")
    "documentation" = @("docs-team", "technical-writer")
    "security" = @("security-team", "security-lead")
    "performance" = @("performance-team", "lead-performance-engineer")
}

# Severity definitions with SLA
$severityConfig = @{
    critical = @{
        label = "severity/critical"
        response_sla_hours = 1
        resolution_sla_hours = 24
        color = "b60205"
    }
    high = @{
        label = "severity/high"
        response_sla_hours = 4
        resolution_sla_hours = 72
        color = "d93f0b"
    }
    medium = @{
        label = "severity/medium"
        response_sla_hours = 24
        resolution_sla_hours = 168
        color = "fbca04"
    }
    low = @{
        label = "severity/low"
        response_sla_hours = 72
        resolution_sla_hours = 336
        color = "0e8a16"
    }
}

# Keywords for auto-classification
$severityKeywords = @{
    critical = @("crash", "data loss", "security breach", "vulnerability", "exploit", "corruption", "panic")
    high = @("memory leak", "performance degradation", "error", "failure", "broken", "not working")
    medium = @("slow", "inefficient", "improvement", "enhancement", "feature request")
    low = @("typo", "documentation", "cosmetic", "ui polish", "wording")
}

$componentKeywords = @{
    inference = @("model", "inference", "token", "generation", "sampling", "gguf")
    gpu = @("gpu", "cuda", "rocm", "vulkan", "memory", "vram", "compute")
    api = @("endpoint", "rest", "http", "json", "request", "response")
    ui = @("interface", "display", "window", "button", "click", "visual")
    deployment = @("deploy", "kubernetes", "docker", "helm", "ci/cd", "build")
    documentation = @("docs", "readme", "guide", "documentation", "example")
    security = @("auth", "permission", "vulnerability", "exploit", "cve")
    performance = @("slow", "latency", "throughput", "benchmark", "optimization")
}

Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Repository: $Repo"
Write-Host "  Mode: $(if ($DryRun) { 'DRY RUN' } else { 'LIVE' })"
Write-Host "  Components: $($componentOwners.Count)"
Write-Host ""

# Phase 1: Fetch Open Issues
Write-Host "[Phase 1/5] Fetching open issues..." -ForegroundColor Green

$issuesUrl = "$baseUrl/issues?state=open&per_page=100"
try {
    $issues = Invoke-RestMethod -Uri $issuesUrl -Headers $headers -Method Get
    Write-Host "  Found $($issues.Count) open issues"
} catch {
    throw "Failed to fetch issues: $_"
}

# Filter out PRs
$bugIssues = $issues | Where-Object { -not $_.pull_request }
Write-Host "  $($bugIssues.Count) issues to triage"
Write-Host ""

# Phase 2: Classify Severity
Write-Host "[Phase 2/5] Classifying severity..." -ForegroundColor Green

function Get-Severity {
    param([string]$Title, [string]$Body)
    
    $text = "$Title $Body".ToLower()
    
    foreach ($sev in $severityKeywords.GetEnumerator()) {
        foreach ($keyword in $sev.Value) {
            if ($text -match $keyword) {
                return $sev.Key
            }
        }
    }
    
    return "medium"  # Default
}

$classifiedIssues = @()
foreach ($issue in $bugIssues) {
    $severity = Get-Severity -Title $issue.title -Body $issue.body
    
    $classifiedIssues += @{
        issue = $issue
        severity = $severity
        severity_config = $severityConfig[$severity]
    }
    
    Write-Host "  #$($issue.number): $severity - $($issue.title.Substring(0, [Math]::Min(50, $issue.title.Length)))..."
}

Write-Host "  Classified $($classifiedIssues.Count) issues"
Write-Host ""

# Phase 3: Identify Component
Write-Host "[Phase 3/5] Identifying components..." -ForegroundColor Green

function Get-Component {
    param([string]$Title, [string]$Body, [array]$Labels)
    
    $text = "$Title $Body".ToLower()
    
    # Check existing labels first
    foreach ($label in $Labels) {
        $labelName = $label.name.ToLower()
        foreach ($comp in $componentKeywords.GetEnumerator()) {
            if ($labelName -match $comp.Key) {
                return $comp.Key
            }
        }
    }
    
    # Keyword matching
    foreach ($comp in $componentKeywords.GetEnumerator()) {
        foreach ($keyword in $comp.Value) {
            if ($text -match $keyword) {
                return $comp.Key
            }
        }
    }
    
    return "general"
}

foreach ($item in $classifiedIssues) {
    $component = Get-Component -Title $item.issue.title -Body $item.issue.body -Labels $item.issue.labels
    $item.component = $component
    $item.owners = $componentOwners[$component]
    
    Write-Host "  #$($item.issue.number): $component - $(if ($item.owners) { $item.owners[0] } else { 'unassigned' })"
}

Write-Host ""

# Phase 4: Check for Duplicates
Write-Host "[Phase 4/5] Checking for duplicates..." -ForegroundColor Green

function Get-TextSimilarity {
    param([string]$Text1, [string]$Text2)
    
    $words1 = ($Text1.ToLower() -split '\W+') | Where-Object { $_.Length -gt 3 }
    $words2 = ($Text2.ToLower() -split '\W+') | Where-Object { $_.Length -gt 3 }
    
    $set1 = @($words1 | Select-Object -Unique)
    $set2 = @($words2 | Select-Object -Unique)
    
    $intersection = $set1 | Where-Object { $set2 -contains $_ }
    $union = ($set1 + $set2) | Select-Object -Unique
    
    if ($union.Count -eq 0) { return 0 }
    return $intersection.Count / $union.Count
}

$duplicates = @()
for ($i = 0; $i -lt $classifiedIssues.Count; $i++) {
    for ($j = $i + 1; $j -lt $classifiedIssues.Count; $j++) {
        $issue1 = $classifiedIssues[$i]
        $issue2 = $classifiedIssues[$j]
        
        $similarity = Get-TextSimilarity -Text1 "$($issue1.issue.title) $($issue1.issue.body)" -Text2 "$($issue2.issue.title) $($issue2.issue.body)"
        
        if ($similarity -gt 0.7) {
            $duplicates += @{
                issue1 = $issue1.issue.number
                issue2 = $issue2.issue.number
                similarity = [math]::Round($similarity, 2)
            }
            Write-Host "  Potential duplicate: #$($issue1.issue.number) and #$($issue2.issue.number) ($([math]::Round($similarity * 100))% similar)"
        }
    }
}

Write-Host "  Found $($duplicates.Count) potential duplicates"
Write-Host ""

# Phase 5: Apply Labels and Assignments
Write-Host "[Phase 5/5] Applying triage actions..." -ForegroundColor Green

$actionsTaken = @{
    labeled = 0
    assigned = 0
    commented = 0
    duplicates_flagged = 0
}

foreach ($item in $classifiedIssues) {
    $issueNumber = $item.issue.number
    
    # Apply severity label
    $severityLabel = $item.severity_config.label
    $existingLabels = $item.issue.labels | ForEach-Object { $_.name }
    
    if ($severityLabel -notin $existingLabels) {
        if (-not $DryRun) {
            $labelUrl = "$baseUrl/issues/$issueNumber/labels"
            $body = @{ labels = @($severityLabel) } | ConvertTo-Json
            Invoke-RestMethod -Uri $labelUrl -Headers $headers -Method Post -Body $body -ContentType "application/json" | Out-Null
        }
        $actionsTaken.labeled++
        Write-Host "  #$issueNumber: Added label '$severityLabel'"
    }
    
    # Apply component label
    if ($item.component -ne "general") {
        $componentLabel = "component/$($item.component)"
        if ($componentLabel -notin $existingLabels) {
            if (-not $DryRun) {
                $labelUrl = "$baseUrl/issues/$issueNumber/labels"
                $body = @{ labels = @($componentLabel) } | ConvertTo-Json
                Invoke-RestMethod -Uri $labelUrl -Headers $headers -Method Post -Body $body -ContentType "application/json" | Out-Null
            }
            Write-Host "  #$issueNumber: Added label '$componentLabel'"
        }
    }
    
    # Assign to component owner
    if (-not $TriageOnly -and $item.owners -and -not $item.issue.assignee) {
        $assignee = $item.owners[0]
        if (-not $DryRun) {
            $assignUrl = "$baseUrl/issues/$issueNumber/assignees"
            $body = @{ assignees = @($assignee) } | ConvertTo-Json
            Invoke-RestMethod -Uri $assignUrl -Headers $headers -Method Post -Body $body -ContentType "application/json" | Out-Null
        }
        $actionsTaken.assigned++
        Write-Host "  #$issueNumber: Assigned to @$assignee"
    }
    
    # Add triage comment for critical/high
    if ($item.severity -in @("critical", "high") -and -not $DryRun) {
        $commentsUrl = "$baseUrl/issues/$issueNumber/comments"
        $sla = $item.severity_config.response_sla_hours
        $comment = ":warning: **Auto-Triage:** This issue has been classified as **$($item.severity.ToUpper())** severity.`n`nResponse SLA: **$sla hours**`nComponent: **$($item.component)**`nAssigned to: **$($item.owners -join ', ')**"
        $body = @{ body = $comment } | ConvertTo-Json
        Invoke-RestMethod -Uri $commentsUrl -Headers $headers -Method Post -Body $body -ContentType "application/json" | Out-Null
        $actionsTaken.commented++
    }
}

# Flag duplicates
foreach ($dup in $duplicates) {
    if (-not $DryRun) {
        $commentsUrl = "$baseUrl/issues/$($dup.issue2)/comments"
        $comment = ":information_source: **Possible Duplicate:** This issue appears similar to #$($dup.issue1) ($($dup.similarity * 100)% similarity). Please review and close if duplicate."
        $body = @{ body = $comment } | ConvertTo-Json
        Invoke-RestMethod -Uri $commentsUrl -Headers $headers -Method Post -Body $body -ContentType "application/json" | Out-Null
    }
    $actionsTaken.duplicates_flagged++
}

Write-Host ""

# Summary
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "BUG TRIAGE COMPLETE" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Issues processed: $($classifiedIssues.Count)"
Write-Host "Severities:"
$classifiedIssues | Group-Object -Property { $_.severity } | ForEach-Object {
    Write-Host "  $($_.Name): $($_.Count)"
}
Write-Host ""
Write-Host "Actions taken:"
Write-Host "  Labels applied: $($actionsTaken.labeled)"
Write-Host "  Assignments made: $($actionsTaken.assigned)"
Write-Host "  Comments added: $($actionsTaken.commented)"
Write-Host "  Duplicates flagged: $($actionsTaken.duplicates_flagged)"
Write-Host ""

if ($DryRun) {
    Write-Host "⚠️ DRY RUN MODE - No changes were applied" -ForegroundColor Yellow
}

Write-Host "✅ Bug triage complete!" -ForegroundColor Green
