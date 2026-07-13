#!/usr/bin/env pwsh
#requires -Version 7.0
# Phase AD.3: Institutional Memory Archive
# Preserves decisions, context, and organizational history

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("record", "query", "timeline", "decisions", "milestones")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [string]$Topic,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\memory"
)

$ErrorActionPreference = "Stop"

# Memory registry
$MemoryRegistry = @{
    Decisions = @()
    Milestones = @()
    Context = @()
    Timeline = @()
    LastUpdated = $null
}

function Write-MemoryHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase AD.3: Institutional Memory Archive                          ║
║  Preserving organizational decisions and history                   ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-MemorySystem {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $OutputPath "decisions") -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $OutputPath "milestones") -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $OutputPath "context") -Force | Out-Null
    }
    
    # Load registry
    $registryFile = Join-Path $OutputPath "memory_registry.json"
    if (Test-Path $registryFile) {
        $script:MemoryRegistry = Get-Content -Path $registryFile -Raw | ConvertFrom-Json -AsHashtable
    }
}

function Save-MemoryRegistry {
    $script:MemoryRegistry.LastUpdated = Get-Date -Format "o"
    $registryFile = Join-Path $OutputPath "memory_registry.json"
    $script:MemoryRegistry | ConvertTo-Json -Depth 10 | Set-Content -Path $registryFile
}

function New-DecisionRecord {
    param($Title, $Context, $Decision, $Consequences, $Alternatives, $DecidedBy)
    
    $record = @{
        Id = [Guid]::NewGuid().ToString()
        Title = $Title
        Context = $Context
        Decision = $Decision
        Consequences = $Consequences
        Alternatives = $Alternatives
        DecidedBy = $DecidedBy
        DecidedAt = Get-Date -Format "o"
        Status = "active"
    }
    
    $script:MemoryRegistry.Decisions += $record
    Save-MemoryRegistry
    
    Write-Host "✓ Decision recorded: $Title" -ForegroundColor Green
}

function New-Milestone {
    param($Title, $Description, $Impact, $Category)
    
    $milestone = @{
        Id = [Guid]::NewGuid().ToString()
        Title = $Title
        Description = $Description
        Impact = $Impact
        Category = $Category
        AchievedAt = Get-Date -Format "o"
    }
    
    $script:MemoryRegistry.Milestones += $milestone
    Save-MemoryRegistry
    
    Write-Host "✓ Milestone recorded: $Title" -ForegroundColor Green
}

function Get-OrganizationalTimeline {
    Write-Host "`nOrganizational Timeline" -ForegroundColor Yellow
    Write-Host ""
    
    # Combine all events
    $events = @()
    
    foreach ($decision in $script:MemoryRegistry.Decisions) {
        $events += @{
            Date = $decision.DecidedAt
            Type = "Decision"
            Title = $decision.Title
        }
    }
    
    foreach ($milestone in $script:MemoryRegistry.Milestones) {
        $events += @{
            Date = $milestone.AchievedAt
            Type = "Milestone"
            Title = $milestone.Title
        }
    }
    
    # Sort and display
    $sorted = $events | Sort-Object Date
    
    if ($sorted.Count -eq 0) {
        Write-Host "  No events recorded yet" -ForegroundColor Gray
        return
    }
    
    foreach ($event in $sorted) {
        $date = [DateTime]::Parse($event.Date).ToString("yyyy-MM-dd")
        $icon = if ($event.Type -eq "Decision") { "📋" } else { "🏆" }
        Write-Host "  $date $icon $($event.Title)" -ForegroundColor $(if ($event.Type -eq "Decision") { "White" } else { "Cyan" })
    }
}

function Get-DecisionLog {
    Write-Host "`nDecision Log" -ForegroundColor Yellow
    Write-Host ""
    
    if ($script:MemoryRegistry.Decisions.Count -eq 0) {
        Write-Host "  No decisions recorded" -ForegroundColor Gray
        return
    }
    
    foreach ($decision in ($script:MemoryRegistry.Decisions | Sort-Object DecidedAt -Descending)) {
        Write-Host "  📋 $($decision.Title)" -ForegroundColor White
        Write-Host "    Context: $($decision.Context)" -ForegroundColor Gray
        Write-Host "    Decision: $($decision.Decision)" -ForegroundColor Cyan
        Write-Host "    By: $($decision.DecidedBy) at $([DateTime]::Parse($decision.DecidedAt).ToString('yyyy-MM-dd'))" -ForegroundColor Gray
        Write-Host ""
    }
}

function Get-MilestoneSummary {
    Write-Host "`nMilestone Summary" -ForegroundColor Yellow
    Write-Host ""
    
    if ($script:MemoryRegistry.Milestones.Count -eq 0) {
        Write-Host "  No milestones recorded" -ForegroundColor Gray
        return
    }
    
    $byCategory = $script:MemoryRegistry.Milestones | Group-Object -Property Category
    
    foreach ($category in $byCategory) {
        Write-Host "  $($category.Name): $($category.Count)" -ForegroundColor White
        foreach ($milestone in $category.Group) {
            Write-Host "    🏆 $($milestone.Title)" -ForegroundColor Gray
        }
    }
}

# Main execution
Write-MemoryHeader
Initialize-MemorySystem

switch ($Action) {
    "record" {
        New-DecisionRecord -Title "Adopt Microservices" -Context "Monolithic scaling issues" -Decision "Migrate to microservices" -Consequences "Improved scalability, increased complexity" -Alternatives @("Optimize monolith", "Serverless") -DecidedBy "Architecture Team"
    }
    "query" {
        if ($Topic) {
            $results = $script:MemoryRegistry.Decisions | Where-Object { $_.Title -like "*$Topic*" -or $_.Context -like "*$Topic*" }
            Write-Host "`nQuery results for '$Topic':" -ForegroundColor Yellow
            foreach ($result in $results) {
                Write-Host "  $($result.Title)" -ForegroundColor White
            }
        } else {
            Get-DecisionLog
        }
    }
    "timeline" {
        Get-OrganizationalTimeline
    }
    "decisions" {
        Get-DecisionLog
    }
    "milestones" {
        Get-MilestoneSummary
    }
    default {
        Get-OrganizationalTimeline
    }
}

Write-Host "`n✅ Institutional memory operation complete" -ForegroundColor Green
