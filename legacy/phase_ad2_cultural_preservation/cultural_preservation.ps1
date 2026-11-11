#!/usr/bin/env pwsh
#requires -Version 7.0
# Phase AD.2: Cultural Preservation System
# Maintains organizational culture and values across generations

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("document", "onboard", "ritual", "story", "values")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [string]$Artifact,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\culture"
)

$ErrorActionPreference = "Stop"

# Cultural registry
$CulturalRegistry = @{
    Values = @()
    Stories = @()
    Rituals = @()
    Onboarding = @{}
    LastUpdated = $null
}

# Core values
$CoreValues = @(
    @{ Name = "Excellence"; Description = "Pursue the highest standards in everything" },
    @{ Name = "Innovation"; Description = "Challenge the status quo, embrace change" },
    @{ Name = "Integrity"; Description = "Do the right thing, even when no one is watching" },
    @{ Name = "Collaboration"; Description = "Together we achieve more" },
    @{ Name = "Customer Obsession"; Description = "Start with the customer and work backwards" },
    @{ Name = "Ownership"; Description = "Think long-term, act like an owner" },
    @{ Name = "Learn & Be Curious"; Description = "Never stop learning, always explore" },
    @{ Name = "Deliver Results"; Description = "Focus on the output that matters" }
)

function Write-CultureHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase AD.2: Cultural Preservation System                        ║
║  Maintaining organizational soul across generations                ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-CultureSystem {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $OutputPath "stories") -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $OutputPath "rituals") -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $OutputPath "onboarding") -Force | Out-Null
    }
    
    # Initialize core values
    $valuesFile = Join-Path $OutputPath "core_values.json"
    if (-not (Test-Path $valuesFile)) {
        $CoreValues | ConvertTo-Json -Depth 5 | Set-Content -Path $valuesFile
    }
    
    # Load registry
    $registryFile = Join-Path $OutputPath "cultural_registry.json"
    if (Test-Path $registryFile) {
        $script:CulturalRegistry = Get-Content -Path $registryFile -Raw | ConvertFrom-Json -AsHashtable
    }
}

function Save-CulturalRegistry {
    $script:CulturalRegistry.LastUpdated = Get-Date -Format "o"
    $registryFile = Join-Path $OutputPath "cultural_registry.json"
    $script:CulturalRegistry | ConvertTo-Json -Depth 10 | Set-Content -Path $registryFile
}

function Get-CultureDashboard {
    Write-Host "`nCultural Preservation Dashboard" -ForegroundColor Yellow
    Write-Host ""
    
    # Core values
    Write-Host "Core Values:" -ForegroundColor White
    foreach ($value in $CoreValues) {
        Write-Host "  ★ $($value.Name)" -ForegroundColor Cyan
        Write-Host "    $($value.Description)" -ForegroundColor Gray
    }
    
    # Stories
    Write-Host "`nOrganizational Stories: $($script:CulturalRegistry.Stories.Count)" -ForegroundColor White
    if ($script:CulturalRegistry.Stories.Count -gt 0) {
        foreach ($story in ($script:CulturalRegistry.Stories | Select-Object -Last 3)) {
            Write-Host "  📖 $($story.Title) ($($story.Year))" -ForegroundColor Gray
        }
    }
    
    # Rituals
    Write-Host "`nActive Rituals: $($script:CulturalRegistry.Rituals.Count)" -ForegroundColor White
    foreach ($ritual in $script:CulturalRegistry.Rituals) {
        Write-Host "  🎭 $($ritual.Name) - $($ritual.Frequency)" -ForegroundColor Gray
    }
    
    # Onboarding
    Write-Host "`nOnboarding Program:" -ForegroundColor White
    if ($script:CulturalRegistry.Onboarding.ContainsKey("Steps")) {
        Write-Host "  Steps: $($script:CulturalRegistry.Onboarding.Steps.Count)" -ForegroundColor Gray
        Write-Host "  Completion Rate: $($script:CulturalRegistry.Onboarding.CompletionRate)%" -ForegroundColor Gray
    } else {
        Write-Host "  Not yet configured" -ForegroundColor Gray
    }
}

function New-CulturalStory {
    param($Title, $Content, $Year, $Lesson)
    
    $story = @{
        Id = [Guid]::NewGuid().ToString()
        Title = $Title
        Content = $Content
        Year = $Year
        Lesson = $Lesson
        CreatedAt = Get-Date -Format "o"
    }
    
    $script:CulturalRegistry.Stories += $story
    Save-CulturalRegistry
    
    Write-Host "✓ Story documented: $Title" -ForegroundColor Green
}

function New-CulturalRitual {
    param($Name, $Purpose, $Frequency, $Format)
    
    $ritual = @{
        Id = [Guid]::NewGuid().ToString()
        Name = $Name
        Purpose = $Purpose
        Frequency = $Frequency
        Format = $Format
        CreatedAt = Get-Date -Format "o"
    }
    
    $script:CulturalRegistry.Rituals += $ritual
    Save-CulturalRegistry
    
    Write-Host "✓ Ritual established: $Name" -ForegroundColor Green
}

# Main execution
Write-CultureHeader
Initialize-CultureSystem

switch ($Action) {
    "document" {
        Get-CultureDashboard
    }
    "values" {
        Write-Host "`nCore Values:" -ForegroundColor Yellow
        foreach ($value in $CoreValues) {
            Write-Host "  $($value.Name): $($value.Description)" -ForegroundColor White
        }
    }
    "story" {
        New-CulturalStory -Title "The Great Migration" -Content "How we moved to microservices" -Year 2025 -Lesson "Incremental change is safer"
    }
    "ritual" {
        New-CulturalRitual -Name "Demo Friday" -Purpose "Share weekly progress" -Frequency "Weekly" -Format "Live demo + Q&A"
    }
    default {
        Get-CultureDashboard
    }
}

Write-Host "`n✅ Cultural preservation operation complete" -ForegroundColor Green
