#!/usr/bin/env pwsh
#requires -Version 7.0
# Phase AE.2: Interactive Documentation System
# Provides guided, contextual help and tutorials

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("tutorial", "guide", "reference", "search", "wizard")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [string]$Topic,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\guides"
)

$ErrorActionPreference = "Stop"

# Guide registry
$GuideRegistry = @{
    Tutorials = @{}
    Guides = @{}
    References = @{}
    Wizards = @{}
}

function Write-GuideHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase AE.2: Interactive Documentation System                      ║
║  Guided, contextual help and tutorials                             ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-GuideSystem {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    # Initialize built-in tutorials
    $script:GuideRegistry.Tutorials["getting-started"] = @{
        Title = "Getting Started with RawrXD"
        Steps = @(
            @{ Title = "Installation"; Content = "Download and install RawrXD"; Action = "Install-Package RawrXD" },
            @{ Title = "Configuration"; Content = "Configure your first model"; Action = "rawrxd config --init" },
            @{ Title = "First Inference"; Content = "Run your first inference"; Action = "rawrxd infer --model qwen2.5" }
        )
        EstimatedTime = "15 minutes"
    }
    
    $script:GuideRegistry.Tutorials["advanced-tuning"] = @{
        Title = "Advanced Performance Tuning"
        Steps = @(
            @{ Title = "Benchmark"; Content = "Establish baseline performance"; Action = "rawrxd bench --full" },
            @{ Title = "Analyze"; Content = "Review benchmark results"; Action = "rawrxd analyze" },
            @{ Title = "Optimize"; Content = "Apply optimizations"; Action = "rawrxd optimize --auto" }
        )
        EstimatedTime = "45 minutes"
    }
    
    $script:GuideRegistry.Guides["troubleshooting"] = @{
        Title = "Troubleshooting Guide"
        Sections = @(
            @{ Title = "Common Issues"; Content = "Frequently encountered problems" },
            @{ Title = "Diagnostics"; Content = "How to diagnose issues" },
            @{ Title = "Solutions"; Content = "Step-by-step solutions" }
        )
    }
}

function Start-Tutorial {
    param($TutorialName)
    
    $tutorial = $script:GuideRegistry.Tutorials[$TutorialName]
    if (-not $tutorial) {
        Write-Error "Tutorial not found: $TutorialName"
        return
    }
    
    Write-Host "`n📚 $($tutorial.Title)" -ForegroundColor Yellow
    Write-Host "   Estimated time: $($tutorial.EstimatedTime)" -ForegroundColor Gray
    Write-Host ""
    
    $stepNum = 1
    foreach ($step in $tutorial.Steps) {
        Write-Host "Step $stepNum`: $($step.Title)" -ForegroundColor Cyan
        Write-Host "  $($step.Content)" -ForegroundColor White
        Write-Host "  Command: $($step.Action)" -ForegroundColor DarkGray
        
        $response = Read-Host "`n  Press Enter to continue (or 'skip' to skip)"
        if ($response -eq "skip") {
            Write-Host "  Skipped." -ForegroundColor Yellow
        } else {
            Write-Host "  ✓ Completed" -ForegroundColor Green
        }
        
        $stepNum++
        Write-Host ""
    }
    
    Write-Host "✅ Tutorial complete!" -ForegroundColor Green
}

function Show-Guide {
    param($GuideName)
    
    $guide = $script:GuideRegistry.Guides[$GuideName]
    if (-not $guide) {
        Write-Error "Guide not found: $GuideName"
        return
    }
    
    Write-Host "`n📖 $($guide.Title)" -ForegroundColor Yellow
    Write-Host ""
    
    foreach ($section in $guide.Sections) {
        Write-Host "## $($section.Title)" -ForegroundColor Cyan
        Write-Host "$($section.Content)" -ForegroundColor White
        Write-Host ""
    }
}

function Get-GuideList {
    Write-Host "`nAvailable Documentation:" -ForegroundColor Yellow
    Write-Host ""
    
    Write-Host "Tutorials:" -ForegroundColor White
    foreach ($tutorial in $script:GuideRegistry.Tutorials.Keys) {
        $info = $script:GuideRegistry.Tutorials[$tutorial]
        Write-Host "  📚 $tutorial - $($info.Title)" -ForegroundColor Gray
    }
    
    Write-Host "`nGuides:" -ForegroundColor White
    foreach ($guide in $script:GuideRegistry.Guides.Keys) {
        $info = $script:GuideRegistry.Guides[$guide]
        Write-Host "  📖 $guide - $($info.Title)" -ForegroundColor Gray
    }
}

function Start-Wizard {
    Write-Host "`n🧙 Configuration Wizard" -ForegroundColor Yellow
    Write-Host ""
    
    Write-Host "Welcome! I'll help you configure RawrXD for your environment." -ForegroundColor White
    Write-Host ""
    
    # Step 1: Environment
    Write-Host "Step 1: Select your environment" -ForegroundColor Cyan
    Write-Host "  1. Development (local machine)" -ForegroundColor Gray
    Write-Host "  2. Staging (test environment)" -ForegroundColor Gray
    Write-Host "  3. Production (live system)" -ForegroundColor Gray
    $env = Read-Host "  Enter choice (1-3)"
    
    # Step 2: Hardware
    Write-Host "`nStep 2: Select your hardware" -ForegroundColor Cyan
    Write-Host "  1. CPU only" -ForegroundColor Gray
    Write-Host "  2. NVIDIA GPU" -ForegroundColor Gray
    Write-Host "  3. AMD GPU" -ForegroundColor Gray
    $hw = Read-Host "  Enter choice (1-3)"
    
    # Step 3: Model preference
    Write-Host "`nStep 3: Primary model type" -ForegroundColor Cyan
    Write-Host "  1. Small & Fast (7B parameters)" -ForegroundColor Gray
    Write-Host "  2. Balanced (13B parameters)" -ForegroundColor Gray
    Write-Host "  3. Large & Capable (70B+ parameters)" -ForegroundColor Gray
    $model = Read-Host "  Enter choice (1-3)"
    
    Write-Host "`n✅ Configuration complete!" -ForegroundColor Green
    Write-Host "  Environment: $(switch($env){'1'{'Development'}'2'{'Staging'}'3'{'Production'}})" -ForegroundColor Cyan
    Write-Host "  Hardware: $(switch($hw){'1'{'CPU'}'2'{'NVIDIA GPU'}'3'{'AMD GPU'}})" -ForegroundColor Cyan
    Write-Host "  Model: $(switch($model){'1'{'Small & Fast'}'2'{'Balanced'}'3'{'Large & Capable'}})" -ForegroundColor Cyan
}

# Main execution
Write-GuideHeader
Initialize-GuideSystem

switch ($Action) {
    "tutorial" {
        if ($Topic) {
            Start-Tutorial -TutorialName $Topic
        } else {
            Get-GuideList
        }
    }
    "guide" {
        if ($Topic) {
            Show-Guide -GuideName $Topic
        } else {
            Get-GuideList
        }
    }
    "reference" {
        Write-Host "`nReference documentation available in docs/" -ForegroundColor Yellow
    }
    "search" {
        if ($Topic) {
            Write-Host "`nSearching for '$Topic'..." -ForegroundColor Yellow
            $results = $script:GuideRegistry.Tutorials.Keys | Where-Object { $_ -like "*$Topic*" }
            if ($results) {
                Write-Host "Found in tutorials:" -ForegroundColor Green
                $results | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
            }
        } else {
            Get-GuideList
        }
    }
    "wizard" {
        Start-Wizard
    }
    default {
        Get-GuideList
    }
}

Write-Host "`n✅ Interactive documentation operation complete" -ForegroundColor Green
