# RawrXD Tooling Overview
# Displays comprehensive information about the production tooling suite

param(
    [switch]$ListScripts,
    [switch]$ShowStats,
    [switch]$ValidateInstallation,
    [switch]$GenerateIndex
)

$ErrorActionPreference = "Stop"

$ToolingSuite = @{
    Version = "3.2.0"
    TotalScripts = 0
    Categories = @{}
}

function Write-Header {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                                  ║" -ForegroundColor Cyan
    Write-Host "║           RawrXD Production Tooling Suite v3.2.0                 ║" -ForegroundColor Cyan
    Write-Host "║                                                                  ║" -ForegroundColor Cyan
    Write-Host "║     Vision & Generation System - Complete Automation Suite       ║" -ForegroundColor Cyan
    Write-Host "║                                                                  ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Get-ScriptCategories {
    return @{
        "Core" = @{
            Description = "Essential build, test, and deployment automation"
            Scripts = @(
                @{ Name = "rawrxd-cli.ps1"; Description = "Unified CLI entry point"; Lines = 350 }
                @{ Name = "build-orchestrator.ps1"; Description = "Build management with caching"; Lines = 500 }
                @{ Name = "test-harness.ps1"; Description = "Multi-tier testing framework"; Lines = 500 }
                @{ Name = "deployment-orchestrator.ps1"; Description = "Multi-environment deployment"; Lines = 400 }
            )
        }
        "Analysis" = @{
            Description = "Code analysis and quality assurance"
            Scripts = @(
                @{ Name = "analyze-unlinked-files.ps1"; Description = "9,001 unlinked file analyzer"; Lines = 1008 }
                @{ Name = "execute-analysis.ps1"; Description = "Analysis execution engine"; Lines = 300 }
                @{ Name = "dependency-visualizer.ps1"; Description = "Dependency graph generation"; Lines = 450 }
                @{ Name = "code-quality-gate.ps1"; Description = "Pre-commit quality checks"; Lines = 400 }
                @{ Name = "security-scanner.ps1"; Description = "Security vulnerability scanning"; Lines = 500 }
            )
        }
        "Monitoring" = @{
            Description = "System health and performance monitoring"
            Scripts = @(
                @{ Name = "workspace-health-monitor.ps1"; Description = "Health monitoring"; Lines = 400 }
                @{ Name = "performance-dashboard.ps1"; Description = "Performance visualization"; Lines = 350 }
                @{ Name = "benchmark-runner.ps1"; Description = "Performance benchmarking"; Lines = 300 }
            )
        }
        "Management" = @{
            Description = "Model registry and release management"
            Scripts = @(
                @{ Name = "model-registry-cli.ps1"; Description = "GGUF model management"; Lines = 400 }
                @{ Name = "model-manager.ps1"; Description = "Model lifecycle management"; Lines = 350 }
                @{ Name = "release-manager.ps1"; Description = "Release automation"; Lines = 450 }
                @{ Name = "hotpatch-manager.ps1"; Description = "7-layer hotpatch system"; Lines = 400 }
            )
        }
        "Documentation" = @{
            Description = "Documentation generation and reporting"
            Scripts = @(
                @{ Name = "documentation-generator.ps1"; Description = "Auto documentation generation"; Lines = 400 }
            )
        }
        "Integration" = @{
            Description = "File integration and CMake management"
            Scripts = @(
                @{ Name = "integrate-unlinked-files.ps1"; Description = "Unlinked file integration"; Lines = 400 }
            )
        }
    }
}

function Show-Overview {
    Write-Header
    
    $categories = Get-ScriptCategories
    $totalScripts = 0
    $totalLines = 0
    
    foreach ($cat in $categories.Values) {
        $totalScripts += $cat.Scripts.Count
        $totalLines += ($cat.Scripts | Measure-Object -Property Lines -Sum).Sum
    }
    
    Write-Host "SUITE OVERVIEW" -ForegroundColor White
    Write-Host "==============" -ForegroundColor White
    Write-Host ""
    Write-Host "Total Scripts: $totalScripts" -ForegroundColor Cyan
    Write-Host "Total Lines of Code: $totalLines" -ForegroundColor Cyan
    Write-Host "Categories: $($categories.Count)" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "CATEGORIES" -ForegroundColor White
    Write-Host "==========" -ForegroundColor White
    Write-Host ""
    
    foreach ($category in $categories.GetEnumerator() | Sort-Object Key) {
        $catTotalLines = ($category.Value.Scripts | Measure-Object -Property Lines -Sum).Sum
        Write-Host "$($category.Key.PadRight(15)) " -ForegroundColor Yellow -NoNewline
        Write-Host "$($category.Value.Scripts.Count.ToString().PadRight(3)) scripts  " -ForegroundColor White -NoNewline
        Write-Host "$($catTotalLines.ToString().PadLeft(5)) LOC" -ForegroundColor Gray
        Write-Host "  $($category.Value.Description)" -ForegroundColor DarkGray
        Write-Host ""
    }
    
    Write-Host "QUICK START" -ForegroundColor White
    Write-Host "===========" -ForegroundColor White
    Write-Host ""
    Write-Host "  # Use the unified CLI" -ForegroundColor Gray
    Write-Host "  .\rawrxd-cli.ps1 <command> [subcommand] [options]" -ForegroundColor White
    Write-Host ""
    Write-Host "  # Examples:" -ForegroundColor Gray
    Write-Host "  .\rawrxd-cli.ps1 build full              # Full build" -ForegroundColor White
    Write-Host "  .\rawrxd-cli.ps1 test smoke             # Quick tests" -ForegroundColor White
    Write-Host "  .\rawrxd-cli.ps1 analyze unlinked       # Analyze files" -ForegroundColor White
    Write-Host "  .\rawrxd-cli.ps1 deploy staging         # Deploy" -ForegroundColor White
    Write-Host ""
    
    Write-Host "DOCUMENTATION" -ForegroundColor White
    Write-Host "===========" -ForegroundColor White
    Write-Host ""
    Write-Host "  README-Production-Tooling.md    Complete tooling documentation" -ForegroundColor Gray
    Write-Host "  README.md                       General project documentation" -ForegroundColor Gray
    Write-Host ""
}

function Show-ScriptList {
    $categories = Get-ScriptCategories
    
    Write-Host ""
    Write-Host "COMPLETE SCRIPT LISTING" -ForegroundColor Cyan
    Write-Host "======================" -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($category in $categories.GetEnumerator() | Sort-Object Key) {
        Write-Host "$($category.Key)" -ForegroundColor Yellow
        Write-Host ("-" * 50) -ForegroundColor DarkGray
        
        foreach ($script in $category.Value.Scripts | Sort-Object Name) {
            Write-Host "  $($script.Name.PadRight(35)) " -ForegroundColor White -NoNewline
            Write-Host "$($script.Lines.ToString().PadLeft(4)) LOC" -ForegroundColor Gray
            Write-Host "    $($script.Description)" -ForegroundColor DarkGray
        }
        
        Write-Host ""
    }
}

function Show-Statistics {
    $categories = Get-ScriptCategories
    
    Write-Host ""
    Write-Host "TOOLING STATISTICS" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan
    Write-Host ""
    
    # Calculate statistics
    $allScripts = $categories.Values | ForEach-Object { $_.Scripts } | ForEach-Object { $_ }
    $totalLines = ($allScripts | Measure-Object -Property Lines -Sum).Sum
    $avgLines = [math]::Round($totalLines / $allScripts.Count)
    $maxLines = ($allScripts | Measure-Object -Property Lines -Maximum).Maximum
    $minLines = ($allScripts | Measure-Object -Property Lines -Minimum).Minimum
    
    Write-Host "Code Metrics:" -ForegroundColor White
    Write-Host "  Total Scripts:        $($allScripts.Count)" -ForegroundColor Gray
    Write-Host "  Total Lines:          $totalLines" -ForegroundColor Gray
    Write-Host "  Average Lines/Script: $avgLines" -ForegroundColor Gray
    Write-Host "  Largest Script:       $maxLines LOC" -ForegroundColor Gray
    Write-Host "  Smallest Script:      $minLines LOC" -ForegroundColor Gray
    Write-Host ""
    
    # Distribution by size
    Write-Host "Size Distribution:" -ForegroundColor White
    $small = ($allScripts | Where-Object { $_.Lines -lt 300 }).Count
    $medium = ($allScripts | Where-Object { $_.Lines -ge 300 -and $_.Lines -lt 500 }).Count
    $large = ($allScripts | Where-Object { $_.Lines -ge 500 }).Count
    
    Write-Host "  Small (<300 LOC):     $small scripts" -ForegroundColor Green
    Write-Host "  Medium (300-500):     $medium scripts" -ForegroundColor Yellow
    Write-Host "  Large (>500 LOC):     $large scripts" -ForegroundColor Cyan
    Write-Host ""
    
    # Category breakdown
    Write-Host "Scripts by Category:" -ForegroundColor White
    foreach ($cat in $categories.GetEnumerator() | Sort-Object Key) {
        $percent = [math]::Round(($cat.Value.Scripts.Count / $allScripts.Count) * 100)
        $bar = "█" * [math]::Round($percent / 2)
        Write-Host "  $($cat.Key.PadRight(15)) $bar $percent%" -ForegroundColor Gray
    }
}

function Test-Installation {
    Write-Host ""
    Write-Host "VALIDATING INSTALLATION" -ForegroundColor Cyan
    Write-Host "======================" -ForegroundColor Cyan
    Write-Host ""
    
    $categories = Get-ScriptCategories
    $allScripts = $categories.Values | ForEach-Object { $_.Scripts } | ForEach-Object { $_.Name }
    
    $found = 0
    $missing = @()
    
    foreach ($script in $allScripts) {
        $path = Join-Path $PSScriptRoot $script
        if (Test-Path $path) {
            $found++
            Write-Host "  ✓ $script" -ForegroundColor Green
        } else {
            $missing += $script
            Write-Host "  ✗ $script" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    Write-Host "Results: $found/$($allScripts.Count) scripts found" -ForegroundColor $(if($missing.Count -eq 0){'Green'}else{'Yellow'})
    
    if ($missing.Count -gt 0) {
        Write-Host ""
        Write-Host "Missing Scripts:" -ForegroundColor Red
        foreach ($script in $missing) {
            Write-Host "  - $script" -ForegroundColor Red
        }
    }
    
    return $missing.Count -eq 0
}

function Export-ToolingIndex {
    $categories = Get-ScriptCategories
    
    $index = @{
        SuiteVersion = $ToolingSuite.Version
        GeneratedAt = Get-Date -Format "o"
        Categories = $categories
        QuickReference = @{
            Build = "rawrxd-cli.ps1 build <full|quick|clean|release>"
            Test = "rawrxd-cli.ps1 test <all|unit|integration|smoke>"
            Deploy = "rawrxd-cli.ps1 deploy <staging|production|canary>"
            Analyze = "rawrxd-cli.ps1 analyze <unlinked|complexity|dependencies>"
            Monitor = "rawrxd-cli.ps1 monitor <start|status|alerts>"
            Docs = "rawrxd-cli.ps1 docs <generate|serve|api>"
            Model = "rawrxd-cli.ps1 model <list|add|remove|verify>"
            Quality = "rawrxd-cli.ps1 quality <check|fix|report>"
            Health = "rawrxd-cli.ps1 health <check|cleanup>"
            Clean = "rawrxd-cli.ps1 clean <all|build|cache|logs>"
        }
    }
    
    $outputFile = "tooling-index.json"
    $index | ConvertTo-Json -Depth 10 | Out-File $outputFile
    
    Write-Host ""
    Write-Success "Tooling index exported: $outputFile"
}

# Main execution
function Main {
    if ($ListScripts) {
        Show-ScriptList
    } elseif ($ShowStats) {
        Show-Statistics
    } elseif ($ValidateInstallation) {
        $valid = Test-Installation
        exit $(if($valid){0}else{1})
    } elseif ($GenerateIndex) {
        Export-ToolingIndex
    } else {
        Show-Overview
    }
}

Main
