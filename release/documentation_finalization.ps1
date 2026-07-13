# RawrXD Documentation Finalization
# Phase I Batch 4/5: Final Documentation Review
# Finalizes all documentation before release

param(
    [Parameter()]
    [ValidateSet("Review", "Generate", "Validate", "Sync", "ShowStatus")]
    [string]$Action = "Review",
    
    [Parameter()]
    [string]$Version,
    
    [Parameter()]
    [string]$DocsPath = "$PSScriptRoot\..\docs",
    
    [Parameter()]
    [string]$OutputPath = "$PSScriptRoot\artifacts\docs",
    
    [Parameter()]
    [switch]$FailOnError
)

# Documentation requirements
$DocRequirements = @{
    RequiredFiles = @(
        "README.md",
        "LICENSE",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "docs\getting-started.md",
        "docs\installation.md",
        "docs\configuration.md",
        "docs\api-reference.md",
        "docs\architecture.md",
        "docs\troubleshooting.md"
    )
    
    RequiredSections = @{
        "README.md" = @("Installation", "Usage", "Features", "Contributing", "License")
        "docs\getting-started.md" = @("Prerequisites", "Quick Start", "Next Steps")
        "docs\installation.md" = @("System Requirements", "Installation Steps", "Verification")
    }
    
    MaxFileSizeKB = 500
    RequiredLineCount = 10
}

# Ensure output directory exists
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

function Write-DocLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    $logPath = "$PSScriptRoot\..\logs\documentation"
    if (-not (Test-Path $logPath)) {
        New-Item -ItemType Directory -Path $logPath -Force | Out-Null
    }
    $logFile = Join-Path $logPath "docs_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "SUCCESS" { "Green" }
        "DOCS" { "Cyan" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Test-DocumentationCompleteness {
    Write-DocLog "Checking documentation completeness..." "DOCS"
    
    $results = @{
        Category = "Completeness"
        Passed = 0
        Failed = 0
        Total = $DocRequirements.RequiredFiles.Count
        Missing = @()
        Issues = @()
    }
    
    $basePath = "$PSScriptRoot\.."
    
    foreach ($file in $DocRequirements.RequiredFiles) {
        $fullPath = Join-Path $basePath $file
        
        if (Test-Path $fullPath) {
            $results.Passed++
            Write-DocLog "✓ $file" "SUCCESS"
            
            # Check file size
            $fileInfo = Get-Item $fullPath
            $sizeKB = $fileInfo.Length / 1KB
            if ($sizeKB -gt $DocRequirements.MaxFileSizeKB) {
                $results.Issues += "$file exceeds maximum size ($([math]::Round($sizeKB, 2))KB > $($DocRequirements.MaxFileSizeKB)KB)"
            }
            
            # Check line count
            $lineCount = (Get-Content $fullPath).Count
            if ($lineCount -lt $DocRequirements.RequiredLineCount) {
                $results.Issues += "$file has insufficient content ($lineCount lines < $($DocRequirements.RequiredLineCount))"
            }
            
            # Check required sections
            if ($DocRequirements.RequiredSections.ContainsKey($file)) {
                $content = Get-Content $fullPath -Raw
                $requiredSections = $DocRequirements.RequiredSections[$file]
                foreach ($section in $requiredSections) {
                    if ($content -notmatch "##?\s*$section") {
                        $results.Issues += "$file missing required section: $section"
                    }
                }
            }
        }
        else {
            $results.Failed++
            $results.Missing += $file
            Write-DocLog "✗ $file missing" "ERROR"
        }
    }
    
    return $results
}

function Test-DocumentationQuality {
    Write-DocLog "Checking documentation quality..." "DOCS"
    
    $results = @{
        Category = "Quality"
        FilesChecked = 0
        Issues = @()
        Warnings = @()
    }
    
    $mdFiles = Get-ChildItem -Path "$PSScriptRoot\.." -Filter "*.md" -Recurse -ErrorAction SilentlyContinue
    
    foreach ($file in $mdFiles) {
        $results.FilesChecked++
        $content = Get-Content $file.FullName -Raw
        
        # Check for broken links
        $linkMatches = [regex]::Matches($content, '\[([^\]]+)\]\(([^)]+)\)')
        foreach ($match in $linkMatches) {
            $link = $match.Groups[2].Value
            if ($link -notmatch '^https?://' -and $link -notmatch '^mailto:') {
                # Relative link - check if file exists
                $linkPath = Join-Path $file.DirectoryName $link
                if (-not (Test-Path $linkPath)) {
                    $results.Issues += "Broken link in $($file.Name): $link"
                }
            }
        }
        
        # Check for common markdown issues
        if ($content -match '\t') {
            $results.Warnings += "$($file.Name) contains tabs (use spaces)"
        }
        
        if ($content -match '\s+$') {
            $results.Warnings += "$($file.Name) contains trailing whitespace"
        }
        
        if ($content -match '`\w+`\w+') {
            $results.Warnings += "$($file.Name) may have unspaced inline code"
        }
    }
    
    return $results
}

function Invoke-DocumentationGeneration {
    param([string]$Version)
    
    Write-DocLog "Generating final documentation for v$Version..." "DOCS"
    
    # Generate consolidated documentation
    $consolidated = @"
# RawrXD v$Version Documentation

**Version:** $Version  
**Generated:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [API Reference](#api-reference)
5. [Architecture](#architecture)
6. [Troubleshooting](#troubleshooting)

---

## Overview

RawrXD is a sovereign AI inference runtime with autonomous operations capabilities.

## Installation

See [Installation Guide](docs/installation.md) for detailed instructions.

## Configuration

See [Configuration Guide](docs/configuration.md) for configuration options.

## API Reference

See [API Reference](docs/api-reference.md) for API documentation.

## Architecture

See [Architecture Documentation](docs/architecture.md) for system architecture.

## Troubleshooting

See [Troubleshooting Guide](docs/troubleshooting.md) for common issues.

---

*This documentation was automatically generated for RawrXD v$Version*
"@
    
    $outputFile = Join-Path $OutputPath "DOCUMENTATION_v$Version.md"
    $consolidated | Out-File $outputFile -Encoding UTF8
    
    Write-DocLog "Consolidated documentation generated: $outputFile" "SUCCESS"
    
    return @{
        Path = $outputFile
        Generated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

function Sync-Documentation {
    Write-DocLog "Syncing documentation..." "DOCS"
    
    # Sync generated docs with source
    $generatedDocs = "$PSScriptRoot\..\docs\generated"
    if (Test-Path $generatedDocs) {
        $docs = Get-ChildItem -Path $generatedDocs -Filter "*.md" -ErrorAction SilentlyContinue
        foreach ($doc in $docs) {
            $dest = Join-Path $DocsPath $doc.Name
            Copy-Item -Path $doc.FullName -Destination $dest -Force
            Write-DocLog "Synced: $($doc.Name)" "INFO"
        }
    }
    
    return @{
        Synced = $true
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

function Show-DocumentationStatus {
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║         RawrXD Documentation Finalization Status                ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    # Check required files
    $basePath = "$PSScriptRoot\.."
    $found = 0
    $missing = @()
    
    foreach ($file in $DocRequirements.RequiredFiles) {
        $fullPath = Join-Path $basePath $file
        if (Test-Path $fullPath) {
            $found++
        }
        else {
            $missing += $file
        }
    }
    
    Write-Host "║ Required Files: $found/$($DocRequirements.RequiredFiles.Count)" -ForegroundColor $(if($found -eq $DocRequirements.RequiredFiles.Count){"Green"}else{"Yellow"})
    
    if ($missing.Count -gt 0) {
        Write-Host "║ Missing:" -ForegroundColor Red
        foreach ($file in $missing) {
            Write-Host "║   ✗ $file" -ForegroundColor Red
        }
    }
    
    # Count total documentation
    $mdFiles = (Get-ChildItem -Path $basePath -Filter "*.md" -Recurse -ErrorAction SilentlyContinue).Count
    Write-Host "║ Total Markdown Files: $mdFiles" -ForegroundColor Cyan
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
switch ($Action) {
    "Review" {
        $completeness = Test-DocumentationCompleteness
        $quality = Test-DocumentationQuality
        
        $report = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Completeness = $completeness
            Quality = $quality
            Overall = if ($completeness.Issues.Count -eq 0 -and $quality.Issues.Count -eq 0) { "Passed" } else { "Failed" }
        }
        
        $report | ConvertTo-Json -Depth 10
        
        if ($FailOnError -and $report.Overall -eq "Failed") {
            exit 1
        }
    }
    "Generate" {
        if (-not $Version) {
            Write-DocLog "Version parameter required" "ERROR"
            exit 1
        }
        $result = Invoke-DocumentationGeneration -Version $Version
        $result | ConvertTo-Json
    }
    "Validate" {
        $completeness = Test-DocumentationCompleteness
        $quality = Test-DocumentationQuality
        
        $valid = $completeness.Failed -eq 0 -and $completeness.Issues.Count -eq 0 -and $quality.Issues.Count -eq 0
        
        if ($valid) {
            Write-DocLog "Documentation validation passed" "SUCCESS"
            exit 0
        }
        else {
            Write-DocLog "Documentation validation failed" "ERROR"
            exit 1
        }
    }
    "Sync" {
        $result = Sync-Documentation
        $result | ConvertTo-Json
    }
    "ShowStatus" {
        Show-DocumentationStatus
    }
}
