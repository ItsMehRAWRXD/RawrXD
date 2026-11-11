#!/usr/bin/env pwsh
#requires -Version 7.0
# Phase AE.1: Living Documentation Generator
# Automatically generates and maintains documentation

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("scan", "generate", "validate", "sync", "publish")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [string]$SourcePath = ".\src",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\docs"
)

$ErrorActionPreference = "Stop"

# Documentation registry
$DocRegistry = @{
    Sources = @()
    Generated = @()
    LastScan = $null
    LastSync = $null
}

function Write-DocHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase AE.1: Living Documentation Generator                      ║
║  Documentation that evolves with your code                        ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-DocSystem {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    # Load registry
    $registryFile = Join-Path $OutputPath "doc_registry.json"
    if (Test-Path $registryFile) {
        $script:DocRegistry = Get-Content -Path $registryFile -Raw | ConvertFrom-Json -AsHashtable
    }
}

function Save-DocRegistry {
    $registryFile = Join-Path $OutputPath "doc_registry.json"
    $script:DocRegistry | ConvertTo-Json -Depth 10 | Set-Content -Path $registryFile
}

function Invoke-DocScan {
    Write-Host "`nScanning source code for documentation..." -ForegroundColor Yellow
    
    $sources = @()
    
    # Scan for PowerShell files
    $psFiles = Get-ChildItem -Path $SourcePath -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue
    foreach ($file in $psFiles) {
        $content = Get-Content -Path $file.FullName -Raw
        $hasDocs = $content -match "\.SYNOPSIS|\.DESCRIPTION|\.EXAMPLE"
        
        $sources += @{
            Path = $file.FullName
            Type = "PowerShell"
            HasDocumentation = [bool]$hasDocs
            LastModified = $file.LastWriteTime
        }
    }
    
    # Scan for Markdown files
    $mdFiles = Get-ChildItem -Path $SourcePath -Filter "*.md" -Recurse -ErrorAction SilentlyContinue
    foreach ($file in $mdFiles) {
        $sources += @{
            Path = $file.FullName
            Type = "Markdown"
            HasDocumentation = $true
            LastModified = $file.LastWriteTime
        }
    }
    
    $script:DocRegistry.Sources = $sources
    $script:DocRegistry.LastScan = Get-Date -Format "o"
    Save-DocRegistry
    
    Write-Host "  ✓ Scanned $($sources.Count) files" -ForegroundColor Green
    
    $withDocs = ($sources | Where-Object { $_.HasDocumentation }).Count
    $withoutDocs = ($sources | Where-Object { -not $_.HasDocumentation }).Count
    
    Write-Host "  With documentation: $withDocs" -ForegroundColor Green
    Write-Host "  Without documentation: $withoutDocs" -ForegroundColor $(if ($withoutDocs -gt 0) { "Yellow" } else { "Green" })
}

function Invoke-DocGenerate {
    Write-Host "`nGenerating documentation..." -ForegroundColor Yellow
    
    $generated = @()
    
    foreach ($source in $script:DocRegistry.Sources) {
        if ($source.Type -eq "PowerShell" -and -not $source.HasDocumentation) {
            # Generate basic documentation template
            $docContent = @"
# $(Split-Path -Leaf $source.Path)

## Overview

Auto-generated documentation for $(Split-Path -Leaf $source.Path).

## Source

File: $($source.Path)
Last Modified: $($source.LastModified)

## Documentation Status

⚠️ This file needs manual documentation.

## Quick Start

```powershell
# Add usage example here
```

## Parameters

*To be documented*

## Examples

*To be added*

---
*Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")*
"@
            
            $docPath = Join-Path $OutputPath "$(Split-Path -Leaf $source.Path).md"
            $docContent | Set-Content -Path $docPath
            
            $generated += @{
                Source = $source.Path
                Documentation = $docPath
                GeneratedAt = Get-Date -Format "o"
            }
            
            Write-Host "  ✓ Generated: $(Split-Path -Leaf $docPath)" -ForegroundColor Green
        }
    }
    
    $script:DocRegistry.Generated = $generated
    Save-DocRegistry
    
    Write-Host "`n✓ Generated $($generated.Count) documentation files" -ForegroundColor Green
}

function Get-DocStatus {
    Write-Host "`nDocumentation Status" -ForegroundColor Yellow
    Write-Host ""
    
    if ($script:DocRegistry.LastScan) {
        Write-Host "  Last Scan: $([DateTime]::Parse($script:DocRegistry.LastScan).ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor Gray
    }
    
    if ($script:DocRegistry.LastSync) {
        Write-Host "  Last Sync: $([DateTime]::Parse($script:DocRegistry.LastSync).ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor Gray
    }
    
    Write-Host "`n  Total Sources: $($script:DocRegistry.Sources.Count)" -ForegroundColor White
    Write-Host "  Generated Docs: $($script:DocRegistry.Generated.Count)" -ForegroundColor White
}

# Main execution
Write-DocHeader
Initialize-DocSystem

switch ($Action) {
    "scan" { Invoke-DocScan }
    "generate" { Invoke-DocGenerate }
    "validate" { Get-DocStatus }
    "sync" { 
        Invoke-DocScan
        Invoke-DocGenerate
        $script:DocRegistry.LastSync = Get-Date -Format "o"
        Save-DocRegistry
    }
    default { Get-DocStatus }
}

Write-Host "`n✅ Documentation operation complete" -ForegroundColor Green
