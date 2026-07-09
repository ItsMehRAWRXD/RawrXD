#!/usr/bin/env powershell
#Requires -Version 7.0
<#
.SYNOPSIS
    Consolidates duplicate implementations by archiving old files.
.DESCRIPTION
    Moves duplicate CPUInferenceEngine and AgenticEngine implementations
    to an archive directory, keeping only the unified versions.
.NOTES
    Run this AFTER verifying the unified implementations work correctly.
#>

param(
    [switch]$WhatIf,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# Configuration
$ArchiveDir = "d:\rawrxd\.archived_duplicates"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Files to archive (duplicates to be consolidated)
$Duplicates = @{
    "CPUInferenceEngine" = @(
        "src\cpu_inference_engine_Clean.cpp"
        "src\cpu_inference_engine_Clean.h"
        "src\cpu_inference_engine_fixed.cpp"
        "src\cpu_inference_engine_init_fix.cpp"
        "src\cpu_inference_engine_production.cpp"
        "src\cpu_inference_engine_real.cpp"
    )
    "AgenticEngine" = @(
        "src\agentic_core.h"
        "src\agentic_core.cpp"
        "src\agentic_core_win32.h"
        "src\agentic_executor.h"
        "src\agentic_executor.cpp"
        "src\agentic_bridge.cpp"
    )
    "ExecutionScheduler" = @(
        "src\ExecutionScheduler_v2.h"
        "src\ExecutionScheduler_v2.cpp"
        "src\ExecutionScheduler_PATCH_PLAN.md"
    )
}

function Archive-File {
    param(
        [string]$SourcePath,
        [string]$Component
    )
    
    $fullPath = Join-Path "d:\rawrxd" $SourcePath
    
    if (-not (Test-Path $fullPath)) {
        Write-Host "  ⚠️  Not found: $SourcePath" -ForegroundColor Yellow
        return
    }
    
    $componentDir = Join-Path $ArchiveDir "$Component`_$Timestamp"
    $destPath = Join-Path $componentDir $SourcePath
    
    if ($WhatIf) {
        Write-Host "  [WHATIF] Would move: $SourcePath -> $destPath" -ForegroundColor Cyan
        return
    }
    
    # Create directory structure
    $destDir = Split-Path $destPath -Parent
    if (-not (Test-Path $destDir)) {
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    }
    
    # Move file
    Move-Item -Path $fullPath -Destination $destPath -Force:$Force
    Write-Host "  ✅ Archived: $SourcePath" -ForegroundColor Green
}

function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Duplicate Consolidation Script" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($WhatIf) {
        Write-Host "Running in WHATIF mode - no files will be moved" -ForegroundColor Magenta
        Write-Host ""
    }
    
    # Create archive directory
    if (-not $WhatIf -and -not (Test-Path $ArchiveDir)) {
        New-Item -ItemType Directory -Path $ArchiveDir -Force | Out-Null
        Write-Host "Created archive directory: $ArchiveDir" -ForegroundColor Gray
    }
    
    # Process each component
    $totalFiles = 0
    $archivedFiles = 0
    
    foreach ($component in $Duplicates.Keys) {
        Write-Host "`nProcessing: $component" -ForegroundColor Yellow
        Write-Host "-" * 40
        
        $files = $Duplicates[$component]
        foreach ($file in $files) {
            $totalFiles++
            Archive-File -SourcePath $file -Component $component
        }
    }
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Consolidation Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Total files processed: $totalFiles"
    Write-Host "Archive location: $ArchiveDir"
    
    if ($WhatIf) {
        Write-Host "`nRun without -WhatIf to perform actual consolidation" -ForegroundColor Magenta
    } else {
        Write-Host "`n✅ Consolidation complete!" -ForegroundColor Green
        Write-Host "`nUnified implementations:" -ForegroundColor Yellow
        Write-Host "  - src\inference\InferenceEngine.h/cpp"
        Write-Host "  - src\agentic\Core.h/cpp"
    }
}

# Run main function
Main
