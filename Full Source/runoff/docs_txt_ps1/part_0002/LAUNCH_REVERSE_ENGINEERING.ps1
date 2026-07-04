#requires -Version 7.0
<#
.SYNOPSIS
    Quick launcher for Reverse Engineering Master
.DESCRIPTION
    Simple menu-driven launcher for common operations
#>

Clear-Host

$banner = @"

██████╗ ███████╗██╗   ██╗███████╗██████╗ ███████╗███████╗
██╔══██╗██╔════╝██║   ██║██╔════╝██╔══██╗██╔════╝██╔════╝
██████╔╝█████╗  ██║   ██║█████╗  ██████╔╝███████╗█████╗  
██╔══██╗██╔══╝  ╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║██╔══╝  
██║  ██║███████╗ ╚████╔╝ ███████╗██║  ██║███████║███████╗
╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝
                                                          
███████╗███╗   ██╗ ██████╗ ██╗███╗   ██╗███████╗         
██╔════╝████╗  ██║██╔════╝ ██║████╗  ██║██╔════╝         
█████╗  ██╔██╗ ██║██║  ███╗██║██╔██╗ ██║█████╗           
██╔══╝  ██║╚██╗██║██║   ██║██║██║╚██╗██║██╔══╝           
███████╗██║ ╚████║╚██████╔╝██║██║ ╚████║███████╗         
╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚══════╝         
                                                          
    RawrXD IDE - Reverse Engineering Master System
    Cursor + Codex Integration | Auto + Manual Modes
    
"@

Write-Host $banner -ForegroundColor Cyan

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
Write-Host "                    QUICK LAUNCHER MENU                        " -ForegroundColor Magenta
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
Write-Host ""
Write-Host "  [1] 🔍 Analyze Completeness" -ForegroundColor White
Write-Host "      Check IDE status and get recommendations" -ForegroundColor Gray
Write-Host ""
Write-Host "  [2] ⚡ Auto-Fix Everything" -ForegroundColor White
Write-Host "      Automatically integrate all features" -ForegroundColor Gray
Write-Host ""
Write-Host "  [3] 🎮 Interactive Mode" -ForegroundColor White
Write-Host "      Manual control with interactive menu" -ForegroundColor Gray
Write-Host ""
Write-Host "  [4] 🎯 Cursor Integration Only" -ForegroundColor White
Write-Host "      Reverse engineer and integrate Cursor" -ForegroundColor Gray
Write-Host ""
Write-Host "  [5] 🔧 Codex Integration Only" -ForegroundColor White
Write-Host "      Reverse engineer and integrate Codex" -ForegroundColor Gray
Write-Host ""
Write-Host "  [6] 🚀 Complete Integration" -ForegroundColor White
Write-Host "      Everything at once (Cursor + Codex)" -ForegroundColor Gray
Write-Host ""
Write-Host "  [7] 📊 View Reports" -ForegroundColor White
Write-Host "      Show completeness and integration reports" -ForegroundColor Gray
Write-Host ""
Write-Host "  [8] 🏗️  Build IDE After Integration" -ForegroundColor White
Write-Host "      Run build system after integration" -ForegroundColor Gray
Write-Host ""
Write-Host "  [9] 📚 Show Documentation" -ForegroundColor White
Write-Host "      Open quick start guide" -ForegroundColor Gray
Write-Host ""
Write-Host "  [0] ❌ Exit" -ForegroundColor White
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta

$choice = Read-Host "`nSelect option (0-9)"

$projectRoot = "d:\lazy init ide"

switch ($choice) {
    "1" {
        Write-Host "`n▶ Running completeness analysis..." -ForegroundColor Cyan
        & "$projectRoot\REVERSE_ENGINEERING_MASTER.ps1" -Mode analyze
        Read-Host "`nPress Enter to continue"
    }
    "2" {
        Write-Host "`n▶ Running automatic integration..." -ForegroundColor Cyan
        Write-Host "This will auto-detect and integrate all missing features.`n" -ForegroundColor Yellow
        $confirm = Read-Host "Continue? (y/n)"
        if ($confirm -eq 'y') {
            & "$projectRoot\REVERSE_ENGINEERING_MASTER.ps1" -Mode auto -AutoDetect -IntegrateAll -Verbose
        }
        Read-Host "`nPress Enter to continue"
    }
    "3" {
        Write-Host "`n▶ Launching interactive mode..." -ForegroundColor Cyan
        & "$projectRoot\REVERSE_ENGINEERING_MASTER.ps1" -Mode manual -Interactive
    }
    "4" {
        Write-Host "`n▶ Running Cursor integration..." -ForegroundColor Cyan
        $confirm = Read-Host "This will reverse engineer Cursor and integrate features. Continue? (y/n)"
        if ($confirm -eq 'y') {
            & "$projectRoot\REVERSE_ENGINEERING_MASTER.ps1" -Mode cursor -IntegrateAll -Verbose
        }
        Read-Host "`nPress Enter to continue"
    }
    "5" {
        Write-Host "`n▶ Running Codex integration..." -ForegroundColor Cyan
        $confirm = Read-Host "This will reverse engineer Codex and integrate features. Continue? (y/n)"
        if ($confirm -eq 'y') {
            & "$projectRoot\REVERSE_ENGINEERING_MASTER.ps1" -Mode codex -IntegrateAll -Verbose
        }
        Read-Host "`nPress Enter to continue"
    }
    "6" {
        Write-Host "`n▶ Running complete integration..." -ForegroundColor Cyan
        Write-Host "This will integrate everything: Cursor + Codex + all features.`n" -ForegroundColor Yellow
        $confirm = Read-Host "Continue? (y/n)"
        if ($confirm -eq 'y') {
            & "$projectRoot\REVERSE_ENGINEERING_MASTER.ps1" -Mode all -Verbose
        }
        Read-Host "`nPress Enter to continue"
    }
    "7" {
        Write-Host "`n▶ Viewing reports..." -ForegroundColor Cyan
        Write-Host "`n--- COMPLETENESS REPORT ---" -ForegroundColor Yellow
        if (Test-Path "$projectRoot\reverse_engineering_reports\completeness_analysis.json") {
            Get-Content "$projectRoot\reverse_engineering_reports\completeness_analysis.json" | ConvertFrom-Json | Format-List
        } else {
            Write-Host "No completeness report found. Run analysis first." -ForegroundColor Red
        }
        Write-Host "`n--- INTEGRATION MANIFEST ---" -ForegroundColor Yellow
        if (Test-Path "$projectRoot\reverse_engineering_reports\integration_manifest.json") {
            Get-Content "$projectRoot\reverse_engineering_reports\integration_manifest.json" | ConvertFrom-Json | Format-List
        } else {
            Write-Host "No integration manifest found. Run integration first." -ForegroundColor Red
        }
        Read-Host "`nPress Enter to continue"
    }
    "8" {
        Write-Host "`n▶ Running build system..." -ForegroundColor Cyan
        Write-Host "`nBuild modes:" -ForegroundColor Yellow
        Write-Host "  [1] Quick build (2-5 minutes)" -ForegroundColor White
        Write-Host "  [2] Production build (15-30 minutes)" -ForegroundColor White
        $buildChoice = Read-Host "Select build mode (1-2)"
        
        $buildMode = $(if ($buildChoice -eq "1") { "quick" } else { "production" }
        & "$projectRoot\BUILD_ORCHESTRATOR.ps1" -Mode $buildMode
        Read-Host "`nPress Enter to continue"
    }
    "9" {
        Write-Host "`n▶ Opening documentation..." -ForegroundColor Cyan
        if (Test-Path "$projectRoot\REVERSE_ENGINEERING_QUICK_START.md") {
            notepad "$projectRoot\REVERSE_ENGINEERING_QUICK_START.md"
        } else {
            Write-Host "Documentation not found!" -ForegroundColor Red
        }
        Read-Host "`nPress Enter to continue"
    }
    "0" {
        Write-Host "`nExiting..." -ForegroundColor Cyan
        Start-Sleep -Seconds 1
        return
    }
    default {
        Write-Host "`n❌ Invalid choice. Please select 0-9." -ForegroundColor Red
        Start-Sleep -Seconds 2
    }
}

# Loop back to menu if not exiting
if ($choice -ne "0") {
    & "$PSCommandPath"
}
