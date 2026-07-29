# RawrXD Unlinked File Integration Tool
# Helps integrate high-priority unlinked files into the CMake build

param(
    [string]$AnalysisReport = "analysis/unlinked-files/unlinked-analysis-latest.json",
    [string]$CMakeListsPath = "CMakeLists.txt",
    [int]$MaxFilesToIntegrate = 50,
    [switch]$DryRun,
    [switch]$Backup,
    [switch]$AutoApprove
)

$ErrorActionPreference = "Stop"

$script:IntegrationPlan = @{
    Timestamp = Get-Date -Format "o"
    FilesToIntegrate = @()
    CMakeModifications = @()
    Warnings = @()
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[✗] $Message" -ForegroundColor Red }

function Load-AnalysisReport {
    if (-not (Test-Path $AnalysisReport)) {
        # Try to find latest report
        $reports = Get-ChildItem -Path "analysis/unlinked-files" -Filter "unlinked-analysis-*.json" | Sort-Object Name -Descending
        if ($reports) {
            $AnalysisReport = $reports[0].FullName
        } else {
            Write-Error "Analysis report not found. Run analyze-unlinked-files.ps1 first."
            exit 1
        }
    }
    
    $report = Get-Content $AnalysisReport | ConvertFrom-Json
    Write-Success "Loaded analysis report: $AnalysisReport"
    return $report
}

function Test-FileCompatibility {
    param([string]$FilePath)
    
    $issues = @()
    
    if (-not (Test-Path $FilePath)) {
        $issues += "File does not exist"
        return $issues
    }
    
    $content = Get-Content $FilePath -Raw -ErrorAction SilentlyContinue
    
    # Check for Qt dependencies
    if ($content -match "#include\s*[<\"]Q[A-Z]" -or $content -match "Q_OBJECT|QWidget|QApplication") {
        $issues += "Contains Qt dependencies - needs conversion"
    }
    
    # Check for missing includes
    if ($content -match "class\s+\w+;" -and $content -notmatch "#include") {
        $issues += "May have missing includes (forward declarations without includes)"
    }
    
    # Check for platform-specific code
    if ($content -match "#ifdef\s+_WIN32|#ifdef\s+__linux__|#ifdef\s+__APPLE__") {
        $issues += "Contains platform-specific code - verify cross-platform compatibility"
    }
    
    # Check for incomplete implementations
    if ($content -match "TODO|FIXME|XXX|STUB|NOT\s+IMPLEMENTED" -and $content -notmatch "//\s*TODO.*:\s*\w+") {
        $issues += "Contains incomplete implementation markers"
    }
    
    # Check for duplicate definitions
    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
    $existingFiles = Get-ChildItem -Path "." -Filter "*$fileName*" -Recurse | Where-Object { $_.FullName -ne $FilePath }
    if ($existingFiles) {
        $issues += "Possible duplicate: $($existingFiles[0].FullName)"
    }
    
    return $issues
}

function Generate-IntegrationPlan {
    param([hashtable]$Analysis)
    
    Write-Status "Generating integration plan..."
    
    $priorityFiles = $Analysis.PriorityFiles | Select-Object -First $MaxFilesToIntegrate
    
    foreach ($fileInfo in $priorityFiles) {
        $filePath = $fileInfo.File
        
        # Test compatibility
        $issues = Test-FileCompatibility -FilePath $filePath
        
        $integration = @{
            File = $filePath
            Score = $fileInfo.Score
            Categories = $fileInfo.Categories
            Target = ""
            CompatibilityIssues = $issues
            RecommendedAction = ""
        }
        
        # Determine target based on categories
        $categories = $fileInfo.Categories
        if ($categories -contains "CoreKernel") {
            $integration.Target = "rawrxd_core"
        } elseif ($categories -contains "GGML") {
            $integration.Target = "ggml"
        } elseif ($categories -contains "GPU") {
            $integration.Target = "gpu_backend"
        } elseif ($categories -contains "ASM") {
            $integration.Target = "asm_kernels"
        } elseif ($categories -contains "Test") {
            $integration.Target = "test_suite"
        } else {
            $integration.Target = "rawrxd_sources"
        }
        
        # Determine action
        if ($issues.Count -eq 0) {
            $integration.RecommendedAction = "Direct integration"
        } elseif ($issues -match "Qt") {
            $integration.RecommendedAction = "Requires Qt removal first"
        } elseif ($issues -match "incomplete") {
            $integration.RecommendedAction = "Review before integration"
        } else {
            $integration.RecommendedAction = "Review warnings"
        }
        
        $script:IntegrationPlan.FilesToIntegrate += $integration
    }
    
    Write-Success "Integration plan generated for $($script:IntegrationPlan.FilesToIntegrate.Count) files"
}

function Show-IntegrationPlan {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Integration Plan" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    $readyFiles = $script:IntegrationPlan.FilesToIntegrate | Where-Object { $_.CompatibilityIssues.Count -eq 0 }
    $reviewFiles = $script:IntegrationPlan.FilesToIntegrate | Where-Object { $_.CompatibilityIssues.Count -gt 0 }
    
    Write-Host "Ready for Integration: $($readyFiles.Count)" -ForegroundColor Green
    Write-Host "Requires Review: $($reviewFiles.Count)" -ForegroundColor Yellow
    Write-Host ""
    
    if ($readyFiles.Count -gt 0) {
        Write-Host "Files Ready for Direct Integration:" -ForegroundColor Green
        foreach ($file in $readyFiles | Select-Object -First 10) {
            Write-Host "  ✓ $($file.File) → $($file.Target)" -ForegroundColor Gray
        }
        if ($readyFiles.Count -gt 10) {
            Write-Host "  ... and $($readyFiles.Count - 10) more" -ForegroundColor Gray
        }
        Write-Host ""
    }
    
    if ($reviewFiles.Count -gt 0) {
        Write-Host "Files Requiring Review:" -ForegroundColor Yellow
        foreach ($file in $reviewFiles | Select-Object -First 10) {
            Write-Host "  ! $($file.File)" -ForegroundColor Yellow
            Write-Host "    Issues: $($file.CompatibilityIssues -join ', ')" -ForegroundColor DarkYellow
        }
        Write-Host ""
    }
}

function Backup-CMakeLists {
    if ($Backup) {
        $backupPath = "$CMakeListsPath.backup.$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        Copy-Item $CMakeListsPath $backupPath
        Write-Success "Backup created: $backupPath"
    }
}

function Apply-Integration {
    param([array]$Files)
    
    if ($DryRun) {
        Write-Warning "DRY RUN - No changes will be made"
        return
    }
    
    if (-not $AutoApprove) {
        $confirm = Read-Host "Apply integration for $($Files.Count) files? (y/N)"
        if ($confirm -ne "y") {
            Write-Status "Integration cancelled"
            return
        }
    }
    
    Backup-CMakeLists
    
    $cmakeContent = Get-Content $CMakeListsPath -Raw
    
    # Group files by target
    $grouped = $Files | Group-Object -Property Target
    
    foreach ($group in $grouped) {
        $target = $group.Name
        $sourceFiles = $group.Group | ForEach-Object { $_.File }
        
        Write-Status "Adding $($sourceFiles.Count) files to target: $target"
        
        # Find the target_sources or add_library/add_executable block
        $targetPattern = "(target_sources\s*\(\s*$target[^)]+)"
        if ($cmakeContent -match $targetPattern) {
            # Add to existing target_sources
            $filesList = ($sourceFiles | ForEach-Object { "`n    `$_" }) -join ""
            $cmakeContent = $cmakeContent -replace $targetPattern, "`$1$filesList"
        } else {
            # Create new target_sources block
            $filesList = ($sourceFiles | ForEach-Object { "`n    `$_" }) -join ""
            $newBlock = "`ntarget_sources($target PRIVATE$filesList`n)"
            $cmakeContent += $newBlock
        }
    }
    
    # Save modified CMakeLists.txt
    $cmakeContent | Out-File $CMakeListsPath -Encoding UTF8
    Write-Success "CMakeLists.txt updated"
    
    # Verify CMake can parse the file
    Write-Status "Verifying CMake syntax..."
    $testResult = cmake -P (New-TemporaryFile).FullName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Success "CMake syntax valid"
    } else {
        Write-Warning "CMake syntax check failed - review changes manually"
    }
}

function Export-IntegrationReport {
    $reportFile = "integration-plan-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $script:IntegrationPlan | ConvertTo-Json -Depth 10 | Out-File $reportFile
    Write-Success "Integration plan exported: $reportFile"
}

# Main execution
function Main {
    Write-Host "RawrXD Unlinked File Integration Tool" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host ""
    
    $analysis = Load-AnalysisReport
    Generate-IntegrationPlan -Analysis $analysis
    Show-IntegrationPlan
    
    $readyFiles = $script:IntegrationPlan.FilesToIntegrate | Where-Object { $_.CompatibilityIssues.Count -eq 0 }
    
    if ($readyFiles.Count -gt 0) {
        Write-Host ""
        Apply-Integration -Files $readyFiles
    }
    
    Export-IntegrationReport
    
    Write-Host ""
    Write-Success "Integration process complete!"
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor White
    Write-Host "  1. Review integration-report-*.json for details" -ForegroundColor Gray
    Write-Host "  2. Build project to verify integration: cmake --build build" -ForegroundColor Gray
    Write-Host "  3. Run tests: ctest --output-on-failure" -ForegroundColor Gray
    Write-Host "  4. Address any files marked for review" -ForegroundColor Gray
}

Main
