# Validate RawrXD codebase is ready for build
# Checks for merge conflicts, missing files, and build prerequisites

$ErrorActionPreference = 'Continue'
$issues = @()
$warnings = @()

Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     RawrXD Build Validation - Pre-Build Checklist         ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# 1. Check for remaining merge conflicts
Write-Host "[1/6] Checking for git merge conflicts..." -ForegroundColor Yellow
$conflictFiles = @()
$allFiles = Get-ChildItem -Path 'd:\rawrxd' -Recurse -File -ErrorAction SilentlyContinue | 
    Where-Object { 
        $_.Extension -notin @('.exe', '.dll', '.obj', '.lib', '.pdb', '.ilk', '.gguf', '.bin', '.idx', '.zip', '.7z', '.png', '.jpg', '.ico', '.tmp', '.log') -and
        $_.FullName -notlike '*\.archive\*' -and 
        $_.FullName -notlike '*\.git\*' -and
        $_.FullName -notlike '*\.worktrees\*'
    }

foreach ($file in $allFiles) {
    try {
        $content = Get-Content -Raw -Path $file.FullName -ErrorAction SilentlyContinue
        if ($content -and ($content -match '<<<<<<< HEAD')) {
            $conflictFiles += $file.FullName
        }
    } catch {}
}

if ($conflictFiles.Count -gt 0) {
    $issues += "Found $($conflictFiles.Count) files with merge conflicts"
    Write-Host "  ❌ FAIL: $($conflictFiles.Count) files with conflicts" -ForegroundColor Red
    $conflictFiles | Select-Object -First 10 | ForEach-Object { Write-Host "    - $_" -ForegroundColor Gray }
    if ($conflictFiles.Count -gt 10) {
        Write-Host "    ... and $($conflictFiles.Count - 10) more" -ForegroundColor Gray
    }
} else {
    Write-Host "  ✅ PASS: No merge conflicts found" -ForegroundColor Green
}

# 2. Check critical source files exist
Write-Host "`n[2/6] Checking critical source files..." -ForegroundColor Yellow
$criticalFiles = @(
    'd:\rawrxd\src\win32app\Win32IDE.cpp',
    'd:\rawrxd\src\win32app\main_win32.cpp',
    'd:\rawrxd\include\agentic_executor.h',
    'd:\rawrxd\include\planning_agent.h',
    'd:\rawrxd\agentic_build\build.ps1'
)

$missingFiles = @()
foreach ($file in $criticalFiles) {
    if (-not (Test-Path $file)) {
        $missingFiles += $file
    }
}

if ($missingFiles.Count -gt 0) {
    $issues += "Missing $($missingFiles.Count) critical source files"
    Write-Host "  ❌ FAIL: $($missingFiles.Count) critical files missing" -ForegroundColor Red
    $missingFiles | ForEach-Object { Write-Host "    - $_" -ForegroundColor Gray }
} else {
    Write-Host "  ✅ PASS: All critical source files present" -ForegroundColor Green
}

# 3. Check build scripts
Write-Host "`n[3/6] Checking build scripts..." -ForegroundColor Yellow
$buildScripts = @(
    'd:\rawrxd\agentic_build\build.ps1',
    'd:\rawrxd\BUILD_ORCHESTRATOR.ps1'
)

$missingScripts = @()
foreach ($script in $buildScripts) {
    if (-not (Test-Path $script)) {
        $missingScripts += $script
    }
}

if ($missingScripts.Count -gt 0) {
    $warnings += "Missing build scripts: $($missingScripts.Count)"
    Write-Host "  ⚠️ WARN: $($missingScripts.Count) build scripts missing" -ForegroundColor Yellow
    $missingScripts | ForEach-Object { Write-Host "    - $_" -ForegroundColor Gray }
} else {
    Write-Host "  ✅ PASS: Build scripts present" -ForegroundColor Green
}

# 4. Check include directories
Write-Host "`n[4/6] Checking include directories..." -ForegroundColor Yellow
$includeDirs = @(
    'd:\rawrxd\include',
    'd:\rawrxd\src',
    'd:\rawrxd\src\win32app'
)

$missingDirs = @()
foreach ($dir in $includeDirs) {
    if (-not (Test-Path $dir)) {
        $missingDirs += $dir
    }
}

if ($missingDirs.Count -gt 0) {
    $issues += "Missing include directories: $($missingDirs.Count)"
    Write-Host "  ❌ FAIL: $($missingDirs.Count) include directories missing" -ForegroundColor Red
} else {
    Write-Host "  ✅ PASS: Include directories present" -ForegroundColor Green
}

# 5. Check for required tools (if in PATH)
Write-Host "`n[5/6] Checking build tools..." -ForegroundColor Yellow
$tools = @('cl', 'link', 'ml64', 'cmake')
$missingTools = @()

foreach ($tool in $tools) {
    $found = Get-Command $tool -ErrorAction SilentlyContinue
    if (-not $found) {
        $missingTools += $tool
    }
}

if ($missingTools.Count -gt 0) {
    $warnings += "Build tools not in PATH: $($missingTools -join ', ')"
    Write-Host "  ⚠️ WARN: Tools not in PATH: $($missingTools -join ', ')" -ForegroundColor Yellow
    Write-Host "    (May still work if using Visual Studio Developer Command Prompt)" -ForegroundColor Gray
} else {
    Write-Host "  ✅ PASS: Build tools available" -ForegroundColor Green
}

# 6. Check .cursorrules
Write-Host "`n[6/6] Checking .cursorrules..." -ForegroundColor Yellow
if (Test-Path 'd:\rawrxd\.cursorrules') {
    $cursorrules = Get-Content 'd:\rawrxd\.cursorrules' -Raw
    if ($cursorrules -match 'Win32/C\+\+20') {
        Write-Host "  ✅ PASS: .cursorrules configured for Win32/C++20" -ForegroundColor Green
    } else {
        $warnings += ".cursorrules may not be properly configured"
        Write-Host "  ⚠️ WARN: .cursorrules configuration unclear" -ForegroundColor Yellow
    }
} else {
    $issues += ".cursorrules file missing"
    Write-Host "  ❌ FAIL: .cursorrules file missing" -ForegroundColor Red
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "VALIDATION SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if ($issues.Count -eq 0 -and $warnings.Count -eq 0) {
    Write-Host "`n✅ ALL CHECKS PASSED" -ForegroundColor Green
    Write-Host "The codebase is ready for build!" -ForegroundColor Green
    Write-Host "`nNext steps:" -ForegroundColor White
    Write-Host "  1. Open 'x64 Native Tools Command Prompt for VS 2022'" -ForegroundColor Gray
    Write-Host "  2. cd D:\rawrxd" -ForegroundColor Gray
    Write-Host "  3. .\BUILD_ORCHESTRATOR.ps1 -Mode quick" -ForegroundColor Gray
    exit 0
} elseif ($issues.Count -eq 0) {
    Write-Host "`n⚠️ BUILD READY WITH WARNINGS" -ForegroundColor Yellow
    Write-Host "Warnings: $($warnings.Count)" -ForegroundColor Yellow
    $warnings | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
    Write-Host "`nThe codebase should build, but review warnings above." -ForegroundColor Yellow
    exit 0
} else {
    Write-Host "`n❌ BUILD BLOCKED" -ForegroundColor Red
    Write-Host "Issues: $($issues.Count)" -ForegroundColor Red
    Write-Host "Warnings: $($warnings.Count)" -ForegroundColor Yellow
    Write-Host "`nPlease resolve the issues above before building." -ForegroundColor Red
    exit 1
}
