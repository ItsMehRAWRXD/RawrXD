#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Foundation Freeze Cleanup Script
.DESCRIPTION
    Prepares repository for v1.0-foundation-freeze tag by:
    1. Removing generated files from git index
    2. Cleaning temporary files
    3. Verifying .gitignore coverage
    4. Creating clean state for reproducible builds
.NOTES
    Run this BEFORE creating the freeze tag.
    This script modifies the git index but preserves local files.
#>

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Foundation Freeze Cleanup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Track what we do
$Actions = @()

# Step 1: Remove generated files from git index
Write-Host "[STEP 1] Removing generated files from git index..." -ForegroundColor Yellow

$GeneratedPatterns = @(
    "RawrXD-ModelLoader/build/*",
    "*.exe",
    "src/asm/*.obj",
    "test_output_*/*.obj",
    "RawrXD.exe.WebView2/*",
    "RawrXD_v3.*.exe.WebView2/*"
)

$RemovedCount = 0
foreach ($pattern in $GeneratedPatterns) {
    $files = git ls-files | Where-Object { $_ -like $pattern }
    foreach ($file in $files) {
        Write-Host "  Removing from index: $file" -ForegroundColor Gray
        git rm --cached "$file" 2>$null
        if ($LASTEXITCODE -eq 0) {
            $RemovedCount++
        }
    }
}

$Actions += @{ step = 1; action = "Remove generated files"; count = $RemovedCount; status = "DONE" }
Write-Host "  ✓ Removed $RemovedCount files from index" -ForegroundColor Green

# Step 2: Clean temporary files
Write-Host "`n[STEP 2] Cleaning temporary files..." -ForegroundColor Yellow

$TempFiles = Get-ChildItem -Path "." -Filter "__*.txt" -File -ErrorAction SilentlyContinue
$TempCount = 0
foreach ($file in $TempFiles) {
    Write-Host "  Deleting: $($file.Name)" -ForegroundColor Gray
    Remove-Item $file.FullName -Force
    $TempCount++
}

$Actions += @{ step = 2; action = "Clean temp files"; count = $TempCount; status = "DONE" }
Write-Host "  ✓ Deleted $TempCount temporary files" -ForegroundColor Green

# Step 3: Verify .gitignore
Write-Host "`n[STEP 3] Verifying .gitignore coverage..." -ForegroundColor Yellow

$RequiredPatterns = @(
    "*.exe",
    "*.obj",
    "*.dll",
    "*.lib",
    "*.pdb",
    "*.ilk",
    "build/",
    "*.log",
    "*.tmp"
)

$GitignoreContent = Get-Content .gitignore -Raw
$MissingPatterns = @()
foreach ($pattern in $RequiredPatterns) {
    if ($GitignoreContent -notmatch [regex]::Escape($pattern)) {
        $MissingPatterns += $pattern
    }
}

if ($MissingPatterns.Count -eq 0) {
    $Actions += @{ step = 3; action = "Verify .gitignore"; status = "PASS" }
    Write-Host "  ✓ All required patterns present" -ForegroundColor Green
} else {
    $Actions += @{ step = 3; action = "Verify .gitignore"; status = "WARN"; missing = $MissingPatterns }
    Write-Host "  ⚠ Missing patterns: $($MissingPatterns -join ', ')" -ForegroundColor Yellow
}

# Step 4: Check remaining tracked generated files
Write-Host "`n[STEP 4] Checking for remaining generated files..." -ForegroundColor Yellow

$RemainingGenerated = git ls-files | Where-Object { 
    $_ -match "\.(obj|exe|dll|lib|pdb|ilk)$" -or
    $_ -match "\.WebView2/" -or
    $_ -match "RawrXD-ModelLoader/build/"
}

if ($RemainingGenerated.Count -eq 0) {
    $Actions += @{ step = 4; action = "Check remaining generated"; status = "PASS" }
    Write-Host "  ✓ No generated files remain in index" -ForegroundColor Green
} else {
    $Actions += @{ step = 4; action = "Check remaining generated"; status = "WARN"; count = $RemainingGenerated.Count }
    Write-Host "  ⚠ $($RemainingGenerated.Count) generated files still tracked:" -ForegroundColor Yellow
    $RemainingGenerated | Select-Object -First 10 | ForEach-Object { Write-Host "    - $_" -ForegroundColor Gray }
}

# Step 5: Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Cleanup Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

foreach ($action in $Actions) {
    $statusColor = if ($action.status -eq "PASS" -or $action.status -eq "DONE") { "Green" } else { "Yellow" }
    Write-Host "[$($action.step)] $($action.action): $($action.status)" -ForegroundColor $statusColor
}

Write-Host "`nNext steps:" -ForegroundColor White
Write-Host "  1. Review changes: git status" -ForegroundColor Gray
Write-Host "  2. Commit cleanup: git commit -m 'chore: remove generated files from tracking'" -ForegroundColor Gray
Write-Host "  3. Verify build: cmake -B build -G Ninja && cmake --build build" -ForegroundColor Gray
Write-Host "  4. Run tests: ctest --test-dir build" -ForegroundColor Gray
Write-Host "  5. Create tag: git tag -a v1.0-foundation-freeze -m 'Foundation freeze'" -ForegroundColor Gray
Write-Host ""

# Export report
$Report = @{
    timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    actions = $Actions
    removed_from_index = $RemovedCount
    temp_files_deleted = $TempCount
    remaining_generated = $RemainingGenerated.Count
}

$ReportPath = "foundation_freeze_cleanup_report.json"
$Report | ConvertTo-Json -Depth 3 | Set-Content $ReportPath
Write-Host "Report saved to: $ReportPath" -ForegroundColor Gray
