# Commit and Push Script for RawrXD Sovereign Toolchain Updates
# Run this from D:\rawrxd

param(
    [string]$CommitMessage = "Sovereign Toolchain: Bootstrap architecture, certification pipeline, compiler-neutral layer",
    [switch]$Push = $true,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     RawrXD Git Commit & Push - Sovereign Toolchain Update     ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check if we're in a git repository
if (-not (Test-Path .git)) {
    Write-Host "❌ Error: Not a git repository. Run from D:\rawrxd" -ForegroundColor Red
    exit 1
}

# Check git status
Write-Host "[1/5] Checking git status..." -ForegroundColor Yellow
$status = git status --short
if ($status) {
    Write-Host "Modified files:" -ForegroundColor White
    $status | ForEach-Object { Write-Host "  $_" }
} else {
    Write-Host "⚠️ No changes detected" -ForegroundColor Yellow
    exit 0
}

# Stage all changes
Write-Host "`n[2/5] Staging changes..." -ForegroundColor Yellow
if ($DryRun) {
    Write-Host "  (Dry run - would execute: git add -A)" -ForegroundColor Gray
} else {
    git add -A
    Write-Host "  ✅ All changes staged" -ForegroundColor Green
}

# Show what will be committed
Write-Host "`n[3/5] Changes to be committed:" -ForegroundColor Yellow
if ($DryRun) {
    Write-Host "  (Dry run - showing git diff --cached --stat)" -ForegroundColor Gray
    git diff --cached --stat 2>$null || git diff --stat
} else {
    git diff --cached --stat | ForEach-Object { Write-Host "  $_" }
}

# Commit
Write-Host "`n[4/5] Committing..." -ForegroundColor Yellow
Write-Host "  Message: $CommitMessage" -ForegroundColor White

if ($DryRun) {
    Write-Host "  (Dry run - would execute: git commit -m \"$CommitMessage\")" -ForegroundColor Gray
} else {
    git commit -m "$CommitMessage"
    Write-Host "  ✅ Committed successfully" -ForegroundColor Green
}

# Push
if ($Push) {
    Write-Host "`n[5/5] Pushing to GitHub..." -ForegroundColor Yellow
    $branch = git branch --show-current
    Write-Host "  Branch: $branch" -ForegroundColor White
    
    if ($DryRun) {
        Write-Host "  (Dry run - would execute: git push origin $branch)" -ForegroundColor Gray
    } else {
        git push origin $branch
        Write-Host "  ✅ Pushed to origin/$branch" -ForegroundColor Green
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
if ($DryRun) {
    Write-Host "DRY RUN COMPLETE" -ForegroundColor Yellow
    Write-Host "Remove -DryRun to execute" -ForegroundColor Yellow
} else {
    Write-Host "✅ COMMIT & PUSH COMPLETE" -ForegroundColor Green
}
Write-Host "========================================" -ForegroundColor Cyan
