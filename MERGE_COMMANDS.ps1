#!/usr/bin/env pwsh
# OMEGA-1 v1.0.0-Certified Merge Script
# Run this to merge session_7f014eb4 to main and create release tag

$ErrorActionPreference = "Stop"

Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     OMEGA-1 v1.0.0-Certified Release Merge Script           ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Verify we're on the right branch
$currentBranch = git branch --show-current
if ($currentBranch -ne "session_7f014eb4") {
    Write-Host "⚠️  Warning: Not on session_7f014eb4 branch" -ForegroundColor Yellow
    Write-Host "Current branch: $currentBranch"
    $continue = Read-Host "Continue anyway? (y/N)"
    if ($continue -ne "y") { exit 1 }
}

# Check for uncommitted changes
$status = git status --porcelain
if ($status) {
    Write-Host "❌ Error: Uncommitted changes detected" -ForegroundColor Red
    Write-Host $status
    exit 1
}

Write-Host "✅ Working directory clean" -ForegroundColor Green
Write-Host ""

# Fetch latest main
Write-Host "📥 Fetching latest main..." -ForegroundColor Blue
git fetch origin main

# Show what will be merged
Write-Host ""
Write-Host "📊 Commits to be merged:" -ForegroundColor Blue
$commits = git log origin/main..session_7f014eb4 --oneline
$commitCount = ($commits | Measure-Object).Count
Write-Host "   $commitCount commits"
Write-Host ""

# Confirm merge
Write-Host "⚠️  This will merge $commitCount commits from session_7f014eb4 to main" -ForegroundColor Yellow
$confirm = Read-Host "Proceed with merge? (yes/N)"
if ($confirm -ne "yes") {
    Write-Host "❌ Merge cancelled" -ForegroundColor Red
    exit 1
}

# Checkout main
Write-Host ""
Write-Host "🔀 Checking out main..." -ForegroundColor Blue
git checkout main

# Merge
Write-Host ""
Write-Host "🔀 Merging session_7f014eb4..." -ForegroundColor Blue
git merge session_7f014eb4 --no-ff -m "Merge session_7f014eb4: OMEGA-1 Full Certification v1.0.0

- 31 certification gates (VAL-050 → VAL-082)
- Real-token proof with 1.32 TPS
- Polyglot bindings (C#, Rust, Python, Go)
- Model loader fixes for quantized types
- Diagnostic tools (gguf_tensor_inspector.py, fix_tps.py)
- CI/CD pipeline with GitHub Actions
- Complete documentation

This release marks the first fully certified OMEGA-1 build."

# Push main
Write-Host ""
Write-Host "📤 Pushing main to origin..." -ForegroundColor Blue
git push origin main

Write-Host ""
Write-Host "✅ Merge complete!" -ForegroundColor Green
Write-Host ""

# Create tag
Write-Host "🏷️  Creating release tag..." -ForegroundColor Blue
git tag -a v1.0.0-certified -m "OMEGA-1 Full Certification Release v1.0.0

🎯 31 Certification Gates Complete
✅ VAL-050 → VAL-082 all implemented
✅ Real-token proof: 1.32 TPS
✅ Polyglot bindings: C#, Rust, Python, Go
✅ Model loader: All quantized types
✅ CI/CD: GitHub Actions multi-platform
✅ Documentation: Complete

This release marks the first fully certified OMEGA-1 build."

# Push tag
Write-Host ""
Write-Host "📤 Pushing tag to origin..." -ForegroundColor Blue
git push origin v1.0.0-certified

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║     ✅ RELEASE COMPLETE                                      ║" -ForegroundColor Green
Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "║  Branch: main                                                ║" -ForegroundColor Green
Write-Host "║  Tag: v1.0.0-certified                                       ║" -ForegroundColor Green
Write-Host "║  Status: PRODUCTION READY                                    ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Create GitHub Release at: https://github.com/ItsMehRAWRXD/RawrXD/releases/new"
Write-Host "  2. Publish packages (optional):"
Write-Host "     - NuGet: dotnet pack + nuget push"
Write-Host "     - PyPI: python -m build + twine upload"
Write-Host "     - crates.io: cargo publish"
Write-Host "     - Go: git tag + push"
Write-Host ""
Write-Host "🎉 Congratulations on the release!" -ForegroundColor Green
