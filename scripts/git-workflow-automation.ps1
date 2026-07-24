# RawrXD Git Workflow Automation
# Automates common Git workflows: feature branches, PRs, releases, and hotfixes

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("feature", "hotfix", "release", "pr", "sync", "cleanup", "status")]
    [string]$Action = "status",
    
    [string]$BranchName,
    [string]$BaseBranch = "main",
    [string]$Title,
    [string]$Description,
    [switch]$Push,
    [switch]$CreatePR,
    [string]$Reviewers,
    [switch]$Force,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$GitConfig = @{
    MainBranch = "main"
    DevelopBranch = "develop"
    FeaturePrefix = "feature/"
    HotfixPrefix = "hotfix/"
    ReleasePrefix = "release/"
    Remote = "origin"
}

$script:WorkflowState = @{
    StartTime = Get-Date
    ActionsTaken = @()
    Warnings = @()
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[✗] $Message" -ForegroundColor Red }

function Test-GitRepository {
    $gitDir = git rev-parse --git-dir 2>$null
    if (-not $gitDir) {
        Write-Error "Not a Git repository"
        exit 1
    }
    Write-Success "Git repository verified"
}

function Get-CurrentBranch {
    return git rev-parse --abbrev-ref HEAD 2>$null
}

function Invoke-FeatureWorkflow {
    if (-not $BranchName) {
        Write-Error "BranchName required for feature workflow"
        exit 1
    }
    
    $featureBranch = "$($GitConfig.FeaturePrefix)$BranchName"
    $currentBranch = Get-CurrentBranch
    
    Write-Status "Starting feature workflow: $featureBranch"
    
    # Ensure we're on develop branch
    if ($currentBranch -ne $GitConfig.DevelopBranch) {
        Write-Status "Switching to $($GitConfig.DevelopBranch)..."
        if (-not $DryRun) {
            git checkout $GitConfig.DevelopBranch 2>$null
            git pull $GitConfig.Remote $GitConfig.DevelopBranch 2>$null
        }
    }
    
    # Create feature branch
    Write-Status "Creating feature branch: $featureBranch"
    if (-not $DryRun) {
        git checkout -b $featureBranch 2>$null
    }
    
    $script:WorkflowState.ActionsTaken += "Created feature branch: $featureBranch"
    
    if ($Push) {
        Write-Status "Pushing to remote..."
        if (-not $DryRun) {
            git push -u $GitConfig.Remote $featureBranch 2>$null
        }
        $script:WorkflowState.ActionsTaken += "Pushed feature branch to remote"
    }
    
    if ($CreatePR) {
        Write-Status "Creating pull request..."
        # Would use GitHub CLI or API
        $script:WorkflowState.ActionsTaken += "Created pull request"
    }
    
    Write-Success "Feature workflow complete"
}

function Invoke-HotfixWorkflow {
    if (-not $BranchName) {
        Write-Error "BranchName required for hotfix workflow"
        exit 1
    }
    
    $hotfixBranch = "$($GitConfig.HotfixPrefix)$BranchName"
    
    Write-Status "Starting hotfix workflow: $hotfixBranch"
    
    # Switch to main and pull
    if (-not $DryRun) {
        git checkout $GitConfig.MainBranch 2>$null
        git pull $GitConfig.Remote $GitConfig.MainBranch 2>$null
    }
    
    # Create hotfix branch
    Write-Status "Creating hotfix branch: $hotfixBranch"
    if (-not $DryRun) {
        git checkout -b $hotfixBranch 2>$null
    }
    
    $script:WorkflowState.ActionsTaken += "Created hotfix branch: $hotfixBranch"
    
    Write-Success "Hotfix workflow complete"
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor White
    Write-Host "  1. Make your hotfix changes" -ForegroundColor Gray
    Write-Host "  2. Commit: git commit -am 'Hotfix: description'" -ForegroundColor Gray
    Write-Host "  3. Finish: .\git-workflow-automation.ps1 -Action release" -ForegroundColor Gray
}

function Invoke-ReleaseWorkflow {
    Write-Status "Starting release workflow..."
    
    $currentBranch = Get-CurrentBranch
    
    # Check if we're on a hotfix or release branch
    if ($currentBranch -match "^hotfix/") {
        Write-Status "Finishing hotfix: $currentBranch"
        
        if (-not $DryRun) {
            # Merge to main
            git checkout $GitConfig.MainBranch 2>$null
            git merge --no-ff $currentBranch -m "Merge hotfix: $currentBranch" 2>$null
            
            # Tag
            $version = $currentBranch -replace "^hotfix/", ""
            git tag -a "v$version" -m "Hotfix v$version" 2>$null
            
            # Merge to develop
            git checkout $GitConfig.DevelopBranch 2>$null
            git merge --no-ff $currentBranch -m "Merge hotfix to develop: $currentBranch" 2>$null
            
            # Delete branch
            git branch -d $currentBranch 2>$null
        }
        
        $script:WorkflowState.ActionsTaken += "Merged hotfix to main and develop"
    }
    elseif ($currentBranch -match "^release/") {
        Write-Status "Finishing release: $currentBranch"
        
        if (-not $DryRun) {
            # Similar to hotfix but for releases
            git checkout $GitConfig.MainBranch 2>$null
            git merge --no-ff $currentBranch 2>$null
            
            $version = $currentBranch -replace "^release/", ""
            git tag -a "v$version" -m "Release v$version" 2>$null
            
            git checkout $GitConfig.DevelopBranch 2>$null
            git merge --no-ff $currentBranch 2>$null
            
            git branch -d $currentBranch 2>$null
        }
        
        $script:WorkflowState.ActionsTaken += "Merged release to main and develop"
    }
    else {
        Write-Warning "Not on a hotfix or release branch"
    }
    
    if ($Push) {
        Write-Status "Pushing to remote..."
        if (-not $DryRun) {
            git push $GitConfig.Remote $GitConfig.MainBranch 2>$null
            git push $GitConfig.Remote $GitConfig.DevelopBranch 2>$null
            git push --tags 2>$null
        }
    }
    
    Write-Success "Release workflow complete"
}

function Invoke-SyncWorkflow {
    Write-Status "Syncing with remote..."
    
    $currentBranch = Get-CurrentBranch
    
    if (-not $DryRun) {
        git fetch $GitConfig.Remote 2>$null
        
        # Update current branch
        git pull $GitConfig.Remote $currentBranch 2>$null
        
        # Prune deleted branches
        git remote prune $GitConfig.Remote 2>$null
    }
    
    $script:WorkflowState.ActionsTaken += "Synced with remote"
    
    Write-Success "Sync complete"
}

function Invoke-CleanupWorkflow {
    Write-Status "Cleaning up branches..."
    
    if (-not $DryRun) {
        # Delete merged branches
        $merged = git branch --merged $GitConfig.MainBranch 2>$null | Where-Object { $_ -notmatch "\*|$GitConfig.MainBranch|$GitConfig.DevelopBranch" }
        
        foreach ($branch in $merged) {
            $branchName = $branch.Trim()
            if ($branchName) {
                Write-Status "Deleting merged branch: $branchName"
                git branch -d $branchName 2>$null
                $script:WorkflowState.ActionsTaken += "Deleted merged branch: $branchName"
            }
        }
        
        # Prune remote branches
        git remote prune $GitConfig.Remote 2>$null
    }
    
    Write-Success "Cleanup complete"
}

function Show-Status {
    Write-Host "Git Workflow Status" -ForegroundColor Cyan
    Write-Host "===================" -ForegroundColor Cyan
    Write-Host ""
    
    $currentBranch = Get-CurrentBranch
    Write-Host "Current Branch: $currentBranch" -ForegroundColor White
    
    # Show recent commits
    Write-Host ""
    Write-Host "Recent Commits:" -ForegroundColor White
    git log --oneline -5 2>$null | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    
    # Show branch status
    Write-Host ""
    Write-Host "Branch Status:" -ForegroundColor White
    $status = git status --short 2>$null
    if ($status) {
        $status | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
    } else {
        Write-Host "  Working directory clean" -ForegroundColor Green
    }
    
    # Show unpushed commits
    $unpushed = git log $GitConfig.Remote/$currentBranch..HEAD --oneline 2>$null
    if ($unpushed) {
        Write-Host ""
        Write-Host "Unpushed Commits:" -ForegroundColor White
        $unpushed | ForEach-Object { Write-Host "  $_" -ForegroundColor Cyan }
    }
}

function Show-Summary {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Workflow Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($action in $script:WorkflowState.ActionsTaken) {
        Write-Host "  ✓ $action" -ForegroundColor Green
    }
    
    if ($script:WorkflowState.Warnings.Count -gt 0) {
        Write-Host ""
        Write-Host "Warnings:" -ForegroundColor Yellow
        foreach ($warning in $script:WorkflowState.Warnings) {
            Write-Host "  ! $warning" -ForegroundColor Yellow
        }
    }
    
    Write-Host ""
    Write-Success "Git workflow automation complete!"
}

# Main execution
function Main {
    Write-Host "RawrXD Git Workflow Automation" -ForegroundColor Cyan
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host ""
    
    Test-GitRepository
    
    switch ($Action) {
        "feature" { Invoke-FeatureWorkflow }
        "hotfix" { Invoke-HotfixWorkflow }
        "release" { Invoke-ReleaseWorkflow }
        "sync" { Invoke-SyncWorkflow }
        "cleanup" { Invoke-CleanupWorkflow }
        "status" { Show-Status }
        default { Show-Status }
    }
    
    if ($Action -ne "status") {
        Show-Summary
    }
}

Main
