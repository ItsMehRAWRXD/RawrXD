<#
.SYNOPSIS
  Non-destructive RawrXD branch reconciliation planner.

.DESCRIPTION
  Analyzes divergence between a branch and a target (default origin/main) and
  emits a SAFE, non-destructive integration plan. It NEVER force-pushes, resets,
  rebases, or rewrites the shared branch. With -Execute it only creates a NEW
  integration branch locally (no push) from the branch tip, leaving the original
  branch and target untouched.

  Handles the critical UNRELATED_HISTORIES case (no common ancestor): a normal
  3-way merge/rebase is impossible, so the plan uses `git merge
  --allow-unrelated-histories` into a throwaway integration branch for review.

.PARAMETER Target    Target ref to reconcile against (default origin/main).
.PARAMETER Branch    Branch ref to reconcile (default current HEAD).
.PARAMETER Execute   Create the local integration branch (still no push).
#>
[CmdletBinding()]
param(
    [string]$Target = 'origin/main',
    [string]$Branch,
    [switch]$Execute
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $Branch) { $Branch = (& git -C $Root rev-parse --abbrev-ref HEAD) }

function Git { param([string[]]$gargs) & git.exe -C $Root @gargs }

$branchTip = (Git @('rev-parse', '--short', $Branch)).Trim()
$targetTip = (Git @('rev-parse', '--short', $Target)).Trim()
Write-Host "BRANCH=$Branch ($branchTip)"
Write-Host "TARGET=$Target ($targetTip)"

# Ahead/behind (left=target-only, right=branch-only).
$counts = (Git @('rev-list', '--left-right', '--count', "$Target...$Branch")).Trim() -split '\s+'
$behind = [int]$counts[0]; $ahead = [int]$counts[1]
Write-Host "AHEAD=$ahead BEHIND=$behind"

# Common ancestor?
$mb = (Git @('merge-base', $Target, $Branch) 2>$null)
$mbExit = $LASTEXITCODE
if ($mbExit -ne 0 -or -not $mb) {
    Write-Host "MERGE_BASE=NONE"
    Write-Host "HISTORIES=UNRELATED"
    Write-Host "STRATEGY=UNRELATED_HISTORIES_NO_COMMON_ANCESTOR"
    Write-Host "  1. Do NOT rebase/merge the shared branch directly (would replay $ahead commits with no base)."
    Write-Host "  2. Create a throwaway integration branch from the branch tip:"
    Write-Host "       git branch integrate/$targetTip-recon $Branch"
    Write-Host "  3. Merge the target in with unrelated-histories (review conflicts):"
    Write-Host "       git merge --allow-unrelated-histories $Target -m 'integrate: $Target into $Branch'"
    Write-Host "  4. Regression-test the integration branch; open a reviewed PR."
    Write-Host "  5. NEVER force-push, reset, or rewrite $Branch or $Target."
    if ($Execute) {
        $intBranch = "integrate/$targetTip-recon"
        Git @('branch', $intBranch, $Branch) | Out-Null
        Write-Host "INTEGRATION_BRANCH_CREATED=$intBranch (local only; not pushed)"
    }
    exit 0
}

Write-Host "MERGE_BASE=$mb"
# Is target already contained in branch (fast-forward possible)?
Git @('merge-base', '--is-ancestor', $Target, $Branch) 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "STATUS=UP_TO_DATE (target is ancestor of branch)"
    exit 0
}
Write-Host "STRATEGY=3WAY_MERGE_INTO_INTEGRATION_BRANCH"
Write-Host "  1. git branch integrate/recon $Branch"
Write-Host "  2. git merge $Target -m 'integrate: $Target into $Branch'  (resolve conflicts)"
Write-Host "  3. Regression-test; open reviewed PR. No force-push/reset/rewrite."
if ($Execute) {
    $intBranch = 'integrate/recon'
    Git @('branch', $intBranch, $Branch) | Out-Null
    Write-Host "INTEGRATION_BRANCH_CREATED=$intBranch (local only; not pushed)"
}