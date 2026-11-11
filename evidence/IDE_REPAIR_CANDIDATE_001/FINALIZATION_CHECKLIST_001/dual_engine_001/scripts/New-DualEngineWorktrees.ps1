#Requires -Version 5.1
<#
.SYNOPSIS
  Safe helper to create isolated strata-agent / ollama-review git worktrees.
.NOTES
  PROMOTE=0. Does nothing unless -ConfirmCreate is passed.
  Never writes into the main tree as a dual-engine session root.
  Placeholders under dual_engine_001\worktree_placeholders are NOT live worktrees.
#>
[CmdletBinding()]
param(
    [string]$RepoRoot = "F:\rawrxd",
    [string]$WorktreeRoot = "F:\rawrxd\.worktrees\dual_engine_001",
    [string]$StrataName = "strata-agent",
    [string]$OllamaName = "ollama-review",
    [string]$StrataBranch = "dual/strata-agent",
    [string]$OllamaBranch = "dual/ollama-review",
    [switch]$ConfirmCreate,
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"
function Fail([string]$m) { Write-Error $m; exit 2 }

Write-Host "PROMOTE=0"
Write-Host "DUAL_ENGINE_WORKTREE_HELPER"
Write-Host "RepoRoot=$RepoRoot"
Write-Host "WorktreeRoot=$WorktreeRoot"

if (-not (Test-Path -LiteralPath $RepoRoot)) { Fail "RepoRoot missing: $RepoRoot" }
$inside = & git -C $RepoRoot rev-parse --is-inside-work-tree 2>$null
if ($inside -ne "true") { Fail "RepoRoot is not a git work tree: $RepoRoot" }

$strataPath = Join-Path $WorktreeRoot $StrataName
$ollamaPath = Join-Path $WorktreeRoot $OllamaName

if (-not $ConfirmCreate) {
    Write-Host "DRY_PLAN_ONLY=1 (pass -ConfirmCreate to execute)"
    Write-Host "PLAN_CMD_1=git -C `"$RepoRoot`" worktree add -b $StrataBranch `"$strataPath`""
    Write-Host "PLAN_CMD_2=git -C `"$RepoRoot`" worktree add -b $OllamaBranch `"$ollamaPath`""
    Write-Host "NO_SIMULTANEOUS_WRITE_SAME_TREE=1"
    Write-Host "NEXT_EXECUTABLE_GATE=G1_STRATA_STRUCTURED_TOOL_ROUNDTRIP"
    exit 0
}

if ($WhatIf) {
    Write-Host "WHATIF=1; no git worktree mutations"
    exit 0
}

New-Item -ItemType Directory -Force -Path $WorktreeRoot | Out-Null
if (Test-Path -LiteralPath $strataPath) { Fail "Refusing overwrite: $strataPath exists" }
if (Test-Path -LiteralPath $ollamaPath) { Fail "Refusing overwrite: $ollamaPath exists" }

& git -C $RepoRoot worktree add -b $StrataBranch $strataPath
if ($LASTEXITCODE -ne 0) { Fail "strata worktree add failed" }
& git -C $RepoRoot worktree add -b $OllamaBranch $ollamaPath
if ($LASTEXITCODE -ne 0) { Fail "ollama worktree add failed" }

& git -C $RepoRoot worktree list
$topA = & git -C $strataPath rev-parse --show-toplevel
$topB = & git -C $ollamaPath rev-parse --show-toplevel
Write-Host "STRATA_TOPLEVEL=$topA"
Write-Host "OLLAMA_TOPLEVEL=$topB"
if ($topA -eq $topB) { Fail "Isolation check failed: identical toplevels" }
Write-Host "ISOLATION_OK=1"
Write-Host "PROMOTE=0"
Write-Host "NEXT_EXECUTABLE_GATE=G1_STRATA_STRUCTURED_TOOL_ROUNDTRIP"
