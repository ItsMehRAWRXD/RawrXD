<#
.SYNOPSIS
  Mandatory RawrXD agent startup: provision an isolated environment, atomically
  claim the package, and ENFORCE ownership before any work begins.

.DESCRIPTION
  Every development agent MUST run this before editing source, building, or
  testing. It:
    1. Provisions an isolated worktree (optional) + build dir + test workspace +
       free port + instance id, and atomically claims the package.
    2. Enforces ownership via the pre-edit guard (fails closed if not owner).
    3. Emits the environment the agent must adopt (build dir, test ws, port,
       instance id, receipt dir) and the heartbeat command to run while working.

  This is the enforcement layer: an agent that skips it has no claim, so the
  pre-edit guard (and any hook wired to it) denies its source/build/test actions.

.PARAMETER Agent      Unique agent id (e.g. agent-ide, agent-deep2).
.PARAMETER Item       Backlog package id to own (see backlog.json / 'coord.ps1 next').
.PARAMETER Worktree   Path to this agent's git worktree.
.PARAMETER Branch     Branch for the worktree.
.PARAMETER NewWorktree  Create the worktree via git (else it must already exist).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Agent,
    [Parameter(Mandatory = $true)][string]$Item,
    [Parameter(Mandatory = $true)][string]$Worktree,
    [Parameter(Mandatory = $true)][string]$Branch,
    [switch]$NewWorktree,
    [string]$BuildDir,
    [string]$TestDir,
    [int]$Port
)
$ErrorActionPreference = 'Stop'
$coord = Join-Path $PSScriptRoot 'coord.ps1'

# 1. Provision + atomic claim.
$provArgs = @{ Agent = $Agent; Item = $Item; Worktree = $Worktree; Branch = $Branch }
if ($NewWorktree) { $provArgs.NewWorktree = $true }
if ($BuildDir)    { $provArgs.BuildDir = $BuildDir }
if ($TestDir)     { $provArgs.TestDir = $TestDir }
if ($Port)        { $provArgs.Port = $Port }
& $coord provision @provArgs
if ($LASTEXITCODE -ne 0) { Write-Error "AGENT_STARTUP_FAILED stage=provision"; exit 1 }

# 2. Enforce ownership before any work (fail closed).
& $coord preedit -Agent $Agent -Item $Item
if ($LASTEXITCODE -ne 0) { Write-Error "AGENT_STARTUP_DENIED reason=not-owner"; exit 1 }

# 3. Emit the environment the agent must adopt.
Write-Host ""
Write-Host "AGENT_STARTUP_OK agent=$Agent item=$Item"
Write-Host ("  set BUILD_DIR / TEST_WS / PORT / INSTANCE_ID from the PROVISIONED lines above")
Write-Host ("  RECEIPT_DIR is in the PROVISIONED block")
Write-Host ("  HEARTBEAT (run while working): pwsh `"$coord`" heartbeat -Agent $Agent -Item $Item")
Write-Host ("  BEFORE EACH SOURCE/BUILD/TEST ACTION: pwsh `"$coord`" preedit -Agent $Agent -Item $Item")
Write-Host ("  ON COMPLETION: pwsh `"$coord`" done -Agent $Agent -Item $Item  (releases + closes)")
Write-Host ("  RECEIPT: pwsh `"$coord`" receipt -Item $Item -Commit <sha> -Agent $Agent -Evidence <path>")