<#
.SYNOPSIS
  RawrXD agent development coordination mechanism.

.DESCRIPTION
  Prevents independent coding agents from overwriting one another by giving each
  implementation package a single exclusive owner. Ownership is acquired through
  an atomic lock-file create (FileMode.CreateNew) so two agents racing for the
  same package cannot both win. A JSON registry mirrors ownership for status
  reporting; the lock file remains the source of truth.

  Each agent is expected to work in its OWN git worktree with its OWN build
  directory and test workspace. This tool only arbitrates *package ownership*;
  it does not touch source, build state, or git.

.COMMANDS
  status                          Show registry + backlog.
  next                            Print the next unclaimed (or stale) backlog item.
  claim     -Agent <id> -Item <id> -Worktree <p> -Branch <b> [-Pid <n>]
                                  Atomically claim a package. Fails if owned.
  release   -Agent <id> -Item <id>  Release a package you own.
  heartbeat -Agent <id> -Item <id>  Update liveness (call periodically).
  reclaim   -Agent <id> -Item <id>  Force-take a STALE claim (owner gone).

.NOTES
  No external dependencies. PowerShell 5.1+ compatible.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('status', 'next', 'claim', 'release', 'heartbeat', 'reclaim')]
    [string]$Command = 'status',

    [string]$Agent,
    [string]$Item,
    [string]$Worktree,
    [string]$Branch,
    [int]$OwnerPid,
    [int]$StaleMinutes = 30
)

$ErrorActionPreference = 'Stop'

# --- Paths -------------------------------------------------------------------
# Backlog is committed (shared via git, changed through reviewed commits).
# Runtime ownership state (registry + locks) is SHARED across all worktrees via
# the git common dir, so every agent sees the same ownership regardless of which
# worktree it runs from.
$Root     = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)   # tools/agent_coord -> repo root
$CoordDir = Join-Path $Root 'tools\agent_coord'
$Backlog  = Join-Path $CoordDir 'backlog.json'
$StateDir = $null
try {
    $gcd = (& git -C $Root rev-parse --git-common-dir 2>$null)
    if ($LASTEXITCODE -eq 0 -and $gcd) {
        if (-not [System.IO.Path]::IsPathRooted($gcd)) { $gcd = Join-Path $Root $gcd }
        $StateDir = Join-Path $gcd 'agent_coord'
    }
}
catch { }
if (-not $StateDir) { $StateDir = Join-Path $CoordDir 'state' }
$Registry = Join-Path $StateDir 'registry.json'
$LocksDir = Join-Path $StateDir 'locks'

function Ensure-Dirs {
    if (-not (Test-Path -LiteralPath $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
    if (-not (Test-Path -LiteralPath $LocksDir)) { New-Item -ItemType Directory -Path $LocksDir -Force | Out-Null }
}

function Read-Json($path) {
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $raw = Get-Content -LiteralPath $path -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    return ($raw | ConvertFrom-Json)
}

function Write-Json($path, $obj) {
    # Atomic: write temp then move over target.
    $tmp = "$path.tmp.$OwnerPid"
    ($obj | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $tmp -Encoding UTF8
    Move-Item -LiteralPath $tmp -Destination $path -Force
}

function Load-Registry {
    $r = Read-Json $Registry
    if ($null -eq $r) {
        $r = [pscustomobject]@{ version = 1; items = [pscustomobject]@{} }
    }
    if ($null -eq $r.items) {
        $r | Add-Member -NotePropertyName items -NotePropertyValue ([pscustomobject]@{}) -Force
    }
    return $r
}

function Save-Registry($r) { Write-Json $Registry $r }

function Lock-Path($itemId) { Join-Path $LocksDir "$itemId.lock" }

function Test-ProcessAlive([int]$procId) {
    if ($procId -le 0) { return $false }
    return ($null -ne (Get-Process -Id $procId -ErrorAction SilentlyContinue))
}

# Atomic exclusive create. Returns $true only if THIS caller created the lock.
function Acquire-LockFile([string]$itemId) {
    $lp = Lock-Path $itemId
    try {
        $fs = [System.IO.File]::Open($lp, [System.IO.FileMode]::CreateNew,
                                      [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $stamp = "owner=$Agent pid=$OwnerPid at=$((Get-Date).ToString('o'))`r`n"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($stamp)
        $fs.Write($bytes, 0, $bytes.Length)
        $fs.Close()
        return $true
    }
    catch [System.IO.IOException] {
        return $false   # already exists -> someone else won the race
    }
}

function Remove-LockFile([string]$itemId) {
    $lp = Lock-Path $itemId
    if (Test-Path -LiteralPath $lp) { Remove-Item -LiteralPath $lp -Force -ErrorAction SilentlyContinue }
}

# Returns 'free', 'owned', or 'stale' for a backlog item.
function Get-ItemState($r, $itemId) {
    if (-not (Test-Path -LiteralPath (Lock-Path $itemId))) { return 'free' }
    $e = $r.items.$itemId
    if ($null -eq $e) { return 'stale' }   # lock without registry -> orphan
    $ageMin = ((Get-Date) - [datetime]::Parse($e.heartbeat)).TotalMinutes
    if ($ageMin -gt $StaleMinutes) { return 'stale' }
    if (-not (Test-ProcessAlive ([int]$e.pid))) { return 'stale' }
    return 'owned'
}

function Show-Status {
    $r = Load-Registry
    $b = Read-Json $Backlog
    Write-Host "== Backlog / ownership =="
    if ($null -eq $b -or $null -eq $b.items) {
        Write-Host "  (no backlog.json)"
    }
    else {
        foreach ($it in $b.items) {
            $state = Get-ItemState $r $it.id
            $owner = if ($r.items.$($it.id)) { $r.items.$($it.id).owner } else { '-' }
            Write-Host ("  {0,-22} {1,-8} owner={2,-14} {3}" -f $it.id, $it.status, $owner, $state)
        }
    }
    Write-Host "== Lock files =="
    $locks = Get-ChildItem -LiteralPath $LocksDir -Filter *.lock -ErrorAction SilentlyContinue
    if ($locks) { $locks | ForEach-Object { Write-Host ("  " + $_.Name) } }
    else { Write-Host "  (none)" }
}

function Show-Next {
    $r = Load-Registry
    $b = Read-Json $Backlog
    if ($null -eq $b -or $null -eq $b.items) { Write-Host "NO_BACKLOG"; return }
    foreach ($it in $b.items) {
        if ($it.status -eq 'CLOSED') { continue }
        $state = Get-ItemState $r $it.id
        if ($state -eq 'free' -or $state -eq 'stale') {
            Write-Host ("NEXT_ITEM={0} PACKAGE={1} STATE={2} TITLE={3}" -f $it.id, $it.package, $state, $it.title)
            return
        }
    }
    Write-Host "NO_UNCLAIMED_ITEM"
}

function Claim-Item {
    if (-not $Agent -or -not $Item) { throw "claim requires -Agent and -Item" }
    $r = Load-Registry
    $state = Get-ItemState $r $Item
    if ($state -eq 'owned') {
        throw "ITEM_ALREADY_OWNED item=$Item owner=$($r.items.$Item.owner) (reclaim only if stale)"
    }
    if ($state -eq 'stale') { Remove-LockFile $Item }
    if (-not (Acquire-LockFile $Item)) {
        throw "CLAIM_FAILED item=$Item (another agent created the lock concurrently)"
    }
    $now = (Get-Date).ToString('o')
    $entry = [pscustomobject]@{
        owner = $Agent; worktree = $Worktree; branch = $Branch; pid = $OwnerPid
        claimed_at = $now; heartbeat = $now
    }
    $r.items | Add-Member -NotePropertyName $Item -NotePropertyValue $entry -Force
    Save-Registry $r
    Write-Host ("CLAIMED item={0} agent={1} worktree={2} branch={3}" -f $Item, $Agent, $Worktree, $Branch)
}

function Release-Item {
    if (-not $Agent -or -not $Item) { throw "release requires -Agent and -Item" }
    $r = Load-Registry
    $e = $r.items.$Item
    if ($null -ne $e -and $e.owner -ne $Agent) {
        throw "RELEASE_DENIED item=$Item owner=$($e.owner) caller=$Agent"
    }
    Remove-LockFile $Item
    if ($null -ne $e) { $r.items.PSObject.Properties.Remove($Item) }
    Save-Registry $r
    Write-Host ("RELEASED item={0} agent={1}" -f $Item, $Agent)
}

function Heartbeat-Item {
    if (-not $Agent -or -not $Item) { throw "heartbeat requires -Agent and -Item" }
    $r = Load-Registry
    $e = $r.items.$Item
    if ($null -eq $e) { throw "NOT_OWNED item=$Item" }
    if ($e.owner -ne $Agent) { throw "HEARTBEAT_DENIED item=$Item owner=$($e.owner)" }
    $e.heartbeat = (Get-Date).ToString('o')
    Save-Registry $r
    Write-Host ("HEARTBEAT item={0} agent={1} at={2}" -f $Item, $Agent, $e.heartbeat)
}

function Reclaim-Item {
    if (-not $Agent -or -not $Item) { throw "reclaim requires -Agent and -Item" }
    $r = Load-Registry
    if ((Get-ItemState $r $Item) -eq 'owned') {
        throw "RECLAIM_DENIED item=$Item is actively owned (not stale)"
    }
    Remove-LockFile $Item
    if (-not (Acquire-LockFile $Item)) { throw "RECLAIM_FAILED item=$Item" }
    $now = (Get-Date).ToString('o')
    $entry = [pscustomobject]@{
        owner = $Agent; worktree = $Worktree; branch = $Branch; pid = $OwnerPid
        claimed_at = $now; heartbeat = $now
    }
    $r.items | Add-Member -NotePropertyName $Item -NotePropertyValue $entry -Force
    Save-Registry $r
    Write-Host ("RECLAIMED item={0} agent={1}" -f $Item, $Agent)
}

Ensure-Dirs
switch ($Command) {
    'status'    { Show-Status }
    'next'      { Show-Next }
    'claim'     { Claim-Item }
    'release'   { Release-Item }
    'heartbeat' { Heartbeat-Item }
    'reclaim'   { Reclaim-Item }
}