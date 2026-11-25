<#
.SYNOPSIS
  RawrXD agent development coordination mechanism (v2).

.DESCRIPTION
  Makes development isolation MANDATORY and race-safe so independent coding
  agents (IDE, Deep2, compression, Vulkan, validation tracks) can progress
  simultaneously without overwriting one another's source, build state, or
  test evidence.

  Core guarantees:
    * Exclusive package ownership via an atomic lock-file create.
    * Race-safe registry mutation (global registry RMW lock) so reclaim and
      heartbeat cannot interleave and corrupt ownership.
    * PID-reuse protection: ownership records the owner's process start time;
      a recycled PID with a different start time is treated as stale.
    * Dependency-aware selection: 'next' only offers items whose deps are CLOSED.
    * Mandatory enforcement: 'preedit' is a pre-edit guard (exit 0 = owned,
      exit 1 = not owned) for hooks / agent startup.
    * Commit-specific acceptance receipts bound to a real commit sha.
    * Provisioner: allocate an isolated worktree + build dir + test workspace +
      free port + instance id in one call.
    * Self-test: N-way concurrent claim to certify atomicity (5-agent).

  No external dependencies. PowerShell 5.1+ compatible.

.COMMANDS
  status
  next
  claim     -Agent <id> -Item <id> [-Worktree <p>] [-Branch <b>] [-OwnerPid <n>]
  release   -Agent <id> -Item <id>
  heartbeat -Agent <id> -Item <id>
  reclaim   -Agent <id> -Item <id> [-OwnerPid <n>]
  done      -Agent <id> -Item <id>   Release + mark CLOSED in backlog.
  preedit   -Agent <id> -Item <id>   Exit 0 if owned, 1 otherwise.
  receipt   -Item <id> -Commit <sha> [-Evidence <path>] [-Agent <id>]
  provision -Agent <id> -Item <id> -Worktree <p> -Branch <b> [-NewWorktree]
            [-BuildDir <p>] [-TestDir <p>] [-Port <n>]
  selftest  [-Item <id>] [-Agents <n>]
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('status','next','claim','release','heartbeat','reclaim','done','preedit','receipt','provision','selftest')]
    [string]$Command = 'status',

    [string]$Agent,
    [string]$Item,
    [string]$Worktree,
    [string]$Branch,
    [int]$OwnerPid,
    [string]$Evidence,
    [string]$Commit,
    [string]$BuildDir,
    [string]$TestDir,
    [int]$Port,
    [switch]$NewWorktree,
    [int]$Agents = 5,
    [int]$StaleMinutes = 30
)

$ErrorActionPreference = 'Stop'

# --- Paths -------------------------------------------------------------------
$Root     = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
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
$Registry    = Join-Path $StateDir 'registry.json'
$LocksDir    = Join-Path $StateDir 'locks'
$RegistryLock = Join-Path $StateDir 'registry.lock'
$ReceiptsDir = Join-Path $StateDir 'receipts'

function Ensure-Dirs {
    foreach ($d in @($StateDir, $LocksDir, $ReceiptsDir)) {
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }
}

function Read-Json($path) {
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $raw = Get-Content -LiteralPath $path -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    return ($raw | ConvertFrom-Json)
}

function Write-Json($path, $obj) {
    $tmp = "$path.tmp.$PID"
    ($obj | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $tmp -Encoding UTF8
    Move-Item -LiteralPath $tmp -Destination $path -Force
}

function Load-Registry {
    $r = Read-Json $Registry
    if ($null -eq $r) { $r = [pscustomobject]@{ version = 2; items = [pscustomobject]@{} } }
    if ($null -eq $r.items) { $r | Add-Member -NotePropertyName items -NotePropertyValue ([pscustomobject]@{}) -Force }
    return $r
}
function Save-Registry($r) { Write-Json $Registry $r }

function Lock-Path($itemId) { Join-Path $LocksDir "$itemId.lock" }

function Get-ProcStart([int]$procId) {
    if ($procId -le 0) { return $null }
    $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
    if ($null -eq $p) { return $null }
    try { return $p.StartTime.ToString('o') } catch { return $null }
}

# Atomic exclusive create; $true only if THIS caller created the file.
function Acquire-File([string]$path) {
    try {
        $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::CreateNew,
                                      [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $fs.Close(); return $true
    }
    catch [System.IO.IOException] { return $false }
}

# Cross-process registry RMW serialization via a named kernel mutex (atomic
# across processes; an abandoned mutex from a crashed owner is treated as
# acquired so a crash never wedges the registry). The mutex name is scoped to
# THIS repository (hash of the shared state dir) so unrelated repos on the same
# machine never contend on each other's registry.
$sha = [System.Security.Cryptography.SHA256]::Create()
$hashBytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($StateDir.ToLower()))
$mutexName = 'RawrXD_coord_registry_' + ([System.BitConverter]::ToString($hashBytes).Replace('-', '').Substring(0, 16))
$script:RegMutex = [System.Threading.Mutex]::new($false, $mutexName)
function Mutate-Registry($transform) {
    $acquired = $false
    try { $acquired = $script:RegMutex.WaitOne(15000) }
    catch [System.Threading.AbandonedMutexException] { $acquired = $true }
    if (-not $acquired) { throw "REGISTRY_LOCK_TIMEOUT" }
    try {
        $r = Load-Registry
        & $transform $r
        Save-Registry $r
    }
    finally { $script:RegMutex.ReleaseMutex() }
}

# Returns 'free', 'owned', or 'stale'. Pure (no mutation); caller holds registry lock.
function Get-ItemState($r, $itemId) {
    if (-not (Test-Path -LiteralPath (Lock-Path $itemId))) { return 'free' }
    $e = $r.items.$itemId
    if ($null -eq $e) { return 'stale' }
    if (-not (Get-ProcStart ([int]$e.pid))) { return 'stale' }              # owner gone
    if ($e.pid_start) {                                                      # PID reuse
        $cur = Get-ProcStart ([int]$e.pid)
        if ($cur -and $cur -ne $e.pid_start) { return 'stale' }
    }
    if (((Get-Date) - [datetime]::Parse($e.heartbeat)).TotalMinutes -gt $StaleMinutes) { return 'stale' }
    return 'owned'
}

function Show-Status {
    $r = Load-Registry
    $b = Read-Json $Backlog
    Write-Host "== Backlog / ownership =="
    if ($null -eq $b -or $null -eq $b.items) { Write-Host "  (no backlog.json)" }
    else {
        foreach ($it in $b.items) {
            $state = Get-ItemState $r $it.id
            $owner = if ($r.items.$($it.id)) { $r.items.$($it.id).owner } else { '-' }
            $deps = if ($it.deps) { "deps=" + ($it.deps -join ',') } else { "" }
            Write-Host ("  {0,-22} {1,-8} owner={2,-14} {3,-7} {4}" -f $it.id, $it.status, $owner, $state, $deps)
        }
    }
    $locks = Get-ChildItem -LiteralPath $LocksDir -Filter *.lock -ErrorAction SilentlyContinue
    Write-Host "== Lock files =="
    if ($locks) { $locks | ForEach-Object { Write-Host ("  " + $_.Name) } } else { Write-Host "  (none)" }
}

function Test-DepsSatisfied($b, $item) {
    if (-not $item.deps) { return $true }
    foreach ($d in $item.deps) {
        $dep = $b.items | Where-Object { $_.id -eq $d }
        if ($dep -and $dep.status -ne 'CLOSED') { return $false }
    }
    return $true
}

function Show-Next {
    $r = Load-Registry
    $b = Read-Json $Backlog
    if ($null -eq $b -or $null -eq $b.items) { Write-Host "NO_BACKLOG"; return }
    foreach ($it in $b.items) {
        if ($it.status -eq 'CLOSED') { continue }
        if (-not (Test-DepsSatisfied $b $it)) { continue }
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
    $effPid = $OwnerPid
    if ($effPid -le 0) { $effPid = $PID }
    $pidStart = Get-ProcStart $effPid
    $script:claimed = $false
    Mutate-Registry {
        param($r)
        $state = Get-ItemState $r $Item
        if ($state -eq 'owned') { throw "ITEM_ALREADY_OWNED item=$Item owner=$($r.items.$Item.owner)" }
        if ($state -eq 'stale') { Remove-Item -LiteralPath (Lock-Path $Item) -Force -ErrorAction SilentlyContinue }
        if (-not (Acquire-File (Lock-Path $Item))) { throw "CLAIM_FAILED item=$Item (concurrent claim won)" }
        $now = (Get-Date).ToString('o')
        $entry = [pscustomobject]@{
            owner = $Agent; worktree = $Worktree; branch = $Branch
            pid = $effPid; pid_start = $pidStart
            claimed_at = $now; heartbeat = $now
        }
        $r.items | Add-Member -NotePropertyName $Item -NotePropertyValue $entry -Force
        $script:claimed = $true
    }
    if ($script:claimed) { Write-Host ("CLAIMED item={0} agent={1} pid={2}" -f $Item, $Agent, $effPid) }
}

function Release-Item {
    if (-not $Agent -or -not $Item) { throw "release requires -Agent and -Item" }
    Mutate-Registry {
        param($r)
        $e = $r.items.$Item
        if ($null -ne $e -and $e.owner -ne $Agent) { throw "RELEASE_DENIED item=$Item owner=$($e.owner) caller=$Agent" }
        Remove-Item -LiteralPath (Lock-Path $Item) -Force -ErrorAction SilentlyContinue
        if ($null -ne $e) { $r.items.PSObject.Properties.Remove($Item) }
    }
    Write-Host ("RELEASED item={0} agent={1}" -f $Item, $Agent)
}

function Heartbeat-Item {
    if (-not $Agent -or -not $Item) { throw "heartbeat requires -Agent and -Item" }
    Mutate-Registry {
        param($r)
        $e = $r.items.$Item
        if ($null -eq $e) { throw "NOT_OWNED item=$Item" }
        if ($e.owner -ne $Agent) { throw "HEARTBEAT_DENIED item=$Item owner=$($e.owner)" }
        $e.heartbeat = (Get-Date).ToString('o')
    }
    Write-Host ("HEARTBEAT item={0} agent={1}" -f $Item, $Agent)
}

function Reclaim-Item {
    if (-not $Agent -or -not $Item) { throw "reclaim requires -Agent and -Item" }
    $effPid = $OwnerPid
    if ($effPid -le 0) { $effPid = $PID }
    $pidStart = Get-ProcStart $effPid
    Mutate-Registry {
        param($r)
        if ((Get-ItemState $r $Item) -eq 'owned') { throw "RECLAIM_DENIED item=$Item actively owned (not stale)" }
        Remove-Item -LiteralPath (Lock-Path $Item) -Force -ErrorAction SilentlyContinue
        if (-not (Acquire-File (Lock-Path $Item))) { throw "RECLAIM_FAILED item=$Item" }
        $now = (Get-Date).ToString('o')
        $entry = [pscustomobject]@{
            owner = $Agent; pid = $effPid; pid_start = $pidStart
            claimed_at = $now; heartbeat = $now
        }
        $r.items | Add-Member -NotePropertyName $Item -NotePropertyValue $entry -Force
    }
    Write-Host ("RECLAIMED item={0} agent={1}" -f $Item, $Agent)
}

function Done-Item {
    if (-not $Agent -or -not $Item) { throw "done requires -Agent and -Item" }
    $r = Load-Registry
    $e = $r.items.$Item
    if ($null -eq $e -or $e.owner -ne $Agent) { throw "DONE_DENIED item=$Item not owned by $Agent" }
    Release-Item
    # Mark CLOSED in the committed backlog (staged for the owner's commit).
    $b = Read-Json $Backlog
    if ($null -ne $b -and $null -ne $b.items) {
        foreach ($it in $b.items) { if ($it.id -eq $Item) { $it.status = 'CLOSED' } }
        Write-Json $Backlog $b
    }
    Write-Host ("DONE item={0} (released + backlog CLOSED)" -f $Item)
}

function PreEdit {
    if (-not $Agent -or -not $Item) { Write-Output "PREEDIT_DENY reason=missing-args"; exit 1 }
    $r = Load-Registry
    $e = $r.items.$Item
    if ($null -eq $e) { Write-Output "PREEDIT_DENY item=$Item reason=not-claimed"; exit 1 }
    if ($e.owner -ne $Agent) { Write-Output "PREEDIT_DENY item=$Item owner=$($e.owner) caller=$Agent"; exit 1 }
    if ((Get-ItemState $r $Item) -eq 'stale') { Write-Output "PREEDIT_DENY item=$Item reason=stale-take-reclaim"; exit 1 }
    Write-Output "PREEDIT_ALLOW item=$Item agent=$Agent"; exit 0
}

function Write-Receipt {
    if (-not $Item -or -not $Commit) { throw "receipt requires -Item and -Commit" }
    # Verify the commit exists in this worktree.
    & git -C $Root cat-file -e "$Commit^{commit}" 2>$null
    if ($LASTEXITCODE -ne 0) { throw "RECEIPT_BAD_COMMIT commit=$Commit not found in $Root" }
    # Verify the commit is actually in HEAD's history (reject an unrelated
    # pre-existing commit supplied as false acceptance evidence).
    & git -C $Root merge-base --is-ancestor $Commit HEAD 2>$null
    if ($LASTEXITCODE -ne 0) { throw "RECEIPT_NOT_ANCESTOR commit=$Commit not in HEAD history" }
    $rp = Join-Path $ReceiptsDir "$Item.$Commit.json"
    $obj = [pscustomobject]@{
        item = $Item; commit = $Commit; agent = $Agent
        evidence = $Evidence; at = (Get-Date).ToString('o')
    }
    Write-Json $rp $obj
    Write-Host ("RECEIPT_WRITTEN item={0} commit={1} path={2}" -f $Item, $Commit, $rp)
}

function Get-FreePort {
    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $l.Start(); $p = $l.LocalEndpoint.Port; $l.Stop(); return $p
}

function Provision-Item {
    if (-not $Agent -or -not $Item -or -not $Worktree -or -not $Branch) {
        throw "provision requires -Agent -Item -Worktree -Branch"
    }
    $createdWorktree = $false
    $createdDirs = @()
    try {
        if ($NewWorktree) {
            if (Test-Path -LiteralPath $Worktree) { throw "WORKTREE_EXISTS path=$Worktree" }
            & git -C $Root worktree add -b $Branch $Worktree HEAD
            if ($LASTEXITCODE -ne 0) { throw "WORKTREE_CREATE_FAILED branch=$Branch" }
            $createdWorktree = $true
        }
        if (-not $BuildDir) { $BuildDir = Join-Path $Worktree "build-coord" }
        if (-not $TestDir)  { $TestDir  = Join-Path $Worktree "test-ws" }
        foreach ($d in @($BuildDir, $TestDir)) {
            if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null; $createdDirs += $d }
        }
        if (-not $Port) { $Port = Get-FreePort }
        $instanceId = "$Agent-$Item-$Port"
        Claim-Item
    }
    catch {
        # Transactional rollback: undo any partial provisioning so a failed
        # provision never leaves an orphan worktree, branch, or build dir.
        foreach ($d in $createdDirs) { Remove-Item -LiteralPath $d -Force -ErrorAction SilentlyContinue }
        if ($createdWorktree) {
            & git -C $Root worktree remove --force $Worktree 2>$null
            & git -C $Root branch -D $Branch 2>$null
        }
        throw "PROVISION_ROLLED_BACK: $($_.Exception.Message)"
    }
    Write-Host ("PROVISIONED item={0} agent={1}" -f $Item, $Agent)
    Write-Host ("  WORKTREE={0}" -f $Worktree)
    Write-Host ("  BRANCH={0}"   -f $Branch)
    Write-Host ("  BUILD_DIR={0}" -f $BuildDir)
    Write-Host ("  TEST_WS={0}"  -f $TestDir)
    Write-Host ("  PORT={0}"     -f $Port)
    Write-Host ("  INSTANCE_ID={0}" -f $instanceId)
    Write-Host ("  RECEIPT_DIR={0}" -f $ReceiptsDir)
}

function SelfTest {
    $item = if ($Item) { $Item } else { 'selftest' }
    # Ensure a clean slate for the test item.
    Remove-Item -LiteralPath (Lock-Path $item) -Force -ErrorAction SilentlyContinue
    Mutate-Registry { param($r) if ($r.items.$item) { $r.items.PSObject.Properties.Remove($item) } }
    $script = Join-Path $CoordDir 'coord.ps1'
    $jobs = @()
    for ($i = 1; $i -le $Agents; $i++) {
        # Each agent claims in-process, then HOLDS (stays alive) so the winner's
        # PID is live while the others contend. Without the hold, short-lived
        # losers would exit and the winner's claim would (correctly) look stale.
        $jobs += Start-Job -ScriptBlock {
            param($s, $it, $i)
            $out = try { & $s claim -Agent "selftest-$i" -Item $it -OwnerPid $PID 2>&1; "CLAIMED" }
                   catch { "REJECTED: " + $_.Exception.Message }
            Start-Sleep -Seconds 5
            "$out"
        } -ArgumentList $script, $item, $i
    }
    $results = $jobs | Wait-Job -Timeout 60 | Receive-Job -ErrorAction SilentlyContinue
    $jobs | Remove-Job -Force -ErrorAction SilentlyContinue
    $wins = ($results | Where-Object { $_ -match 'CLAIMED' }).Count
    Write-Host ("SELFTEST agents={0} winners={1}" -f $Agents, $wins)
    foreach ($r in $results) { Write-Host ("  " + ($r -join ' ')) }
    if ($wins -eq 1) { Write-Host "SELFTEST_PASS=1" }
    else { Write-Host "SELFTEST_PASS=0"; exit 2 }
    # cleanup
    Mutate-Registry { param($r) Remove-Item -LiteralPath (Lock-Path $item) -Force -ErrorAction SilentlyContinue; if ($r.items.$item) { $r.items.PSObject.Properties.Remove($item) } }
}

Ensure-Dirs
switch ($Command) {
    'status'    { Show-Status }
    'next'      { Show-Next }
    'claim'     { Claim-Item }
    'release'   { Release-Item }
    'heartbeat' { Heartbeat-Item }
    'reclaim'   { Reclaim-Item }
    'done'      { Done-Item }
    'preedit'   { PreEdit }
    'receipt'   { Write-Receipt }
    'provision' { Provision-Item }
    'selftest'  { SelfTest }
}