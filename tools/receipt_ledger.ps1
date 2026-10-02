<#
.SYNOPSIS
    Content-addressed backup + append-only receipt ledger with reversible retractions.

.DESCRIPTION
    Three guarantees:

    1. BACKUP BEFORE RUN. Every artifact a verdict depends on is snapshotted into a
       content-addressed store. The SHA-256 IS the address, so a restore target
       cannot be substituted without detection.

    2. APPEND ONLY. No receipt is ever edited or deleted. Every verdict names the
       receipt it supersedes and hashes the receipt before it, so the chain is
       tamper-evident end to end.

    3. RETRACTION IS REVERSIBLE. A retraction is itself a receipt. Un-retracting
       appends a new receipt that supersedes the retraction and REQUIRES evidence.
       The retracted claim stays in the chain forever; what changes is which
       receipt is the tip. Nothing is erased, so a wrong retraction costs a
       supersession, not history.

    A verdict that cannot be traced to a backup and an unbroken chain is not a
    verdict. `test-chain` is the gate.

.PARAMETER Command
    backup | verify | restore | record | retract | unretract | status | list | test-chain

.EXAMPLE
    .\receipt_ledger.ps1 backup -Path .\vulkan_grid_final.txt -Label pre-bisect
    .\receipt_ledger.ps1 record -Gate VULKAN_PARITY_001 -Claim "CPU==GPU within 1e-3" -Status HOLDS -Evidence "8712/8712 pairs"
    .\receipt_ledger.ps1 retract  -Gate VULKAN_PARITY_001 -Reason "instrument recorded only 8 of 2048 elements"
    .\receipt_ledger.ps1 unretract -Gate VULKAN_PARITY_001 -Evidence "instrument upgraded to full-array readback; 8712/8712 reconfirmed"
    .\receipt_ledger.ps1 status   -Gate VULKAN_PARITY_001
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateSet('backup', 'verify', 'restore', 'record', 'retract', 'unretract', 'status', 'list', 'test-chain')]
    [string] $Command,

    [string]   $Path,
    [string]   $Label = '',
    [string]   $To,
    [string]   $Gate,
    [string]   $Claim,
    [ValidateSet('HOLDS', 'FAILS')]
    [string]   $Status = 'HOLDS',
    [string]   $Reason = '',
    [string]   $Evidence = '',
    [string]   $Backup,
    [string]   $Root
)

$ErrorActionPreference = 'Stop'

# $PSScriptRoot is not reliably bound inside param() defaults, so resolve here.
if (-not $Root) {
    $here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $Root = Join-Path (Split-Path -Parent $here) 'receipts\ledger'
}

$BackupStore = Join-Path $Root '_backups'
$ChainRoot   = Join-Path $Root '_chain'

function Get-Sha256([string] $p) {
    (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToUpperInvariant()
}

function Get-TextSha256([string] $s) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($s)
        ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
    } finally { $sha.Dispose() }
}

function Initialize-Store {
    foreach ($d in @($Root, $BackupStore, $ChainRoot)) {
        if (-not (Test-Path -LiteralPath $d)) {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
        }
    }
}

function Get-GateDir([string] $g) {
    $safe = ($g -replace '[^A-Za-z0-9._-]', '_').ToUpperInvariant()
    $d = Join-Path $ChainRoot $safe
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    $d
}

function Get-ReceiptFiles([string] $g) {
    $d = Get-GateDir $g
    @(Get-ChildItem -LiteralPath $d -Filter '*.json' -File -ErrorAction SilentlyContinue |
      Sort-Object Name)
}

function Read-Receipt([string] $f) {
    Get-Content -LiteralPath $f -Raw | ConvertFrom-Json
}

function Get-ReceiptSelfHash($r) {
    # self_hash covers every field except self_hash itself
    $copy = [ordered]@{}
    foreach ($p in $r.PSObject.Properties) {
        if ($p.Name -ne 'self_hash') { $copy[$p.Name] = $p.Value }
    }
    $json = ($copy | ConvertTo-Json -Depth 8 -Compress)
    Get-TextSha256 $json
}

function Get-Tip([string] $g) {
    $files = Get-ReceiptFiles $g
    if ($files.Count -eq 0) { return $null }
    $superseded = @{}
    foreach ($f in $files) {
        $r = Read-Receipt $f.FullName
        if ($r.supersedes) { $superseded[$r.supersedes] = $true }
    }
    $live = @()
    foreach ($f in $files) {
        $r = Read-Receipt $f.FullName
        if (-not $superseded.ContainsKey($r.id)) { $live += [pscustomobject]@{ File = $f; R = $r } }
    }
    if ($live.Count -eq 0) { return $null }
    # A retraction supersedes the claim it retracts, so the retraction is the tip.
    ($live | Sort-Object { $_.R.seq } | Select-Object -Last 1)
}

function Write-Receipt {
    param([string] $g, [string] $claim, [string] $verdict, [string] $reason,
          [string] $evidence, [string] $backupRef, [string] $supersedes)

    $files = Get-ReceiptFiles $g
    $seq = 1
    $prevHash = $null
    $prevId = $null
    if ($files.Count -gt 0) {
        $last = Read-Receipt $files[-1].FullName
        $seq = [int]$last.seq + 1
        $prevHash = $last.self_hash
        $prevId = $last.id
    }
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $id = '{0}#{1:d4}' -f $g, $seq

    $body = [ordered]@{
        id           = $id
        gate         = $g
        seq          = $seq
        verdict      = $verdict
        claim        = $claim
        reason       = $reason
        evidence     = $evidence
        backup_ref   = $backupRef
        supersedes   = $supersedes
        supersedes_id= $prevId
        prev_hash    = $prevHash
        recorded_utc = $stamp
        pid          = $PID
    }
    $self = Get-TextSha256 ($body | ConvertTo-Json -Depth 8 -Compress)
    $body['self_hash'] = $self

    $d = Get-GateDir $g
    $seqStr = '{0:d4}' -f $seq
    $file = Join-Path $d ('{0}_{1}_{2}.json' -f $stamp, $seqStr, $verdict)
    ($body | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $file -Encoding UTF8
    [pscustomobject]@{ Id = $id; Verdict = $verdict; File = $file; SelfHash = $self }
}

function Get-IndexPath { Join-Path $Root '_index.tsv' }

function Read-Index {
    $p = Get-IndexPath
    if (-not (Test-Path -LiteralPath $p)) { return @() }
    @(Get-Content -LiteralPath $p | Where-Object { $_ -match "`t" } | ForEach-Object {
        $f = $_ -split "`t"
        [pscustomobject]@{ Path = $f[0]; Sha256 = $f[1]; Label = $f[2]; Stamp = $f[3] }
    })
}

function Write-Index([array] $rows) {
    $p = Get-IndexPath
    ($rows | ForEach-Object { "$($_.Path)`t$($_.Sha256)`t$($_.Label)`t$($_.Stamp)" }) |
        Set-Content -LiteralPath $p -Encoding UTF8
}

function Invoke-Backup {
    Initialize-Store
    if (-not $Path) { throw 'backup requires -Path' }
    $resolved = @()
    foreach ($p in @($Path -split ';')) {
        if (-not $p) { continue }
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { throw "not a file: $p" }
        $h = Get-Sha256 $p
        $dir = Join-Path (Join-Path $BackupStore $h.Substring(0, 2)) $h
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $dest = Join-Path $dir (Split-Path $p -Leaf)
        if (-not (Test-Path -LiteralPath $dest)) {
            Copy-Item -LiteralPath $p -Destination $dest -Force
        }
        $vh = Get-Sha256 $dest
        if ($vh -ne $h) { throw "backup verify failed for $p" }
        $resolved += [pscustomobject]@{ Source = (Resolve-Path $p).Path; Sha256 = $h; Stored = $dest; Label = $Label }
    }
    # Bind path -> hash so drift is detectable later, not just absence.
    $idx = Read-Index
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    foreach ($r in $resolved) {
        $existing = @($idx | Where-Object { $_.Path -eq $r.Source })
        foreach ($e in $existing) { $idx = @($idx | Where-Object { $_ -ne $e }) }
        $idx += [pscustomobject]@{ Path = $r.Source; Sha256 = $r.Sha256; Label = $r.Label; Stamp = $stamp }
    }
    Write-Index $idx
    $resolved | Format-Table -AutoSize
    Write-Output ("BACKUPS={0}" -f $resolved.Count)
    $resolved | ForEach-Object { "BACKUP_SHA256=$($_.Sha256)" }
}

function Invoke-Verify {
    if (-not $Path) { throw 'verify requires -Path' }
    $p = (Resolve-Path $Path).Path
    $h = Get-Sha256 $p
    $dir = Join-Path (Join-Path $BackupStore $h.Substring(0, 2)) $h
    $found = @(Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue)

    Write-Output "PATH=$p"
    Write-Output "LIVE_SHA256=$h"

    $idx = @(Read-Index | Where-Object { $_.Path -eq $p })
    if ($idx.Count -gt 0 -and $idx[-1].Sha256 -ne $h) {
        Write-Output "INDEXED_SHA256=$($idx[-1].Sha256)"
        Write-Output 'DRIFT=1'
        Write-Output 'BACKUP_PRESENT=0'
        Write-Output ("RESTORE_HINT={0} -To `"$p`"" -f $idx[-1].Sha256)
        Write-Output 'VERIFY=DRIFTED'
        return
    }
    Write-Output 'DRIFT=0'

    if ($found.Count -eq 0) {
        Write-Output 'BACKUP_PRESENT=0'
        Write-Output 'VERIFY=NO_BACKUP'
        return
    }
    $ok = $true
    foreach ($f in $found) { if ((Get-Sha256 $f.FullName) -ne $h) { $ok = $false } }
    Write-Output "BACKUP_PRESENT=1"
    Write-Output "BACKUP_COPIES=$($found.Count)"
    Write-Output ("VERIFY={0}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }))
}

function Invoke-Restore {
    if (-not $Backup) { throw 'restore requires -Backup <sha256>' }
    if (-not $To) { throw 'restore requires -To <path>' }
    $dir = Join-Path (Join-Path $BackupStore $Backup.Substring(0, 2)) $Backup.ToUpperInvariant()
    $src = @(Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue)
    if ($src.Count -eq 0) { throw "no backup at $Backup" }
    if ((Get-Sha256 $src[0].FullName) -ne $Backup.ToUpperInvariant()) {
        throw 'backup store content does not match its address; refusing restore'
    }
    $pre = if (Test-Path -LiteralPath $To) { Get-Sha256 $To } else { 'ABSENT' }
    Copy-Item -LiteralPath $src[0].FullName -Destination $To -Force
    $post = Get-Sha256 $To
    Write-Output "RESTORE_FROM=$Backup"
    Write-Output "TARGET_PRE_SHA256=$pre"
    Write-Output "TARGET_POST_SHA256=$post"
    Write-Output ("RESTORE={0}" -f $(if ($post -eq $Backup.ToUpperInvariant()) { 'PASS' } else { 'FAIL' }))
}

function Invoke-Record {
    if (-not $Gate) { throw 'record requires -Gate' }
    if (-not $Claim) { throw 'record requires -Claim' }
    Initialize-Store
    Write-Receipt -g $Gate -claim $Claim -verdict $Status -reason '' -evidence $Evidence -backupRef $Backup -supersedes $null | Format-List
}

function Invoke-Retract {
    if (-not $Gate) { throw 'retract requires -Gate' }
    if (-not $Reason) { throw 'retract requires -Reason (a retraction without a reason is not reviewable)' }
    Initialize-Store
    $tip = Get-Tip $Gate
    if (-not $tip) { throw "no receipt for gate $Gate to retract" }
    if ($tip.R.verdict -eq 'RETRACTED') { throw "gate $Gate is already retracted; unretract instead" }
    Write-Receipt -g $Gate -claim $tip.R.claim -verdict 'RETRACTED' -reason $Reason `
        -evidence $Evidence -backupRef $tip.R.backup_ref -supersedes $tip.R.id | Format-List
}

function Invoke-Unretract {
    if (-not $Gate) { throw 'unretract requires -Gate' }
    if (-not $Evidence) { throw 'unretract REQUIRES -Evidence; a retraction is never reversed without new evidence' }
    Initialize-Store
    $tip = Get-Tip $Gate
    if (-not $tip) { throw "no receipt for gate $Gate" }
    if ($tip.R.verdict -ne 'RETRACTED') { throw "gate $Gate tip is $($tip.R.verdict), not RETRACTED; nothing to unretract" }
    $newClaim = if ($Claim) { $Claim } else { $tip.R.claim }
    Write-Receipt -g $Gate -claim $newClaim -verdict $Status -reason "un-retraction of $($tip.R.id): $($tip.R.reason)" `
        -evidence $Evidence -backupRef $(if ($Backup) { $Backup } else { $tip.R.backup_ref }) -supersedes $tip.R.id | Format-List
}

function Invoke-Status {
    Initialize-Store
    if ($Gate) {
        $tip = Get-Tip $Gate
        if (-not $tip) { Write-Output "GATE=$Gate"; Write-Output 'RECEIPTS=0'; Write-Output 'VERDICT=NONE'; return }
        Write-Output "GATE=$Gate"
        Write-Output "TIP_ID=$($tip.R.id)"
        Write-Output "VERDICT=$($tip.R.verdict)"
        Write-Output "CLAIM=$($tip.R.claim)"
        Write-Output "REASON=$($tip.R.reason)"
        Write-Output "EVIDENCE=$($tip.R.evidence)"
        Write-Output "BACKUP_REF=$($tip.R.backup_ref)"
        Write-Output "SUPERSEDES=$($tip.R.supersedes)"
        Write-Output '--- CHAIN ---'
        foreach ($f in Get-ReceiptFiles $Gate) {
            $r = Read-Receipt $f.FullName
            $flag = if ((Get-ReceiptSelfHash $r) -eq $r.self_hash) { 'OK  ' } else { 'BAD ' }
            "  $flag $($r.id)  $($r.verdict)  $($r.claim)"
        }
        return
    }
    $gates = @(Get-ChildItem -LiteralPath $ChainRoot -Directory -ErrorAction SilentlyContinue)
    foreach ($g in $gates) {
        $t = Get-Tip $g.Name
        if ($t) { "{0,-40} {1,-10} {2}" -f $g.Name, $t.R.verdict, $t.R.claim }
    }
}

function Invoke-TestChain {
    Initialize-Store
    $gates = @(Get-ChildItem -LiteralPath $ChainRoot -Directory -ErrorAction SilentlyContinue)
    $total = 0; $bad = 0; $gaps = 0
    foreach ($g in $gates) {
        $files = Get-ReceiptFiles $g.Name
        $prev = $null
        foreach ($f in $files) {
            $r = Read-Receipt $f.FullName
            $total++
            if ((Get-ReceiptSelfHash $r) -ne $r.self_hash) {
                Write-Output "SELF_HASH_MISMATCH $($r.id)"; $bad++
            }
            if ($prev) {
                if ($r.prev_hash -ne $prev.self_hash) {
                    Write-Output "CHAIN_BREAK $($r.id) prev_hash does not match $($prev.id)"; $bad++
                }
                if ([int]$r.seq -ne ([int]$prev.seq + 1)) {
                    Write-Output "SEQ_GAP $($prev.id) -> $($r.id)"; $gaps++
                }
            } elseif ($r.prev_hash) {
                Write-Output "ROOT_HAS_PREVHASH $($r.id)"; $bad++
            }
            $prev = $r
        }
    }
    Write-Output "GATES=$($gates.Count)"
    Write-Output "RECEIPTS=$total"
    Write-Output "HASH_FAILURES=$bad"
    Write-Output "SEQ_GAPS=$gaps"
    Write-Output ("CHAIN_VERDICT={0}" -f $(if ($bad -eq 0 -and $gaps -eq 0) { 'PASS' } else { 'FAIL' }))
    if ($bad -gt 0 -or $gaps -gt 0) { exit 1 }
}

Initialize-Store
switch ($Command) {
    'backup'     { Invoke-Backup }
    'verify'     { Invoke-Verify }
    'restore'    { Invoke-Restore }
    'record'     { Invoke-Record }
    'retract'    { Invoke-Retract }
    'unretract'  { Invoke-Unretract }
    'status'     { Invoke-Status }
    'list'       { Invoke-Status }
    'test-chain' { Invoke-TestChain }
}
