# cert_write_transactional_profile.ps1
#   RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001 -- L28f
#
# What this certifies
#   That an autonomous agent can edit real files through the real HTTP tool
#   authority, and that every accepted edit is undoable -- in-process (rollback)
#   and after a crash (a separate recovery process). It also certifies the four
#   refusals that make the write path safe to expose, because a write profile is
#   defined by what it refuses as much as by what it performs.
#
# RAWRXD_HTTP_JSON_HARNESS_RULE_001 is enforced structurally in this file, not
# by a comment:
#     every request body is produced by ConvertTo-Json, written to a file, and
#     POSTed with curl --data-binary @file;
#     every body is round-tripped through ConvertFrom-Json before it is sent;
#     no request body is ever built by string interpolation.
#   B82 lost two of its findings to PowerShell escaping a backslash into an
#   invalid JSON escape and then reading the server's correct 400 as a server
#   defect. Interpolated bodies cannot happen in this harness.
#
# Usage
#   pwsh -File tools/cert_write_transactional_profile.ps1 `
#        -ServerExe <path> -Model <gguf> [-Port 11477] [-OutDir <dir>]
#
# Exit code 0 only when every check passed. Every check prints NAME=PASS|FAIL
# with the measurement it was decided by.

[CmdletBinding()]
param(
    [string]$ServerExe = "F:\~dev\rawrxd\build\bin\Release\rawr-server.exe",
    [string]$Model = "G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
    [int]$Port = 11477,
    [string]$OutDir = "F:\~dev\rawrxd\audit\RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001"
)

# 'Continue', not 'Stop': curl.exe legitimately writes to stderr when the server
# is gone -- which is exactly what the crash checks are measuring -- and under
# 'Stop' PowerShell turns that into a NativeCommandError and abandons the run
# before the check that wanted it. Every decision in this harness is made by an
# explicit comparison, never by the absence of console noise.
$ErrorActionPreference = "Continue"
$script:Failures = New-Object System.Collections.Generic.List[string]
$script:Checks = 0
$script:Log = New-Object System.Collections.Generic.List[string]
$script:ServerProc = $null
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Say([string]$line) {
    Write-Host $line
    $script:Log.Add($line) | Out-Null
}

function Check([string]$name, [bool]$passed, [string]$evidence) {
    $script:Checks++
    $tag = if ($passed) { "PASS" } else { "FAIL" }
    Say ("{0}={1} :: {2}" -f $name, $tag, $evidence)
    if (-not $passed) { $script:Failures.Add($name) | Out-Null }
}

# ---------------------------------------------------------------------------
# HTTP helpers -- RAWRXD_HTTP_JSON_HARNESS_RULE_001
# ---------------------------------------------------------------------------
$script:BodyDir = $null
$script:RespSeq = 0

function New-BodyFile([object]$payload) {
    # Serializer, not interpolation. ConvertTo-Json escapes every backslash,
    # quote, newline and control character for us.
    $json = $payload | ConvertTo-Json -Compress -Depth 8
    # Round-trip guard: an unparseable body never reaches the network. This is
    # the check that would have caught the B82 harness defect at its source.
    $null = $json | ConvertFrom-Json
    $script:RespSeq++
    $path = Join-Path $script:BodyDir ("body{0:d3}.json" -f $script:RespSeq)
    [System.IO.File]::WriteAllText($path, $json, $script:Utf8NoBom)
    return $path
}

function Invoke-Api([string]$method, [string]$path, [object]$payload) {
    $respPath = Join-Path $script:BodyDir ("resp{0:d3}.json" -f $script:RespSeq)
    $args = @('-s', '-o', $respPath, '-w', '%{http_code}', '-X', $method)
    if ($null -ne $payload) {
        $bodyPath = New-BodyFile $payload
        $args += @('-H', 'Content-Type: application/json', '--data-binary', ('@' + $bodyPath))
    }
    $args += ("http://127.0.0.1:{0}{1}" -f $Port, $path)
    $status = (& curl.exe @args) -join ''
    $text = if (Test-Path -LiteralPath $respPath) { Get-Content -LiteralPath $respPath -Raw } else { "" }
    $obj = $null
    if ($text) { try { $obj = $text | ConvertFrom-Json } catch { $obj = $null } }
    return [pscustomobject]@{ Status = [int]$status; Raw = $text; Json = $obj }
}

function Invoke-Tool([string]$tool, [hashtable]$toolArgs) {
    # $args is PowerShell's automatic variable for unbound arguments; naming a
    # parameter $args makes every hashtable arrive as System.Object[].
    $p = @{ tool = $tool; args = $toolArgs }
    return Invoke-Api "POST" "/api/agent/execute-tool" $p
}

function Invoke-Tx([string]$op, [hashtable]$extra) {
    $p = @{ op = $op }
    if ($extra) { foreach ($k in $extra.Keys) { $p[$k] = $extra[$k] } }
    return Invoke-Api "POST" "/api/agent/transaction" $p
}

# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------
function Get-Sha([string]$path) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
}

function Set-Seed([string]$path, [string]$text) {
    [System.IO.File]::WriteAllText($path, $text, $script:Utf8NoBom)
    return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
}

# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------
$script:SavedEnv = @{}

function Set-ServerEnv([hashtable]$vars) {
    foreach ($k in $vars.Keys) {
        if (-not $script:SavedEnv.ContainsKey($k)) {
            $script:SavedEnv[$k] = [Environment]::GetEnvironmentVariable($k, "Process")
        }
        [Environment]::SetEnvironmentVariable($k, [string]$vars[$k], "Process")
    }
}

function Start-Server([string]$tag) {
    $stdout = Join-Path $OutDir ("server_{0}.out.log" -f $tag)
    $stderr = Join-Path $OutDir ("server_{0}.err.log" -f $tag)
    $script:ServerProc = Start-Process -FilePath $ServerExe `
        -ArgumentList @('--model', $Model, '--port', "$Port", '--host', '127.0.0.1') `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
        -WindowStyle Hidden -PassThru
    $deadline = (Get-Date).AddSeconds(120)
    while ((Get-Date) -lt $deadline) {
        if ($script:ServerProc.HasExited) {
            Say ("SERVER_{0}_EXITED_EARLY code={1}" -f $tag, $script:ServerProc.ExitCode)
            return $false
        }
        $h = Invoke-Api "GET" "/health" $null
        if ($h.Status -eq 200) { return $true }
        Start-Sleep -Milliseconds 400
    }
    Say ("SERVER_{0}_READY_TIMEOUT" -f $tag)
    return $false
}

function Stop-Server() {
    if ($null -ne $script:ServerProc) {
        if (-not $script:ServerProc.HasExited) {
            # TerminateProcess, not a graceful shutdown: the server exposes no
            # shutdown route, and an abrupt stop is exactly the condition the
            # recovery pass exists for.
            Stop-Process -Id $script:ServerProc.Id -Force
        }
        $script:ServerProc.WaitForExit(15000) | Out-Null
        $script:ServerProc = $null
    }
}

# ===========================================================================
# Setup
# ===========================================================================
if (-not (Test-Path -LiteralPath $ServerExe)) { throw "server not found: $ServerExe" }
if (-not (Test-Path -LiteralPath $Model)) { throw "model not found: $Model" }
if (Test-Path -LiteralPath $OutDir) { Remove-Item -LiteralPath $OutDir -Recurse -Force }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$script:BodyDir = Join-Path $OutDir "bodies"
New-Item -ItemType Directory -Path $script:BodyDir -Force | Out-Null

$ws = Join-Path $OutDir "work"
New-Item -ItemType Directory -Path $ws -Force | Out-Null

$alphaPath = Join-Path $ws "alpha.txt"
$betaPath = Join-Path $ws "beta.txt"
$gammaPath = Join-Path $ws "gamma.txt"

$ALPHA_ORIGINAL = "// alpha ORIGINAL`nline2`n"
$BETA_ORIGINAL = "// beta ORIGINAL`n"
$ALPHA_EDITED = "// alpha EDITED BY AGENT`nint alpha() { return 2; }`n"
$ALPHA_COMMITTED = "// alpha SECOND EDIT, COMMITTED`nint alpha() { return 3; }`n"
$GAMMA_CREATED = "// gamma CREATED BY AGENT`n"

$alphaOriginalSha = Set-Seed $alphaPath $ALPHA_ORIGINAL
$betaOriginalSha = Set-Seed $betaPath $BETA_ORIGINAL

Say "workspace=$ws"
Say "alpha_original_sha256=$alphaOriginalSha"
Say "beta_original_sha256=$betaOriginalSha"
Say "server_sha256=$((Get-FileHash -LiteralPath $ServerExe -Algorithm SHA256).Hash)"

$portFree = (Test-NetConnection -ComputerName 127.0.0.1 -Port $Port -WarningAction SilentlyContinue).TcpTestSucceeded
if ($portFree) { throw "port $Port is already in use" }

# ===========================================================================
# Phase 1 -- the transactional profile, refusals first
# ===========================================================================
Set-ServerEnv @{
    RAWRXD_TOOL_ROOT = $ws
    RAWRXD_TOOL_ALLOW_WRITE = "1"
    RAWRXD_CKPT_FAULT = ""
    RAWRXD_TOOL_REQUIRE_TX = ""
    # RAWRXD_TOOL_REQUIRE_TX is deliberately left unset (empty above): phase 1
    # proves the DEFAULT when write is enabled is the transactional profile.
}
if (-not (Start-Server "p1")) { throw "phase 1 server did not start" }

try {
    $st = Invoke-Tx "status" $null
    Check "T01_SERVER_UP" ($st.Status -eq 200 -and $st.Json.ok) ("http=" + $st.Status)
    Check "T02_PROFILE_TRANSACTIONAL_BY_DEFAULT" `
        ($st.Json.write_profile -eq 'transactional' -and $st.Json.requires_transaction -eq $true) `
        ("write_profile=" + $st.Json.write_profile + " requireTx=" + $st.Json.requires_transaction)
    Check "T03_NO_TX_ACTIVE_AT_START" ($st.Json.active -eq $false) ("active=" + $st.Json.active)

    # The write that must not happen.
    $r = Invoke-Tool "write_file" @{ path = "pre_tx.txt"; content = "must not exist" }
    $preTxRefused = ($r.Json.ok -eq $false) -and ($r.Json.error -match 'requires an open checkpoint transaction')
    Check "T04_WRITE_WITHOUT_TX_REFUSED" $preTxRefused ("error=" + $r.Json.error)
    Check "T05_WRITE_WITHOUT_TX_LEFT_NO_FILE" (-not (Test-Path -LiteralPath (Join-Path $ws "pre_tx.txt"))) `
        "pre_tx.txt absent"

    $bg = Invoke-Tx "begin" @{ intent = "cert phase 1"; plan = "seed + multi-file edit" }
    Check "T06_BEGIN_OK" ($bg.Status -eq 200 -and $bg.Json.ok -and $bg.Json.tx) `
        ("tx=" + $bg.Json.tx + " root=" + $bg.Json.workspace_root + " identity=" + $bg.Json.identity_sha256)

    $nb = Invoke-Tx "begin" @{}
    Check "T07_NESTED_BEGIN_REFUSED" ($nb.Status -eq 400 -and $nb.Json.ok -eq $false) `
        ("http=" + $nb.Status + " error=" + $nb.Json.error)

    $tj = Invoke-Tx "begin" @{ workspace_root = "C:\Windows\Temp" }
    Check "T08_TX_ROOT_OUTSIDE_SANDBOX_REFUSED" ($tj.Status -eq 400) `
        ("http=" + $tj.Status + " error=" + $tj.Json.error)

    $rt = Invoke-Tool "write_file" @{ path = "..\..\escape.txt"; content = "escape" }
    Check "T09_TRAVERSAL_IN_TX_REFUSED" `
        (($rt.Json.ok -eq $false) -and ($rt.Json.error -match 'rejected by sandbox')) `
        ("error=" + $rt.Json.error)

    $rc = Invoke-Tool "write_file" @{ path = ".rawrxd\ckpt\journal\evil.jrnl"; content = "forged" }
    Check "T10_CKPT_TREE_WRITE_REFUSED" `
        (($rc.Json.ok -eq $false) -and ($rc.Json.error -match 'checkpoint tree')) `
        ("error=" + $rc.Json.error)

    $w1 = Invoke-Tool "write_file" @{ path = "alpha.txt"; content = $ALPHA_EDITED }
    Check "T11_WRITE_EXISTING_INSIDE_TX" ($w1.Json.ok -eq $true) ("output=" + $w1.Json.output)
    $alphaEditedSha = Get-Sha $alphaPath
    Check "T12_EXISTING_FILE_CHANGED_ON_DISK" ($alphaEditedSha -ne $alphaOriginalSha) `
        ("sha=" + $alphaEditedSha)

    $w2 = Invoke-Tool "write_file" @{ path = "gamma.txt"; content = $GAMMA_CREATED }
    Check "T13_WRITE_NEW_INSIDE_TX" ($w2.Json.ok -eq $true) ("output=" + $w2.Json.output)
    Check "T14_NEW_FILE_ON_DISK" ((Get-Sha $gammaPath) -ne $null) ("sha=" + (Get-Sha $gammaPath))

    $st2 = Invoke-Tx "status" $null
    Check "T15_JOURNALLED_COUNTERS" `
        ($st2.Json.file_writes -ge 2 -and $st2.Json.journal_records -ge 6 -and $st2.Json.blob_writes -ge 1) `
        ("file_writes=" + $st2.Json.file_writes + " journal_records=" + $st2.Json.journal_records + " blob_writes=" + $st2.Json.blob_writes)

    # Untouched file must be untouched: rollback restores, it does not rewrite.
    $betaStillOriginal = (Get-Sha $betaPath) -eq $betaOriginalSha
    Check "T16_UNTARGETED_FILE_UNTOUCHED" $betaStillOriginal ("beta_sha=" + (Get-Sha $betaPath))

    $rb = Invoke-Tx "rollback" @{}
    Check "T17_ROLLBACK_OK" ($rb.Status -eq 200 -and $rb.Json.ok) ("http=" + $rb.Status)
    Check "T18_ROLLBACK_MEASURED" `
        ($rb.Json.files_restored -ge 1 -and $rb.Json.files_deleted -ge 1 -and `
         $rb.Json.files_verified -ge 1 -and $rb.Json.files_failed -eq 0 -and `
         $rb.Json.all_restored -eq $true) `
        ("restored=" + $rb.Json.files_restored + " deleted=" + $rb.Json.files_deleted + `
         " verified=" + $rb.Json.files_verified + " failed=" + $rb.Json.files_failed)

    Check "T19_ROLLBACK_RESTORED_ORIGINAL_BYTES" ((Get-Sha $alphaPath) -eq $alphaOriginalSha) `
        ("alpha_sha=" + (Get-Sha $alphaPath) + " expected=" + $alphaOriginalSha)
    Check "T20_ROLLBACK_REMOVED_CREATED_FILE" (-not (Test-Path -LiteralPath $gammaPath)) `
        "gamma.txt absent"

    $rbn = Invoke-Tx "rollback" @{}
    Check "T21_ROLLBACK_WITHOUT_TX_REFUSED" ($rbn.Status -eq 400) ("http=" + $rbn.Status + " error=" + $rbn.Json.error)

    # The journal must be CLOSED by the rollback. If the ROLLBACK record is
    # missing, this pass finds the transaction incomplete again and restores
    # alpha.txt -- undoing the work committed in the next block.
    $cm = Invoke-Tx "begin" @{ intent = "cert post-rollback commit" }
    Check "T22_SECOND_TX_OPENED" ($cm.Json.ok -eq $true) ("tx=" + $cm.Json.tx)
    $w3 = Invoke-Tool "write_file" @{ path = "alpha.txt"; content = $ALPHA_COMMITTED }
    Check "T23_WRITE_AFTER_ROLLBACK" ($w3.Json.ok -eq $true) ("output=" + $w3.Json.output)
    $alphaCommittedSha = Get-Sha $alphaPath
    $ct = Invoke-Tx "commit" @{}
    Check "T24_COMMIT_OK" ($ct.Status -eq 200 -and $ct.Json.ok -and $ct.Json.committed -eq $true) `
        ("http=" + $ct.Status + " file_writes=" + $ct.Json.file_writes)
    Check "T25_COMMIT_PERSISTS_ON_DISK" ((Get-Sha $alphaPath) -eq $alphaCommittedSha) `
        ("alpha_sha=" + (Get-Sha $alphaPath))

    $rec1 = Invoke-Tx "recover" @{}
    Check "T26_RECOVERY_SEES_NO_OPEN_TX" `
        ($rec1.Status -eq 200 -and $rec1.Json.incomplete_transactions -eq 0 -and $rec1.Json.files_restored -eq 0) `
        ("journals_scanned=" + $rec1.Json.journals_scanned + " closed=" + $rec1.Json.closed_transactions + `
         " incomplete=" + $rec1.Json.incomplete_transactions + " restored=" + $rec1.Json.files_restored)
    Check "T27_POST_ROLLBACK_WORK_NOT_REVERTED" ((Get-Sha $alphaPath) -eq $alphaCommittedSha) `
        ("alpha_sha=" + (Get-Sha $alphaPath) + " expected=" + $alphaCommittedSha)

    $bo = Invoke-Tool "write_file" @{ path = "after_commit.txt"; content = "no tx here" }
    Check "T28_WRITE_REFUSED_AGAIN_AFTER_COMMIT" `
        (($bo.Json.ok -eq $false) -and ($bo.Json.error -match 'requires an open checkpoint transaction')) `
        ("error=" + $bo.Json.error)

    # RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001: the drive-colon defect. The
    # sandbox classified every absolute Windows path as a device/stream scheme,
    # because the test demanded scheme[1] == '\\' of the characters before the
    # colon. These two pin the fixed behaviour from both sides: an absolute path
    # OUTSIDE the root is still refused, and what an absolute path INSIDE the
    # root does is measured rather than assumed.
    $absOut = Invoke-Tool "read_file" @{ path = "C:\Windows\win.ini" }
    Check "T45_ABSOLUTE_PATH_OUTSIDE_ROOT_REFUSED" `
        (($absOut.Json.ok -eq $false) -and ($absOut.Json.error -match 'rejected by sandbox')) `
        ("error=" + $absOut.Json.error)
    $absIn = Invoke-Tool "read_file" @{ path = $alphaPath }
    Check "T46_ABSOLUTE_PATH_INSIDE_ROOT_ACCEPTED" ($absIn.Json.ok -eq $true) `
        ("error=" + $absIn.Json.error + " bytes=" + $(if ($absIn.Json.output) { $absIn.Json.output.Length } else { 0 }))

    # The junction escape. mklink /J is available to an unprivileged user on
    # Windows, so this needs no elevation: a directory junction inside the root
    # pointing at a directory outside it. Lexical canonicalisation does not
    # follow it, so before the reparse-point check this read a file the policy
    # never authorised -- and with write enabled it would have written one.
    $junction = Join-Path $ws "escape_link"
    $outsideDir = Join-Path $OutDir "outside"
    New-Item -ItemType Directory -Path $outsideDir -Force | Out-Null
    $secretPath = Join-Path $outsideDir "secret.txt"
    [System.IO.File]::WriteAllText($secretPath, "RAWRXD_SHOULD_NEVER_BE_READ", $script:Utf8NoBom)
    cmd /c "mklink /J `"$junction`" `"$outsideDir`"" | Out-Null
    if (Test-Path -LiteralPath $junction) {
        try {
            $jr = Invoke-Tool "read_file" @{ path = "escape_link\secret.txt" }
            Check "T47_JUNCTION_ESCAPE_REFUSED" `
                (($jr.Json.ok -eq $false) -and ($jr.Json.error -match 'reparse point')) `
                ("error=" + $jr.Json.error)
            Check "T48_SECRET_BYTES_NOT_DISCLOSED" `
                ($jr.Json.output -notmatch 'RAWRXD_SHOULD_NEVER_BE_READ') `
                "no out-of-root bytes in the tool result"
            $jw = Invoke-Tool "write_file" @{ path = "escape_link\planted.txt"; content = "planted" }
            Check "T49_WRITE_THROUGH_JUNCTION_REFUSED" `
                (($jw.Json.ok -eq $false) -and ($jw.Json.error -match 'reparse point')) `
                ("error=" + $jw.Json.error)
            Check "T50_NOTHING_PLANTED_OUTSIDE_ROOT" `
                (-not (Test-Path -LiteralPath (Join-Path $outsideDir "planted.txt"))) `
                "planted.txt absent outside the root"
        }
        finally {
            # rmdir on a junction removes the link, never the target.
            cmd /c "rmdir `"$junction`"" | Out-Null
        }
    }
    else {
        Check "T47_JUNCTION_ESCAPE_REFUSED" $false "mklink /J failed: junction not created"
    }
}
finally {
    Stop-Server
}

# ===========================================================================
# Phase 2 -- crash after a journalled write, recovered by a SEPARATE process
# ===========================================================================
Set-ServerEnv @{ RAWRXD_CKPT_FAULT = "crash_after:1" }
if (-not (Start-Server "p2_crash")) { throw "phase 2 server did not start" }
try {
    $b2 = Invoke-Tx "begin" @{ intent = "cert crash after write" }
    Check "T29_CRASH_TX_OPENED" ($b2.Json.ok -eq $true) ("tx=" + $b2.Json.tx)
    $r2 = Invoke-Tool "write_file" @{ path = "alpha.txt"; content = "// alpha CRASH-WINDOW EDIT`n" }
    Check "T30_CRASH_KILLED_SERVER_MID_TX" ($r2.Status -eq 0 -or $null -eq $r2.Json) `
        ("curl_status=" + $r2.Status + " (no response: the process died at the armed fault point)")
}
finally {
    Stop-Server
}
Start-Sleep -Milliseconds 500

$crashSha = Get-Sha $alphaPath
Check "T31_CRASH_LEFT_EDIT_ON_DISK" ($crashSha -ne $alphaCommittedSha) ("alpha_sha=" + $crashSha)

Set-ServerEnv @{ RAWRXD_CKPT_FAULT = "" }
if (-not (Start-Server "p3_recover")) { throw "phase 3 server did not start" }
try {
    $rec2 = Invoke-Tx "recover" @{}
    Check "T32_SEPARATE_PROCESS_RECOVERY_FOUND_TX" `
        ($rec2.Status -eq 200 -and $rec2.Json.incomplete_transactions -ge 1) `
        ("journals_scanned=" + $rec2.Json.journals_scanned + " incomplete=" + $rec2.Json.incomplete_transactions)
    Check "T33_SEPARATE_PROCESS_RECOVERY_RESTORED" `
        ($rec2.Json.files_restored -ge 1 -and $rec2.Json.files_verified -ge 1 -and `
         $rec2.Json.files_failed -eq 0 -and $rec2.Json.all_restored -eq $true) `
        ("restored=" + $rec2.Json.files_restored + " verified=" + $rec2.Json.files_verified + " failed=" + $rec2.Json.files_failed)
    Check "T34_CRASH_EDIT_REVERTED_TO_PRECRASH" ((Get-Sha $alphaPath) -eq $alphaCommittedSha) `
        ("alpha_sha=" + (Get-Sha $alphaPath) + " expected_precrash=" + $alphaCommittedSha)
    Check "T35_RECOVERY_IDENTITY_MEASURED" `
        ($rec2.Json.identity_before -ne $null -and $rec2.Json.identity_after -ne $null) `
        ("before=" + $rec2.Json.identity_before + " after=" + $rec2.Json.identity_after)

    $rec3 = Invoke-Tx "recover" @{}
    Check "T36_SECOND_RECOVERY_PASS_IS_A_NOOP" `
        ($rec3.Json.incomplete_transactions -eq 0 -and $rec3.Json.files_restored -eq 0) `
        ("incomplete=" + $rec3.Json.incomplete_transactions + " restored=" + $rec3.Json.files_restored)
}
finally {
    Stop-Server
}

# ===========================================================================
# Phase 3 -- torn write: half a file on disk, then recovery removes it
# ===========================================================================
$tornPath = Join-Path $ws "torn.txt"
# The fault must be armed in the child's environment BEFORE the process starts.
Set-ServerEnv @{ RAWRXD_CKPT_FAULT = "crash_torn:1" }
if (Start-Server "p4_torn") {
    try {
        $b3 = Invoke-Tx "begin" @{ intent = "cert torn write" }
        Check "T37_TORN_TX_OPENED" ($b3.Json.ok -eq $true) ("tx=" + $b3.Json.tx)
        $r3 = Invoke-Tool "write_file" @{ path = "torn.txt"; content = ("T" * 4096) }
        Check "T38_TORN_WRITE_KILLED_SERVER" ($r3.Status -eq 0 -or $null -eq $r3.Json) `
            ("curl_status=" + $r3.Status)
    }
    finally {
        Stop-Server
    }
    Set-ServerEnv @{ RAWRXD_CKPT_FAULT = "" }
    $tornSize = if (Test-Path -LiteralPath $tornPath) { (Get-Item -LiteralPath $tornPath).Length } else { 0 }
    Check "T39_TORN_FILE_LEFT_PARTIAL" ($tornSize -gt 0 -and $tornSize -lt 4096) ("bytes_on_disk=" + $tornSize)
    if (Start-Server "p5_torn_recover") {
        try {
            $rec4 = Invoke-Tx "recover" @{}
            Check "T40_TORN_TX_RECOVERED" `
                ($rec4.Json.incomplete_transactions -ge 1 -and $rec4.Json.all_restored -eq $true) `
                ("incomplete=" + $rec4.Json.incomplete_transactions + " deleted=" + $rec4.Json.files_deleted + " failed=" + $rec4.Json.files_failed)
            Check "T41_TORN_FILE_REMOVED" (-not (Test-Path -LiteralPath $tornPath)) "torn.txt absent"
        }
        finally {
            Stop-Server
        }
    }
}

# ===========================================================================
# Phase 4 -- the explicit, logged downgrade (RAWRXD_TOOL_REQUIRE_TX=0)
# ===========================================================================
$downWs = Join-Path $OutDir "work_downgrade"
New-Item -ItemType Directory -Path $downWs -Force | Out-Null
Set-ServerEnv @{ RAWRXD_TOOL_ROOT = $downWs; RAWRXD_TOOL_REQUIRE_TX = "0" }
if (Start-Server "p6_downgrade") {
    try {
        $sd = Invoke-Tx "status" $null
        Check "T42_DOWNGRADE_PROFILE_REPORTED" `
            ($sd.Json.write_profile -eq 'unjournalled' -and $sd.Json.requires_transaction -eq $false) `
            ("write_profile=" + $sd.Json.write_profile)
        $wd = Invoke-Tool "write_file" @{ path = "downgraded.txt"; content = "written without a transaction" }
        Check "T43_DOWNGRADE_WRITES_WITHOUT_TX" ($wd.Json.ok -eq $true) ("output=" + $wd.Json.output)
        $errLog = Get-Content -LiteralPath (Join-Path $OutDir "server_p6_downgrade.err.log") -Raw
        Check "T44_DOWNGRADE_LOGGED_EXPLICITLY" ($errLog -match 'writeProfile=unjournalled') `
            "startup log names the weaker profile"
    }
    finally {
        Stop-Server
    }
}

# ===========================================================================
# Verdict
# ===========================================================================
foreach ($k in $script:SavedEnv.Keys) {
    [Environment]::SetEnvironmentVariable($k, $script:SavedEnv[$k], "Process")
}

$verdict = if ($script:Failures.Count -eq 0) { "PASS" } else { "FAIL" }
Say ""
Say "checks_total=$($script:Checks)"
Say "checks_failed=$($script:Failures.Count)"
if ($script:Failures.Count -gt 0) { Say ("failed=" + ($script:Failures -join ",")) }
Say "RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001=$verdict"
Say "write_profile_certified=transactional"
Say "unjournalled_write_profile_certified=yes (explicit RAWRXD_TOOL_REQUIRE_TX=0 only)"

$receipt = Join-Path $OutDir "CERT_LOG.txt"
[System.IO.File]::WriteAllText($receipt, ($script:Log -join [Environment]::NewLine), $script:Utf8NoBom)
Write-Host "receipt=$receipt"

if ($verdict -ne "PASS") { exit 1 }
exit 0
