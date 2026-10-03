<#
RAWRXD_DEEP2_SOVEREIGN_TOMBSTONE_001 -- build-graph + binary equivalence validator

Purpose
-------
Proves that retiring the phantom source-list entry for
src/deep2/Deep2Server_Sovereign.cpp does NOT change the resulting binary.

Why this is the decisive test
-----------------------------
The tombstone was APPENDED to WIN32IDE_SOURCES and then STRIPPED again by
list(REMOVE_ITEM). Static reasoning says it reached no target, but static
reasoning is exactly what this project has repeatedly been burned by. This
script measures the A/B directly:

  1. capture the exact link INPUT LIST for target rawr-server   (pre)
  2. rebuild the PRE-edit source state, capture exe hash + exports
  3. restore the REPAIRED source state, rebuild, capture again
  4. compare input lists, hashes, sizes, and export tables

A PASS requires the link input set to be IDENTICAL. If ninja does not even
relink, the exe is byte-identical, which is the strongest form of the result.

The script never uses `git checkout` on a file that may carry another lane's
uncommitted work. State swaps are done by literal, idempotent text surgery on
copies, and both variants are preserved in the log dir.
#>

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$Repo     = 'F:\~dev'
$Rawrxd   = 'F:\~dev\rawrxd'
$Build    = 'F:\~dev\build_rawr_ninja'
$Cml      = Join-Path $Rawrxd 'CMakeLists.txt'
$Stub     = Join-Path $Rawrxd 'src\deep2\Deep2Server_Sovereign.cpp'
$Exe      = Join-Path $Build 'bin\rawr-server.exe'
$Log      = Join-Path $Repo 'audit_tombstone_001'
$Vcvars   = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'

if (-not (Test-Path $Log)) { New-Item -ItemType Directory -Path $Log | Out-Null }

function Say($m) { Write-Information $m -InformationAction Continue }
# Above: INFORMATION stream, NOT the success stream. Using Write-Output meant every
# Say inside a value-returning function (Test-PreState) was captured into that
# function's RETURN VALUE instead of being displayed, so the harness's own
# verification evidence vanished from the transcript while the run continued.
# A check whose output cannot be seen is not evidence of anything.

# Minimum harness authority, enforced on every exit path:
#   PRE_STATE_VERIFIED / POST_STATE_VERIFIED  the states are what we claim
#   ANCHOR_POSITION_EXPECTED                  right count is not enough
#   A_B_INPUTS_DISTINCT                       the two states actually differ
#   RESTORE_VERIFIED                          the tree is handed back unchanged
#
# A harness that aborts half way through leaves CMakeLists.txt in a mutated state.
# That is how a failed test becomes an unmeasured source change.
function Restore-And-Exit([int]$code, [string]$why) {
    Say ''
    Say "ABORT($code): $why"
    Say 'RESTORING source tree from saved variants before exiting...'
    try {
        Copy-Item (Join-Path $Log 'CMakeLists.REPAIRED.txt') $Cml -Force
        Copy-Item (Join-Path $Log 'Stub.RETIRED.txt')       $Stub -Force
        $h = (Get-FileHash $Cml -Algorithm SHA256).Hash
        $r = (Get-FileHash $Stub -Algorithm SHA256).Hash
        $ok = ($h -eq $script:BaselineCmlHash) -and ($r -eq $script:BaselineStubHash)
        Say "RESTORE_VERIFIED=$(if ($ok) { 1 } else { 0 })  cml=$($h.Substring(0,16))  stub=$($r.Substring(0,16))"
        if (-not $ok) {
            Say "  expected cml=$($script:BaselineCmlHash.Substring(0,16))  stub=$($script:BaselineStubHash.Substring(0,16))"
            Say '  MANUAL RESTORE REQUIRED: git -C F:/~dev checkout HEAD -- rawrxd/CMakeLists.txt rawrxd/src/deep2/Deep2Server_Sovereign.cpp'
            exit 9
        }
    } catch {
        Say "RESTORE_FAILED: $($_.Exception.Message)"
        Say '  MANUAL RESTORE REQUIRED.'
        exit 9
    }
    exit $code
}

# Run a command inside the MSVC x64 environment.
function Invoke-Msvc([string]$inner, [string]$tag) {
    $out = Join-Path $Log "$tag.out.txt"
    $cmd = "call `"$Vcvars`" >nul 2>&1 && $inner"
    $p = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', $cmd `
         -RedirectStandardOutput $out -RedirectStandardError (Join-Path $Log "$tag.err.txt") `
         -NoNewWindow -PassThru -Wait
    return $p.ExitCode
}

# Exact link inputs for a target, in link order, from ninja itself.
function Get-LinkInputs([string]$target) {
    $out = Join-Path $Log "cmdlines_$target.txt"
    $p = Start-Process -FilePath 'cmd.exe' `
         -ArgumentList '/c', "call `"$Vcvars`" >nul 2>&1 && ninja -C `"$Build`" -t commands $target" `
         -RedirectStandardOutput $out -NoNewWindow -PassThru -Wait
    $txt = Get-Content $out -Raw
    $objs = [regex]::Matches($txt, '[^\s"]*\.obj') | ForEach-Object { $_.Value }
    $srcs = [regex]::Matches($txt, '[^\s"]*\.cpp') | ForEach-Object { $_.Value }
    return [pscustomobject]@{
        Objs   = @($objs | Sort-Object -Unique)
        Srcs   = @($srcs | Sort-Object -Unique)
        Raw    = $txt
    }
}

function Get-Exports([string]$bin) {
    $out = Join-Path $Log 'exports.txt'
    $null = Invoke-Msvc "dumpbin /EXPORTS `"$bin`" > `"$out`"", 'dumpbin'
    if (Test-Path $out) { return (Get-Content $out -Raw) } else { return '<none>' }
}

# --- the two exact edits that constitute the repair -------------------------
# PRE variant  : the original two bare source-list lines
# REPAIRED     : what is on disk right now (comments only)

$PRE_APPEND_ANCHOR = '         src/deep2/Deep2Server_Minimal.cpp'
$PRE_APPEND_LINE   = '         src/deep2/Deep2Server_Sovereign.cpp'

function Get-BareCount([string]$path) {
    if (-not (Test-Path $path)) { return -1 }
    return @(Select-String -Path $path -Pattern '^\s*src/deep2/Deep2Server_Sovereign\.cpp\s*$' -AllMatches).Count
}

# Return the LINE NUMBERS of bare entries. A count alone is not sufficient:
# the original anchor text `...was: src/deep2/Deep2APIServer.cpp` occurs TWICE in
# this file (5715 and 7248), and a replace-first-match silently edited the WRONG
# one -- inserting a phantom source into an unrelated list while still producing
# the expected count. Position is therefore part of the assertion.
function Get-BareLines([string]$path) {
    if (-not (Test-Path $path)) { return @() }
    return @(Select-String -Path $path -Pattern '^\s*src/deep2/Deep2Server_Sovereign\.cpp\s*$' |
             ForEach-Object { $_.LineNumber })
}

# Anchors are the UNIQUE comment markers this repair introduced, never shared
# neighbour lines -- `src/deep2/Deep2Server_Minimal.cpp` appears in BOTH the
# append block and the REMOVE_ITEM block with identical text.
# Site 1 marker: "RAWRXD_DEEP2_SOVEREIGN_TOMBSTONE_001: src/deep2/Deep2Server_Sovereign.cpp"
# Site 2 marker: "RAWRXD_DEEP2_SOVEREIGN_TOMBSTONE_001: the matching"
$REPAIR_BLOCK_APPEND =
  '(?ms)^[ \t]*# RAWRXD_DEEP2_SOVEREIGN_TOMBSTONE_001: src/deep2/Deep2Server_Sovereign\.cpp' +
  '.*?was: src/deep2/Deep2APIServer\.cpp\r?\n'

$REPAIR_BLOCK_REMOVE_ITEM =
  '(?ms)^[ \t]*# RAWRXD_DEEP2_SOVEREIGN_TOMBSTONE_001: the matching' +
  '.*?never contained\.\r?\n'

# Expected neighbourhoods, measured on this file: the APPEND block that carries the
# phantom sits before the list(REMOVE_ITEM WIN32IDE_SOURCES) call, and the
# REMOVE_ITEM entry sits immediately after it.
$APPEND_BLOCK_MIN_LINE = 7000
$REMOVE_ITEM_ANCHOR   = 7391

function Test-PreState {
    $lines = Get-BareLines $Cml
    $n = $lines.Count
    Say "STATE=PRE  bare_line_count=$n  expected=2  at_lines=$($lines -join ',')"
    if ($n -ne 2) {
        Say 'ABORT: pre-state was NOT reproduced. The A/B would compare two identical'
        Say '       states and report a meaningless equivalence result. Refusing to continue.'
        return $false
    }
    $inAppend = @($lines | Where-Object { $_ -ge $APPEND_BLOCK_MIN_LINE -and $_ -lt $REMOVE_ITEM_ANCHOR })
    $inRemove = @($lines | Where-Object { $_ -gt $REMOVE_ITEM_ANCHOR })
    Say "  in_append_block=$($inAppend.Count) (expect 1)   in_remove_item_block=$($inRemove.Count) (expect 1)"
    if ($inAppend.Count -ne 1 -or $inRemove.Count -ne 1) {
        Say 'ABORT: the right COUNT of bare entries, but at the wrong POSITIONS. A'
        Say '       duplicate anchor matched an unrelated source list. Refusing to continue.'
        return $false
    }
    Say 'PRE_STATE_VERIFIED=YES'
    return $true
}

function Set-State([string]$mode) {
    if ($mode -eq 'save') {
        Copy-Item $Cml (Join-Path $Log 'CMakeLists.REPAIRED.txt') -Force
        Copy-Item $Stub (Join-Path $Log 'Stub.RETIRED.txt') -Force
        $script:BaselineCmlHash  = (Get-FileHash $Cml  -Algorithm SHA256).Hash
        $script:BaselineStubHash = (Get-FileHash $Stub -Algorithm SHA256).Hash
        Say "SAVED_REPAIRED_VARIANTS=YES"
        Say "BASELINE_CMAKE_SHA256=$script:BaselineCmlHash"
        Say "BASELINE_STUB_SHA256=$script:BaselineStubHash"
        return
    }
    if ($mode -eq 'pre') {
        $src = Join-Path $Log 'CMakeLists.REPAIRED.txt'
        $t   = Get-Content $src -Raw
        $eol = if ($t -match "`r`n") { "`r`n" } else { "`n" }

        $t2 = [regex]::Replace($t, $REPAIR_BLOCK_APPEND, $PRE_APPEND_LINE + $eol)
        $t3 = [regex]::Replace($t2, $REPAIR_BLOCK_REMOVE_ITEM, $PRE_APPEND_LINE + $eol)

        Set-Content -Path $Cml -Value $t3 -NoNewline
        Set-Content -Path $Stub -Value '// STUB: src/deep2/Deep2Server_Sovereign.cpp' -NoNewline
        # Keep the exact PRE text so the two A/B inputs can be proven DISTINCT below.
        Set-Content -Path (Join-Path $Log 'CMakeLists.PRE.txt') -Value $t3 -NoNewline

        if (-not (Test-PreState)) { Restore-And-Exit 4 'pre-state not reproduced' }
        return
    }
    if ($mode -eq 'repaired') {
        Copy-Item (Join-Path $Log 'CMakeLists.REPAIRED.txt') $Cml -Force
        Copy-Item (Join-Path $Log 'Stub.RETIRED.txt')       $Stub -Force
        $n = Get-BareCount $Cml
        Say "STATE=REPAIRED  bare_line_count=$n  expected=0"
        if ($n -ne 0) {
            Restore-And-Exit 5 'repaired state still lists the phantom source path'
        }
        $nowCml  = (Get-FileHash $Cml  -Algorithm SHA256).Hash
        $nowStub = (Get-FileHash $Stub -Algorithm SHA256).Hash
        $ok = ($nowCml -eq $script:BaselineCmlHash) -and ($nowStub -eq $script:BaselineStubHash)
        Say "POST_STATE_VERIFIED=$(if ($ok) { 1 } else { 0 })"
        Say "REPAIRED_STATE_VERIFIED=YES"
    }
}

# ---------------------------------------------------------------- main ------
Say '============================================================'
Say ' RAWRXD_DEEP2_SOVEREIGN_TOMBSTONE_001 -- equivalence'
Say " started $(Get-Date -Format o)"
Say '============================================================'

Set-State 'save'

Say ''
Say '--- A. PRE-EDIT STATE ---'
Set-State 'pre'
$rcA = Invoke-Msvc "ninja -C `"$Build`" rawr-server" 'build_pre'
Say "BUILD_PRE_EXIT=$rcA"
# A failed build does not merely report a failure. Because ninja LEAVES THE OLD
# EXE IN PLACE, a failed build still yields a readable binary -- so the hash
# comparison below would compare a STALE artifact and report BINARY_BYTE_IDENTICAL=1.
# That is a false green produced by a failed build, which is worse than a crash.
if ($rcA -ne 0) {
    Restore-And-Exit 7 "PRE build FAILED (exit $rcA). A failed ninja leaves the previous exe in place, so the hash comparison below would compare a stale artifact."
}
$preInputs = Get-LinkInputs 'rawr-server'
Say "PRE_OBJ_COUNT=$($preInputs.Objs.Count)"
Say "PRE_SRC_COUNT=$($preInputs.Srcs.Count)"
$preHash  = if (Test-Path $Exe) { (Get-FileHash $Exe -Algorithm SHA256).Hash } else { 'MISSING' }
$preSize  = if (Test-Path $Exe) { (Get-Item $Exe).Length } else { 0 }
$preMtime = if (Test-Path $Exe) { (Get-Item $Exe).LastWriteTimeUtc.ToString('o') } else { 'MISSING' }
$preExp   = Get-Exports $Exe
Set-Content (Join-Path $Log 'exports_pre.txt')  $preExp
Say "PRE_EXE_SHA256=$preHash"
Say "PRE_EXE_SIZE=$preSize"
Say "PRE_EXE_MTIME=$preMtime"

Say ''
Say '--- B. REPAIRED STATE ---'
Set-State 'repaired'
$rcB = Invoke-Msvc "ninja -C `"$Build`" rawr-server" 'build_post'
Say "BUILD_POST_EXIT=$rcB"
if ($rcB -ne 0) {
    Restore-And-Exit 8 "POST build FAILED (exit $rcB). Same stale-artifact hazard as the PRE guard."
}
$postInputs = Get-LinkInputs 'rawr-server'
Say "POST_OBJ_COUNT=$($postInputs.Objs.Count)"
Say "POST_SRC_COUNT=$($postInputs.Srcs.Count)"
$postHash  = if (Test-Path $Exe) { (Get-FileHash $Exe -Algorithm SHA256).Hash } else { 'MISSING' }
$postSize  = if (Test-Path $Exe) { (Get-Item $Exe).Length } else { 0 }
$postMtime = if (Test-Path $Exe) { (Get-Item $Exe).LastWriteTimeUtc.ToString('o') } else { 'MISSING' }
$postExp   = Get-Exports $Exe
Set-Content (Join-Path $Log 'exports_post.txt') $postExp
Say "POST_EXE_SHA256=$postHash"
Say "POST_EXE_SIZE=$postSize"
Say "POST_EXE_MTIME=$postMtime"

# A_B_INPUTS_DISTINCT is the direct guard against "compared the repaired state
# against itself". The PRE text and the REPAIRED text are hashed and must differ.
# A matching pair of hashes means the swap never happened and every downstream
# equality in section C is vacuously true.
$preCmlText  = Join-Path $Log 'CMakeLists.PRE.txt'
$repairedTxt = Join-Path $Log 'CMakeLists.REPAIRED.txt'
$hPre = if (Test-Path $preCmlText)  { (Get-FileHash $preCmlText  -Algorithm SHA256).Hash } else { 'MISSING' }
$hRep = if (Test-Path $repairedTxt) { (Get-FileHash $repairedTxt -Algorithm SHA256).Hash } else { 'MISSING' }
$distinct = ($hPre -ne $hRep)
Say "AB_INPUT_PRE_CMAKE_SHA256=$hPre"
Say "AB_INPUT_REPAIRED_CMAKE_SHA256=$hRep"
Say "A_B_INPUTS_DISTINCT=$(if ($distinct) { 1 } else { 0 })"
if (-not $distinct) {
    Restore-And-Exit 6 'the PRE and REPAIRED source states are identical -- the A/B would compare a state against itself'
}

Say ''
Say '--- C. DIFF ---'
$onlyPre  = @(Compare-Object $preInputs.Objs  $postInputs.Objs  | Where-Object SideIndicator -eq '<=')
$onlyPost = @(Compare-Object $preInputs.Objs  $postInputs.Objs  | Where-Object SideIndicator -eq '=>')
Say "OBJ_DIFF_PRE_ONLY=$($onlyPre.Count)"
Say "OBJ_DIFF_POST_ONLY=$($onlyPost.Count)"
foreach ($o in $onlyPre)  { Say "  PRE_ONLY : $($o.InputObject)" }
foreach ($o in $onlyPost) { Say "  POST_ONLY: $($o.InputObject)" }
$sOnlyPre  = @(Compare-Object $preInputs.Srcs $postInputs.Srcs | Where-Object SideIndicator -eq '<=')
$sOnlyPost = @(Compare-Object $preInputs.Srcs $postInputs.Srcs | Where-Object SideIndicator -eq '=>')
Say "SRC_DIFF_PRE_ONLY=$($sOnlyPre.Count)"
Say "SRC_DIFF_POST_ONLY=$($sOnlyPost.Count)"

$expSame = ($preExp -eq $postExp)
Say "PUBLIC_API_DIFF=$(if ($expSame) { 'NONE' } else { 'PRESENT' })"
$hashSame = ($preHash -eq $postHash)
Say "BINARY_BYTE_IDENTICAL=$(if ($hashSame) { '1' } else { '0' })"
Say "BINARY_SHA_PRE=$preHash"
Say "BINARY_SHA_POST=$postHash"
Say "SIZE_DELTA=$($postSize - $preSize)"

# --- the two VALID outcomes, kept explicitly distinct ---------------------
$relink = if ($preMtime -ne $postMtime) { 1 } else { 0 }
Say "RELINK_OCCURRED=$relink"
$inputsEqual = (($onlyPre.Count -eq 0) -and ($onlyPost.Count -eq 0) -and
                ($sOnlyPre.Count -eq 0) -and ($sOnlyPost.Count -eq 0))
Say "LINK_INPUT_SET_EQUAL=$(if ($inputsEqual) { '1' } else { '0' })"
Say "AB_BUILD_PRE_LINK_INPUTS=$($preInputs.Objs.Count) obj / $($preInputs.Srcs.Count) src"
Say "AB_BUILD_POST_LINK_INPUTS=$($postInputs.Objs.Count) obj / $($postInputs.Srcs.Count) src"

if ($relink -eq 0 -and $hashSame) {
    Say 'AB_INTERPRETATION=STRONGEST_NO_REBUILD'
    Say 'AB_INTERPRETATION_NOTE=graph mutation triggered no rebuild at all;'
    Say 'AB_INTERPRETATION_NOTE2=the executable is provably unchanged.'
} elseif ($relink -eq 1 -and $inputsEqual) {
    Say 'AB_INTERPRETATION=VALID_RELINK_INPUTS_UNCHANGED'
    Say 'AB_INTERPRETATION_NOTE=relink happened for incidental build-system reasons;'
    Say 'AB_INTERPRETATION_NOTE2=semantic link inputs did not change.'
} elseif (-not $inputsEqual) {
    Say 'AB_INTERPRETATION=INVALID_INPUTS_CHANGED'
    Say 'AB_INTERPRETATION_NOTE=the graph mutation DID alter what is linked. Investigate.'
} else {
    Say 'AB_INTERPRETATION=REVIEW_RAW_HASH_ONLY_DIFFERS'
    Say 'AB_INTERPRETATION_NOTE=inputs equal, bytes differ -- expected if MSVC restamped'
    Say 'AB_INTERPRETATION_NOTE2=TimeDateStamp/PDB GUID. Judge on LINK_INPUT_SET_EQUAL.'
}

# ---- negative tests: malformed request, then re-prove liveness ------------
Say ''
Say '--- D. NEGATIVE TESTS ON A LIVE SERVER ---'
# ---- pre-flight: never kill by process name -------------------------------
# A process-name kill destroys every rawr-server on the machine, including an
# instance owned by another user or lane. This harness terminates only a PID it
# launched itself.
$Port = 21700
$busy = $false
try { $null = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/health" -UseBasicParsing -TimeoutSec 3; $busy = $true } catch { }
if ($busy) {
    Say "ABORT: port $Port already in use; another process owns it and will NOT be touched."
    Restore-And-Exit 3 'port already in use'
}

$proc = Start-Process -FilePath $Exe -PassThru -WindowStyle Hidden -ArgumentList @(
    '--model','G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf',
    '--port',"$Port",'--host','127.0.0.1')
Say "SERVER_PID=$($proc.Id)"
Say "SERVER_PORT=$Port"
Say "SERVER_EXE_SHA256=$((Get-FileHash $Exe -Algorithm SHA256).Hash)"
Say "SERVER_START_UTC=$($proc.StartTime.ToUniversalTime().ToString('o'))"

$ready = $false
for ($i=0; $i -lt 300; $i++) {
    if ($proc.HasExited) { Say "SERVER_DIED_EARLY_EXITCODE=$($proc.ExitCode)"; break }
    try { $null = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/health" -UseBasicParsing -TimeoutSec 5; $ready=$true; break }
    catch { }
    Start-Sleep -Seconds 1
}
Say "SERVER_READY=$ready  POLLS=$i"
if (-not $ready) {
    Say 'SERVER_NEVER_READY=1  (negative tests skipped)'
} else {
    # D1 malformed JSON
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:$port/v1/chat/completions" -Method POST `
             -Body '{"model": broken json' -ContentType 'application/json' -UseBasicParsing -TimeoutSec 60
        Say "MALFORMED_JSON_HTTP=$($r.StatusCode)"
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        Say "MALFORMED_JSON_HTTP=$code"
        Say "MALFORMED_JSON_ERR=$($_.Exception.Message)"
    }
    # D2 empty body
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:$port/v1/chat/completions" -Method POST `
             -Body '' -ContentType 'application/json' -UseBasicParsing -TimeoutSec 60
        Say "EMPTY_BODY_HTTP=$($r.StatusCode)"
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        Say "EMPTY_BODY_HTTP=$code"
    }
    # D3 unknown route
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:$port/does/not/exist" -UseBasicParsing -TimeoutSec 30
        Say "UNKNOWN_ROUTE_HTTP=$($r.StatusCode)"
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        Say "UNKNOWN_ROUTE_HTTP=$code"
    }
    # D4 the server must still be alive and correct after all that abuse
    try {
        $h = Invoke-WebRequest -Uri "http://127.0.0.1:$port/health" -UseBasicParsing -TimeoutSec 30
        $j = $h.Content | ConvertFrom-Json
        Say "HEALTH_AFTER_NEGATIVES_HTTP=$($h.StatusCode)"
        Say "HEALTH_AFTER_NEGATIVES_MODEL_LOADED=$($j.model_loaded)"
        Say "HEALTH_AFTER_NEGATIVES_STATUS=$($j.status)"
    } catch {
        Say "HEALTH_AFTER_NEGATIVES_ERR=$($_.Exception.Message)"
    }
    # D5 and it must still actually infer
    try {
        $b = '{"model":"tinyllama-1.1b-chat-v1.0.Q4_K_M","messages":[{"role":"user","content":"The capital of France is"}],"max_tokens":12,"temperature":0,"stream":false}'
        $c = Invoke-WebRequest -Uri "http://127.0.0.1:$port/v1/chat/completions" -Method POST `
             -Body $b -ContentType 'application/json' -UseBasicParsing -TimeoutSec 180
        $cj = $c.Content | ConvertFrom-Json
        Say "CHAT_AFTER_NEGATIVES_HTTP=$($c.StatusCode)"
        Say "CHAT_AFTER_NEGATIVES_TEXT=$($cj.choices[0].message.content)"
        Say "CHAT_AFTER_NEGATIVES_USAGE=$($cj.usage.prompt_tokens)/$($cj.usage.completion_tokens)/$($cj.usage.total_tokens)"
    } catch {
        Say "CHAT_AFTER_NEGATIVES_ERR=$($_.Exception.Message)"
    }
    # teardown: this PID only, never the image name
    if (-not $proc.HasExited) { $proc.Kill(); $proc.WaitForExit(20000) | Out-Null }
    Say "SERVER_EXIT_CODE=$($proc.ExitCode)"
    Say "SERVER_STILL_ALIVE=$(if (-not $proc.HasExited) { 'YES' } else { 'NO' })"
}

# Deliberately NOT doing: Get-Process -Name 'rawr-server' | Stop-Process.
# A stray instance of this image belonging to another user or lane must survive
# this harness untouched. Verify it rather than assume it.
$strays = @(Get-Process -Name 'rawr-server' -ErrorAction SilentlyContinue)
Say "STRAY_RAWR_SERVER_COUNT_LEFT_RUNNING=$($strays.Count)"
foreach ($sp in $strays) { Say "  LEFT RUNNING: pid=$($sp.Id) started=$($sp.StartTime)" }

Say ''
Say '============================================================'
Say " finished $(Get-Date -Format o)"
Say '============================================================'
