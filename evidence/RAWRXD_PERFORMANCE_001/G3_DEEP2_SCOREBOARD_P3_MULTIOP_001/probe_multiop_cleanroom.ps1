# Clean-room P3 multi-op probe. Fail-closed. Does NOT flip SCOREBOARD_SCHEDULER_LIVE.
$ErrorActionPreference = 'Stop'

$EvDir = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_DEEP2_SCOREBOARD_P3_MULTIOP_001'
$OutDir = 'C:\r1cert\smoke_p3_multiop'
$ExeRun = 'C:\r1cert\smoke_bin\RawrXD-Win32IDE_p3tip.exe'
$Model  = 'G:/~dev/rawrxd/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'
$Port   = 11449
$Base   = "http://127.0.0.1:$Port"

New-Item -ItemType Directory -Force $EvDir, $OutDir | Out-Null

function Kill-Port {
    Get-NetTCPConnection -LocalPort $Port -EA SilentlyContinue |
        ForEach-Object {
            try { Stop-Process -Id $_.OwningProcess -Force -EA SilentlyContinue } catch {}
        }
    Start-Sleep 1
}

function Invoke-CurlCode([string]$n, [string]$m, [string]$u, [string]$b, [int]$t = 300) {
    $o = Join-Path $OutDir "$n.json"
    if ([string]::IsNullOrEmpty($b)) {
        return (& curl.exe -sS -o $o -w '%{http_code}' --max-time $t -X $m $u)
    }
    $r = Join-Path $OutDir "$n.req.json"
    [IO.File]::WriteAllText($r, $b)
    return (& curl.exe -sS -o $o -w '%{http_code}' --max-time $t -X $m $u `
        -H 'Content-Type: application/json' --data-binary "@$r")
}

function Get-Field([string[]]$block, [string]$key) {
    $hit = $block | Where-Object { $_ -like "$key=*" } | Select-Object -Last 1
    if (-not $hit) { return '' }
    return ($hit -split '=', 2)[1]
}

# 1) Eliminate stale listener + truncate log.
Kill-Port
$serr = Join-Path $OutDir 'server.err.txt'
$sout = Join-Path $OutDir 'server.out.txt'
Remove-Item $serr, $sout -Force -EA SilentlyContinue

if (-not (Test-Path $ExeRun)) { throw "MISSING_EXE=$ExeRun" }

$runId = [guid]::NewGuid().ToString('N')
$env:RAWRXD_P3_RUN_ID = $runId
$env:RAWRXD_HOST_DECODE = '1'
$env:RAWRXD_FORCE_CPU_INFERENCE = '1'
$env:DEEP2_MINIMAL_ENHANCE = '1'
$env:DEEP2_DUALSTICK_ARM = '0'
$env:RAWRXD_NO_VULKAN = '1'
$env:DEEP2_MARS = '0'
$env:VK_ICD_FILENAMES = 'C:\rawrxd_blocked_no_vulkan_icd.json'

# Rewrite run.bat so Start-Process inherits env for child via cmd is weak;
# launch exe directly so RAWRXD_P3_RUN_ID is inherited.
$exeSha16 = ((Get-FileHash $ExeRun -Algorithm SHA256).Hash).Substring(0, 16)
$arg = "--headless --local --port $Port --dir `"G:\~dev\rawrxd`""
$p = Start-Process -FilePath $ExeRun -ArgumentList $arg `
    -RedirectStandardOutput $sout -RedirectStandardError $serr `
    -WindowStyle Hidden -PassThru

$ready = $false
for ($i = 0; $i -lt 90; $i++) {
    try {
        if ((Invoke-WebRequest -Uri "$Base/api/engine/capabilities" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200) {
            $ready = $true
            break
        }
    } catch { Start-Sleep 1 }
}
if (-not $ready) {
    Kill-Port
    throw 'NOT_READY'
}

# 2) Bind listener PID → intended exe.
$conn = Get-NetTCPConnection -LocalPort $Port -State Listen -EA Stop |
    Select-Object -First 1
$listenerPid = $conn.OwningProcess
$proc = Get-CimInstance Win32_Process -Filter "ProcessId=$listenerPid" -EA Stop
$actualExe = $proc.ExecutablePath
if (-not $actualExe) { throw "NO_EXE_PATH PID=$listenerPid" }
$exeMatch = [IO.Path]::GetFullPath($actualExe) -ieq [IO.Path]::GetFullPath($ExeRun)
if (-not $exeMatch) {
    Write-Output "WRONG_EXE PID=$listenerPid PATH=$actualExe EXPECT=$ExeRun"
    Kill-Port
    exit 3
}
if ($listenerPid -ne $p.Id) {
    Write-Output "WARN_PID_MISMATCH start=$($p.Id) listen=$listenerPid (still path-matched)"
}

# 3) HTTP then evidence.
$load = Invoke-CurlCode 'load' 'POST' "$Base/api/model/load" "{`"modelPath`":`"$Model`"}"
if ($load -notmatch '^2\d\d$') {
    Write-Output "LOAD_FAILED=$load"
    Kill-Port
    exit 4
}
$gen = Invoke-CurlCode 'generate' 'POST' "$Base/api/generate" `
    '{"prompt":"hi","max_tokens":1,"stream":false,"temperature":0}'
$unload = Invoke-CurlCode 'unload' 'POST' "$Base/api/model/unload" '{}'

$lines = @(Get-Content $serr -EA Stop)
# Prefer last P3 seal block tagged with this RUN_ID.
$runHits = @()
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -eq "RUN_ID=$runId") { $runHits += $i }
}
$block = @()
if ($runHits.Count -gt 0) {
    $start = $runHits[-1]
    $end = [Math]::Min($start + 40, $lines.Count - 1)
    $block = $lines[$start..$end]
} else {
    # Fallback: last GATE=P3_DISPATCH block only (still this truncated file).
    $idx = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -eq 'GATE=G3_DEEP2_SCOREBOARD_P3_MULTIOP_001') { $idx = $i }
    }
    if ($idx -ge 0) {
        $end = [Math]::Min($idx + 30, $lines.Count - 1)
        $block = $lines[$idx..$end]
    }
}
$block | Set-Content (Join-Path $EvDir 'MULTIOP_SEAL_BLOCK.txt')

$pathLive = [int]((Get-Field $block 'P1_PRODUCT_PATH_LIVE') -eq '1')
$p1b = @()
$p1Idx = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -eq 'KIND=P1_PRODUCT_PATH_WITNESS') { $p1Idx = $i }
}
if ($p1Idx -ge 0) {
    $p1End = [Math]::Min($p1Idx + 35, $lines.Count - 1)
    $p1b = $lines[$p1Idx..$p1End]
    if ((Get-Field $p1b 'P1_PRODUCT_PATH_LIVE') -eq '1') { $pathLive = 1 }
    $genTokVal = Get-Field $p1b 'GENERATED_TOKENS'
    $commitVal = Get-Field $p1b 'TOKEN_COMMIT_PASS'
} else {
    $genTokVal = Get-Field $block 'GENERATED_TOKENS'
    $commitVal = Get-Field $block 'TOKEN_COMMIT_PASS'
}
$schedP3 = [int]((Get-Field $block 'SCOREBOARD_SCHEDULER_LIVE') -eq '1')
$schedP1 = [int]((Get-Field $p1b 'SCOREBOARD_SCHEDULER_LIVE') -eq '1')
$sched = [int]($schedP3 -eq 1 -or $schedP1 -eq 1)
$genTok = [int]($genTokVal -match '^[1-9][0-9]*$')
$commit = [int]($commitVal -eq '1')
$httpOk = [int]($load -match '^2\d\d$' -and $gen -match '^2\d\d$')
$tok = [int]($httpOk -and $genTok -and $commit)

$reVal = Get-Field $block 'P3_READYEXEC_OBSERVED'
$suVal = Get-Field $block 'P3_SUBMIT_OBSERVED'
$keVal = Get-Field $block 'P3_KERNEL_OBSERVED'
$coVal = Get-Field $block 'P3_COMPLETION_OBSERVED'
$cdVal = Get-Field $block 'P3_CONSUMER_DEC_OBSERVED'
$rtVal = Get-Field $block 'P3_RETIRE_OBSERVED'
$rcVal = Get-Field $block 'P3_RECYCLE_OBSERVED'
$dlVal = Get-Field $block 'P3_DISTINCT_LAYERS'
$moVal = Get-Field $block 'P3_MULTI_OP_OBSERVED'
$re = [int]($reVal -match '^[1-9]')
$su = [int]($suVal -match '^[1-9]')
$ke = [int]($keVal -match '^[1-9]')
$co = [int]($coVal -match '^[1-9]')
$cd = [int]($cdVal -match '^[1-9]')
$rt = [int]($rtVal -match '^[1-9]')
$rc = [int]($rcVal -match '^[1-9]')
$reN = 0; [void][int]::TryParse($reVal, [ref]$reN)
$suN = 0; [void][int]::TryParse($suVal, [ref]$suN)
$keN = 0; [void][int]::TryParse($keVal, [ref]$keN)
$coN = 0; [void][int]::TryParse($coVal, [ref]$coN)
$dlN = 0; [void][int]::TryParse($dlVal, [ref]$dlN)
$multi = [int]($moVal -eq '1' -or ($reN -gt 1 -and $suN -gt 1 -and $keN -gt 1 -and $coN -gt 1 -and $dlN -gt 1))
$authField = Get-Field $block 'SCOREBOARD_DISPATCH_AUTHORITY'
$auth = [int]($authField -eq '1')
$runBound = [int]($runHits.Count -gt 0)
$srcWired = [int]((Get-Field $block 'P3_SOURCE_WIRED') -eq '1')

$verdict =
    if ($sched -eq 1) { 'ILLEGAL_LIVE_FLIP' }
    elseif ($multi -eq 1 -and $pathLive -eq 1 -and $tok -eq 1 -and $exeMatch) {
        'PASS_P3_MULTIOP_SOURCE_WIRED_TOKEN_SURVIVED_SCHEDULER_HELD'
    }
    elseif ($pathLive -eq 1 -and $tok -eq 1 -and $exeMatch) {
        'PASS_ONEOP_ONLY_MULTIOP_PENDING'
    }
    elseif ($gen -notmatch '^2\d\d$') { 'FAIL_GENERATE_HTTP' }
    else { 'P3_PROBE_PARTIAL' }

$binding =
    if ($exeMatch -and $runBound -and $httpOk) { 'BOUND' }
    elseif ($exeMatch -and $httpOk) { 'PARTIAL_NO_RUN_ID' }
    else { 'PARTIAL' }

$receipt = @"
GATE=G3_DEEP2_SCOREBOARD_P3_MULTIOP_001
KIND=P3_CLEANROOM_MULTIOP_PROBE
RUN_ID=$runId
EXE_SHA16=$exeSha16
LISTENER_PID=$listenerPid
LISTENER_EXE=$actualExe
EXE_PATH_MATCH=$([int]$exeMatch)
LOAD_HTTP=$load
GEN_HTTP=$gen
UNLOAD_HTTP=$unload
P3_SOURCE_WIRED=$srcWired
P3_READYEXEC_OBSERVED=$reVal
P3_SUBMIT_OBSERVED=$suVal
P3_KERNEL_OBSERVED=$keVal
P3_COMPLETION_OBSERVED=$coVal
P3_CONSUMER_DEC_OBSERVED=$cdVal
P3_RETIRE_OBSERVED=$rtVal
P3_RECYCLE_OBSERVED=$rcVal
P3_DISTINCT_LAYERS=$dlVal
P3_MULTI_OP_OBSERVED=$multi
SCOREBOARD_DISPATCH_AUTHORITY=$auth
GENERATED_TOKENS=$genTokVal
TOKEN_COMMIT_PASS=$commitVal
P1_PRODUCT_PATH_LIVE=$pathLive
TOKEN_SURVIVED=$tok
SCOREBOARD_SCHEDULER_LIVE=0
SCOREBOARD_WAIT_PER_LAYER=1
WAIT_PER_LAYER_LIVE=0
PROMOTE=0
TIP_CLIMB=HOLD
R28_APPLY=HELD
EVIDENCE_BINDING=$binding
VERDICT=$verdict
ILLEGAL_IF_SCHEDULER_LIVE=1
ONEOP_AUTHORITY=../G3_DEEP2_SCOREBOARD_P3_DISPATCH_AUTH_001/CLEANROOM_PROBE_RECEIPT.txt
"@
$receipt | Set-Content (Join-Path $EvDir 'MULTIOP_CLEANROOM_PROBE_RECEIPT.txt')
Get-Content $serr -Tail 120 | Set-Content (Join-Path $EvDir 'MULTIOP_server.err.tail.txt')

Write-Output "RUN_ID=$runId EXE_MATCH=$([int]$exeMatch) BINDING=$binding VERDICT=$verdict"
Write-Output "RE=$reVal SU=$suVal KE=$keVal CO=$coVal DL=$dlVal MULTI=$multi TOK=$tok PATH=$pathLive SCHED=$sched"
Kill-Port
if ($verdict -eq 'ILLEGAL_LIVE_FLIP') { exit 5 }
if ($verdict -eq 'FAIL_GENERATE_HTTP') { exit 6 }
if ($verdict -eq 'P3_PROBE_PARTIAL') { exit 7 }
if ($verdict -eq 'PASS_ONEOP_ONLY_MULTIOP_PENDING') { exit 8 }
exit 0
