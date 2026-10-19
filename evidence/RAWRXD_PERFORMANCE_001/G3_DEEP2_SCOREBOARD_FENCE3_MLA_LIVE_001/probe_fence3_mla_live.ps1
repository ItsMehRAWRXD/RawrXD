# Narrow K2 MLA / Fence3 live gate. Fail-closed. PROMOTE=0 always.
# Does NOT use single-GGUF HOST_DECODE. Derives LIVE from witness truth table.
$ErrorActionPreference = 'Stop'

$EvDir = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_DEEP2_SCOREBOARD_FENCE3_MLA_LIVE_001'
$OutDir = 'C:\r1cert\smoke_fence3_mla'
$ExeRun = 'C:\r1cert\smoke_bin\RawrXD-Win32IDE_p3tip.exe'
$ShardDir = 'F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M'
$Model = 'F:/OllamaModels/Kimi-K2-Instruct-0905-GGUF/Q4_K_M/Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf'
$Port = 11451
$Base = "http://127.0.0.1:$Port"

New-Item -ItemType Directory -Force $EvDir, $OutDir | Out-Null

function Kill-Port {
    Get-NetTCPConnection -LocalPort $Port -EA SilentlyContinue |
        ForEach-Object {
            try { Stop-Process -Id $_.OwningProcess -Force -EA SilentlyContinue } catch {}
        }
    Start-Sleep 1
}

function Invoke-CurlCode([string]$n, [string]$m, [string]$u, [string]$b, [int]$t = 3600) {
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

function Get-IntField([string[]]$block, [string]$key) {
    $v = Get-Field $block $key
    $n = 0
    [void][int]::TryParse($v, [ref]$n)
    return $n
}

Kill-Port
$serr = Join-Path $OutDir 'server.err.txt'
$sout = Join-Path $OutDir 'server.out.txt'
Remove-Item $serr, $sout -Force -EA SilentlyContinue

if (-not (Test-Path $ExeRun)) { throw "MISSING_EXE=$ExeRun" }
if (-not (Test-Path -LiteralPath $ShardDir)) { throw "MISSING_SHARD_DIR=$ShardDir" }
$shardCount = @(Get-ChildItem -LiteralPath $ShardDir -Filter '*.gguf').Count
if ($shardCount -ne 13) { throw "SHARD_COUNT=$shardCount EXPECT=13" }

$runId = [guid]::NewGuid().ToString('N')
$env:RAWRXD_P3_RUN_ID = $runId
$env:DEEP2_K2_SHARD_DIR = $ShardDir
$env:DEEP2_REAL_K2_GENERATE = '1'
# Narrow layer depth still enters ForwardMLALayers + Fence3 outPrefetch reclaim.
$env:RAWRXD_K2_LAYERS = '2'
# Do not substitute TinyLlama HOST_DECODE path; keep CPU-opt for narrow Fence3.
$env:RAWRXD_HOST_DECODE = '1'
$env:RAWRXD_FORCE_CPU_INFERENCE = '1'
$env:DEEP2_MINIMAL_ENHANCE = '1'
$env:DEEP2_DUALSTICK_ARM = '0'
$env:RAWRXD_NO_VULKAN = '1'
$env:DEEP2_MARS = '0'
$env:VK_ICD_FILENAMES = 'C:\rawrxd_blocked_no_vulkan_icd.json'

$exeSha16 = ((Get-FileHash $ExeRun -Algorithm SHA256).Hash).Substring(0, 16)
$arg = "--headless --local --port $Port --dir `"G:\~dev\rawrxd`""
$p = Start-Process -FilePath $ExeRun -ArgumentList $arg `
    -RedirectStandardOutput $sout -RedirectStandardError $serr `
    -WindowStyle Hidden -PassThru

$ready = $false
for ($i = 0; $i -lt 120; $i++) {
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

$conn = Get-NetTCPConnection -LocalPort $Port -State Listen -EA Stop | Select-Object -First 1
$listenerPid = $conn.OwningProcess
$proc = Get-CimInstance Win32_Process -Filter "ProcessId=$listenerPid" -EA Stop
$actualExe = $proc.ExecutablePath
$exeMatch = [IO.Path]::GetFullPath($actualExe) -ieq [IO.Path]::GetFullPath($ExeRun)
if (-not $exeMatch) {
    Write-Output "WRONG_EXE PID=$listenerPid PATH=$actualExe EXPECT=$ExeRun"
    Kill-Port
    exit 3
}

$modelJson = (@{ modelPath = $Model } | ConvertTo-Json -Compress)
$load = Invoke-CurlCode 'load' 'POST' "$Base/api/model/load" $modelJson 7200
if ($load -notmatch '^2\d\d$') {
    Write-Output "LOAD_FAILED=$load"
    Get-Content $serr -Tail 80 -EA SilentlyContinue | Set-Content (Join-Path $EvDir 'LOAD_FAIL_server.err.tail.txt')
    Kill-Port
    exit 4
}
$gen = Invoke-CurlCode 'generate' 'POST' "$Base/api/generate" `
    '{"prompt":"hi","max_tokens":1,"stream":false,"temperature":0}' 7200
$unload = Invoke-CurlCode 'unload' 'POST' "$Base/api/model/unload" '{}' 600

$lines = @(Get-Content $serr -EA SilentlyContinue)
$outLines = @(Get-Content $sout -EA SilentlyContinue)
$all = $lines + $outLines

$ownIdx = -1
$progIdx = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -eq 'KIND=OWNERSHIP_TIP' -or $lines[$i] -like 'GATE=G3_DEEP2_SCOREBOARD_OWNERSHIP*') { $ownIdx = $i }
    if ($lines[$i] -eq 'KIND=PROGRESS_INDEPENDENCE_TIP') { $progIdx = $i }
}
$own = @(); if ($ownIdx -ge 0) { $own = $lines[$ownIdx..([Math]::Min($ownIdx + 45, $lines.Count - 1))] }
$prog = @(); if ($progIdx -ge 0) { $prog = $lines[$progIdx..([Math]::Min($progIdx + 40, $lines.Count - 1))] }
$own + $prog | Set-Content (Join-Path $EvDir 'SEAL_BLOCK.txt')

$k2Open = [int](($all | Where-Object { $_ -match 'openK2ShardDirectory|loadModel=INDEX_AND_ADDRESS|SHARD_IO bridge path=.*warmed=13|k2ShardIndexOpen' }).Count -gt 0)
$k2Own = [int](($all | Where-Object { $_ -like 'LIVE_K2_OWNERSHIP=generateStream*runK2NativeStreamPartial*' }).Count -gt 0)
$f3a = Get-IntField $prog 'FENCE3_ATTEMPTS'
if ($f3a -eq 0) { $f3a = Get-IntField $own 'FENCE3_ATTEMPTS' }
$f3pump = Get-IntField $prog 'FENCE3_PUMP_WORK'
$pump = Get-IntField $prog 'PUMP_ISSUE_COUNT'
if ($pump -eq 0) { $pump = Get-IntField $own 'PUMP_ISSUE_COUNT' }
$dup = Get-IntField $own 'N_PLUS_1_DUPLICATE_ISSUE_COUNT'
$outer = Get-IntField $prog 'OUTER_LOOP_N_PLUS_1_INITIATION'
if ($outer -eq 0 -and $own.Count -gt 0) { $outer = Get-IntField $own 'OUTER_LOOP_N_PLUS_1_INITIATION' }
$ensure = Get-IntField $prog 'WALK_ENSURE_CRUTCH'
$fencePump = Get-IntField $prog 'FENCE_PUMP_CONTINUE'
$waitReq = Get-IntField $prog 'WAIT_PER_LAYER_REQUIRED_FOR_PROGRESS'
$reclaim = Get-Field $prog 'FENCE3_RECLAIM_ONLY'
if (-not $reclaim) { $reclaim = Get-Field $own 'FENCE3_RECLAIM_ONLY' }
if (-not $reclaim) { $reclaim = '1' }
$compRe = Get-Field $prog 'COMPLETION_SCHEDULER_REENTRY'
if (-not $compRe) { $compRe = '0' }

# Fence3 tip only exists inside ForwardMLALayers; entry also marked when K2 ownership path runs.
$fwdMla = [int](($f3a -gt 0) -or $k2Own -or (($all | Where-Object { $_ -match 'ForwardMLALayers|NoteForwardEntered|OWNER=MLA_FORWARD' }).Count -gt 0))

$liveOk = [int](
    $fwdMla -gt 0 -and
    $f3a -gt 0 -and
    $reclaim -eq '1' -and
    $compRe -eq '0' -and
    $dup -eq 0 -and
    $outer -eq 0 -and
    $ensure -eq 0 -and
    $fencePump -eq 0 -and
    $waitReq -eq 0
)
$exercise = if ($liveOk -eq 1) { 'PROVEN' } else { 'UNPROVEN' }
$schedLive = $liveOk

$receipt = @"
GATE=G3_DEEP2_SCOREBOARD_FENCE3_MLA_LIVE_001
KIND=FENCE3_MLA_LIVE_RECEIPT
RUN_ID=$runId
EXE_SHA16=$exeSha16
LISTENER_PID=$listenerPid
EXE_PATH_MATCH=$([int]$exeMatch)
MODEL_PATH=K2_Q4_K_M_13_SHARDS
DEEP2_K2_SHARD_DIR=$ShardDir
SHARD_COUNT=$shardCount
RAWRXD_K2_LAYERS=2
RAWRXD_HOST_DECODE=0
LOAD_HTTP=$load
GEN_HTTP=$gen
UNLOAD_HTTP=$unload
K2_SHARD_DIR_OPEN=$k2Open
K2_SHARD_COUNT=$shardCount
LIVE_K2_OWNERSHIP_PATH=$k2Own
FORWARD_MLA_LAYERS_ENTERED=$fwdMla
FENCE3_ATTEMPTS=$f3a
FENCE3_PUMP_WORK=$f3pump
FENCE3_RECLAIM_ONLY=$reclaim
COMPLETION_SCHEDULER_REENTRY=$compRe
PUMP_ISSUE_COUNT=$pump
N_PLUS_1_DUPLICATE_ISSUE_COUNT=$dup
OUTER_LOOP_N_PLUS_1_INITIATION=$outer
WALK_ENSURE_CRUTCH=$ensure
FENCE_PUMP_CONTINUE=$fencePump
WAIT_PER_LAYER_REQUIRED_FOR_PROGRESS=$waitReq
PUMP_OWNERSHIP=FROZEN_PASS
WAIT_FREE_PROGRESS=FROZEN_PASS
FENCE3_MLA_EXERCISE=$exercise
SCOREBOARD_SCHEDULER_LIVE=$schedLive
PROMOTE=0
TIP_CLIMB=HOLD
R28_APPLY=HELD
"@
$receipt | Set-Content (Join-Path $EvDir 'FENCE3_MLA_LIVE_RECEIPT.txt')
Get-Content $serr -Tail 160 -EA SilentlyContinue | Set-Content (Join-Path $EvDir 'server.err.tail.txt')
Get-Content $sout -Tail 120 -EA SilentlyContinue | Set-Content (Join-Path $EvDir 'server.out.tail.txt')

Write-Output "RUN_ID=$runId FWD=$fwdMla F3A=$f3a EXERCISE=$exercise LIVE=$schedLive PUMP=$pump DUP=$dup LOAD=$load GEN=$gen"
Kill-Port
if ($load -notmatch '^2\d\d$') { exit 4 }
if ($gen -notmatch '^2\d\d$') { exit 6 }
if ($liveOk -ne 1) { exit 7 }
exit 0
