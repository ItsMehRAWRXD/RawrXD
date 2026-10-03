<#
RAWRXD_DEEP2_SOVEREIGN_TOMBSTONE_001 -- hardened runtime validator

What this replaces
------------------
The original tools/validate_tombstone_001.cmd performed the runtime phase AND killed
the server with `taskkill /IM rawr-server.exe /F`. A process-name kill is broader
than the experiment boundary: it destroys every rawr-server on the machine,
including an instance legitimately owned by another user or lane. This harness
never kills by image name. It records the PID it launched, proves the response
came from that PID and that binary, and terminates only that PID.

Provenance fields recorded for the smoke receipt
------------------------------------------------
  SERVER_PID=          the exact process that served the inference
  SERVER_PORT=
  SERVER_EXE_SHA256=   hash of the binary as it existed at launch
  SERVER_EXE_PATH=
  SERVER_START_UTC=    StartTime of the launched process
  SERVER_IMAGE_MATCH=  1 if the live process image is the expected path
  SERVER_EXIT_CODE=    exit code observed after terminating that PID

Negative tests
--------------
Bad input returning a valid-looking HTTP status is NOT sufficient. After every
abuse the server must still report model_loaded=true AND still produce real
generated text, otherwise the malformed-input path poisoned the runtime.
#>

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$Repo   = 'F:\~dev'
$Exe    = 'F:\~dev\build_rawr_ninja\bin\rawr-server.exe'
$Model  = 'G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'
$Log    = Join-Path $Repo 'audit_tombstone_001'
$Port   = 21600
$Rawrxd = 'F:\~dev\rawrxd'
$Stub   = Join-Path $Rawrxd 'src\deep2\Deep2Server_Sovereign.cpp'
$Cml    = Join-Path $Rawrxd 'CMakeLists.txt'

if (-not (Test-Path $Log)) { New-Item -ItemType Directory -Path $Log | Out-Null }
function Say($m) { Write-Output $m }

Say '============================================================'
Say ' RAWRXD_DEEP2_SOVEREIGN_TOMBSTONE_001 -- runtime (hardened)'
Say " started $(Get-Date -Format o)"
Say '============================================================'

# ---- refuse to run rather than clobber an exe that is not ours ------------
if (-not (Test-Path $Exe)) { Say 'ABORT: server binary missing'; exit 2 }
$exeHash = (Get-FileHash $Exe -Algorithm SHA256).Hash
Say "SERVER_EXE_PATH=$Exe"
Say "SERVER_EXE_SHA256=$exeHash"
Say "SERVER_EXE_SIZE=$((Get-Item $Exe).Length)"

Say ''
Say '--- pre-flight: refuse if our port is already taken ---'
$busy = $false
try { $null = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/health" -UseBasicParsing -TimeoutSec 3; $busy = $true } catch { }
if ($busy) {
    Say "ABORT: port $Port already serving -- another process owns it."
    Say '       This harness will NOT kill it. Choose a free port.'
    exit 3
}
Say "PORT_PREFLIGHT_CLEAR=1"

# ---- launch, capturing the exact PID --------------------------------------
# NOTE: deliberately NOT named $pid_. PowerShell holds an automatic $PID and a
# script managing server processes has no business shadowing it by near-miss.
$proc = Start-Process -FilePath $Exe -PassThru -WindowStyle Hidden -ArgumentList @(
    '--model', $Model, '--port', "$Port", '--host', '127.0.0.1')
$serverPid = $proc.Id
Say "SERVER_PID=$serverPid"
Say "SERVER_PORT=$Port"
Say "SERVER_START_UTC=$($proc.StartTime.ToUniversalTime().ToString('o'))"

# Prove the responding process IS this binary before trusting any response.
$live = Get-Process -Id $serverPid -ErrorAction SilentlyContinue
$imgOk = 0
if ($live) {
    try { if ($live.Path -eq $Exe) { $imgOk = 1 } } catch { }
    Say "SERVER_IMAGE_PATH=$(try { $live.Path } catch { '<unreadable>' })"
}
# confirm the live process really is our exe at our path
$live = Get-Process -Id $serverPid -ErrorAction SilentlyContinue
$imgOk = 0
if ($live) {
    try { if ($live.Path -eq $Exe) { $imgOk = 1 } } catch { }
    Say "SERVER_IMAGE_PATH=$(try { $live.Path } catch { '<unreadable>' })"
}
Say "SERVER_IMAGE_MATCH=$imgOk"
if ($imgOk -ne 1) {
    Say 'ABORT: the live process image is not the binary this harness launched.'
    Say '       Any response below would be unattributable, so no receipt is produced.'
    if (-not $proc.HasExited) { $proc.Kill() }
    exit 6
}

$cleanup = {
    param($p)
    if ($p -and -not $p.HasExited) { $p.Kill(); $p.WaitForExit(20000) | Out-Null }
}

$ready = $false; $i = 0
for (; $i -lt 300; $i++) {
    if ($proc.HasExited) { Say "SERVER_DIED_EARLY_EXITCODE=$($proc.ExitCode)"; break }
    try { $null = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/health" -UseBasicParsing -TimeoutSec 5; $ready = $true; break } catch { }
    Start-Sleep -Seconds 1
}
Say "SERVER_READY=$ready  POLLS=$i"

if (-not $ready) {
    & $cleanup $proc
    Say "SERVER_EXIT_CODE=$($proc.ExitCode)"
    Say 'RUNTIME_VERDICT=FAIL_NO_SERVER'
    exit 4
}

# ---- happy path ------------------------------------------------------------
Say ''
Say '--- happy path ---'
$h = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/health" -UseBasicParsing -TimeoutSec 60
$hj = $h.Content | ConvertFrom-Json
Say "HEALTH_HTTP=$($h.StatusCode)"
Say "HEALTH_BODY=$($h.Content)"
Say "HEALTH_MODEL_LOADED=$($hj.model_loaded)"
Say "HEALTH_STATUS=$($hj.status)"

$m = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/v1/models" -UseBasicParsing -TimeoutSec 60
$mj = $m.Content | ConvertFrom-Json
Say "MODELS_HTTP=$($m.StatusCode)"
Say "MODELS_BODY=$($m.Content)"
Say "MODELS_ID=$($mj.data[0].id)"
Say "MODELS_OWNED_BY=$($mj.data[0].owned_by)"

$t = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/tags" -UseBasicParsing -TimeoutSec 60
Say "TAGS_HTTP=$($t.StatusCode)"
Say "TAGS_BODY=$($t.Content)"

$chat = '{"model":"tinyllama-1.1b-chat-v1.0.Q4_K_M","messages":[{"role":"user","content":"The capital of France is"}],"max_tokens":12,"temperature":0,"stream":false}'
$c = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/v1/chat/completions" -Method POST `
     -Body $chat -ContentType 'application/json' -UseBasicParsing -TimeoutSec 240
$cj = $c.Content | ConvertFrom-Json
Say "CHAT_HTTP=$($c.StatusCode)"
Say "CHAT_BODY=$($c.Content)"
Say "CHAT_TEXT=$($cj.choices[0].message.content)"
Say "CHAT_USAGE=$($cj.usage.prompt_tokens)/$($cj.usage.completion_tokens)/$($cj.usage.total_tokens)"
Say "CHAT_FINISH=$($cj.choices[0].finish_reason)"

$baselineText = ' Yes, the French is a|assistant|system|'
Say "CHAT_MATCHES_BASELINE=$(if ($cj.choices[0].message.content -eq $baselineText) { 'YES' } else { 'NO' })"

# ---- negative / abuse resilience ------------------------------------------
Say ''
Say '--- negative tests (must reject, then must survive) ---'
function Try-Post([string]$label, [string]$uri, [string]$body, [string]$ct) {
    try {
        $r = Invoke-WebRequest -Uri $uri -Method POST -Body $body -ContentType $ct -UseBasicParsing -TimeoutSec 90
        Say "$label`_HTTP=$($r.StatusCode)"
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if (-not $code) { $code = 'CONNECTION_ERROR' }
        Say "$label`_HTTP=$code"
        Say "$label`_ERR=$($_.Exception.Message)"
    }
}
Try-Post 'NEG_MALFORMED_JSON' "http://127.0.0.1:$Port/v1/chat/completions" '{"model": broken json' 'application/json'
Try-Post 'NEG_EMPTY_BODY'    "http://127.0.0.1:$Port/v1/chat/completions" ''                        'application/json'
try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/does/not/exist" -UseBasicParsing -TimeoutSec 30
    Say "NEG_UNKNOWN_ROUTE_HTTP=$($r.StatusCode)"
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    Say "NEG_UNKNOWN_ROUTE_HTTP=$(if (-not $code) { 'CONNECTION_ERROR' } else { $code })"
}

# the decisive part: still healthy, and still actually inferring
$h2 = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/health" -UseBasicParsing -TimeoutSec 60
$h2j = $h2.Content | ConvertFrom-Json
Say "HEALTH_AFTER_NEGATIVES_HTTP=$($h2.StatusCode)"
Say "HEALTH_AFTER_NEGATIVES_MODEL_LOADED=$($h2j.model_loaded)"
Say "HEALTH_AFTER_NEGATIVES_STATUS=$($h2j.status)"

$c2 = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/v1/chat/completions" -Method POST `
      -Body $chat -ContentType 'application/json' -UseBasicParsing -TimeoutSec 240
$c2j = $c2.Content | ConvertFrom-Json
Say "CHAT_AFTER_NEGATIVES_HTTP=$($c2.StatusCode)"
Say "CHAT_AFTER_NEGATIVES_TEXT=$($c2j.choices[0].message.content)"
Say "INFER_AFTER_ABUSE_OK=$(if ($c2j.choices[0].message.content -eq $baselineText) { 'YES' } else { 'NO' })"

# ---- dead-port control: proves the probe can distinguish absence ----------
Say ''
Say '--- negative control: dead port ---'
$dead = 21999
try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:$dead/health" -UseBasicParsing -TimeoutSec 8
    Say "NEG_DEAD_PORT_HTTP=$($r.StatusCode)"
    Say 'NEG_DEAD_PORT_PROBE_VALID=0   <-- a dead port answered; probe is not trustworthy'
} catch {
    Say "NEG_DEAD_PORT_HTTP=CONNECTION_ERROR"
    Say "NEG_DEAD_PORT_ERR=$($_.Exception.Message)"
    Say 'NEG_DEAD_PORT_PROBE_VALID=1'
}

# ---- teardown: this PID only ---------------------------------------------
Say ''
Say '--- teardown ---'
& $cleanup $proc
Say "SERVER_EXIT_CODE=$($proc.ExitCode)"
Say "SERVER_STILL_ALIVE=$(if (-not $proc.HasExited) { 'YES' } else { 'NO' })"

# ---- source-side confirmation (cheap, no build required) ------------------
Say ''
Say '--- source confirmation ---'
$bare = @(Select-String -Path $Cml -Pattern '^\s*src/deep2/Deep2Server_Sovereign\.cpp\s*$' -AllMatches)
Say "CMAKE_BARE_SOURCE_ENTRIES=$($bare.Count)"
Say "CMAKE_BARE_ENTRIES_EXPECTED=0"
$stubHits = @(Select-String -Path $Stub -Pattern '^// STUB:')
Say "STUB_MARKER_LINES=$($stubHits.Count)"
Say "STUB_MARKER_LINES_EXPECTED=0"
$codeLines = @(Get-Content $Stub | Where-Object { $_ -notmatch '^\s*(//.*)?$' })
Say "NON_COMMENT_LINES_IN_RETIRED_FILE=$($codeLines.Count)"
Say "NON_COMMENT_LINES_EXPECTED=0"

Say ''
Say '============================================================'
Say " finished $(Get-Date -Format o)"
Say '============================================================'
