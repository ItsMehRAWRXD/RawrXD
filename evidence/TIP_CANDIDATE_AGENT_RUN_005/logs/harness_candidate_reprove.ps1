# TIP_CANDIDATE_AGENT_RUN_005 — reprove AgentRunLoop + Swarm Path A on CANDIDATE only
# PROMOTE=0 TIP_CLIMB=HOLD ABSORB=NOT_AUTHORIZED PRODUCT_CERTIFIED=0 NO_INVENT_PASS=1
$ErrorActionPreference = "Continue"
$OutDir = "G:\~dev\rawrxd\evidence\TIP_CANDIDATE_AGENT_RUN_005"
$Logs = Join-Path $OutDir "logs\reprove"
New-Item -ItemType Directory -Force -Path $Logs | Out-Null
$CandExe = Join-Path $OutDir "bin\RawrXD-Win32IDE.exe"
$ExpectCand = (Get-Content (Join-Path $OutDir "FROZEN_CANDIDATE_SHA.txt") -Raw).Trim()
$TipExpect = "748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145"
$B421 = "B4212E46598F6490241A531C88C8D9A8DA37532B8C940A2C38BB35226C5D869F"
$Port = 18995
$Model = "G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"
$RunLog = Join-Path $Logs "RUNLOG.txt"
Set-Content $RunLog ""

function WLog([string]$m) {
  $line = "[{0}] {1}" -f (Get-Date -Format "o"), $m
  Add-Content $RunLog $line
  Write-Output $line
}

$sha = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
$sha | Set-Content (Join-Path $Logs "exe_sha.txt")
WLog "CANDIDATE_SHA=$sha EXPECT=$ExpectCand MATCH=$([int]($sha -eq $ExpectCand))"
if ($sha -ne $ExpectCand) { throw "CANDIDATE_SHA_DRIFT" }
if ($sha -eq $TipExpect -or $sha -eq $B421) { throw "FAIL_CLOSED SHA_IS_TIP_OR_B421" }

Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | ForEach-Object {
  WLog "KILL_PRIOR pid=$($_.Id)"; Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep 2

Remove-Item Env:RAWRXD_HOSTED_API_KEY, Env:RAWRXD_HOSTED_API_SCOPES, Env:RAWRXD_IDE_EXEC_GRANT, Env:RAWRXD_GUI -ErrorAction SilentlyContinue
$key = "cand005-" + [guid]::NewGuid().ToString("N").Substring(0, 12)
$env:RAWRXD_HOSTED_API_KEY = $key
$env:RAWRXD_HOSTED_API_SCOPES = "read,inference,models,github,admin,*"
$env:RAWRXD_HEADLESS = "1"
$env:LOCAL_ONLY = "1"
$env:RAWRXD_WEIGHT_BUDGET_MIB = "E8B0M"
$env:RAWRXD_MODELS = "G:\~dev\rawrxd\models"

$stdout = Join-Path $Logs "srv_out.txt"
$stderr = Join-Path $Logs "srv_err.txt"
$p = Start-Process -FilePath $CandExe -WorkingDirectory (Split-Path $CandExe) `
  -ArgumentList @("--headless","--local","--port","$Port","--bind","127.0.0.1","--dir","G:\~dev\rawrxd") `
  -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
  -PassThru -WindowStyle Hidden

$ready = $false
$deadline = (Get-Date).AddSeconds(120)
while ((Get-Date) -lt $deadline) {
  if ($p.HasExited) { break }
  if (netstat -ano | Select-String ":$Port\s+.*LISTENING") { $ready = $true; break }
  Start-Sleep -Milliseconds 400
}
WLog "PID=$($p.Id) PORT_READY=$ready EXITED=$($p.HasExited)"
"PID=$($p.Id) READY=$ready EXITED=$($p.HasExited) SHA=$sha PORT=$Port" | Set-Content (Join-Path $Logs "srv_meta.txt")
if (-not $ready) { throw "NOT_READY" }

$authOrigin = "http://127.0.0.1:$Port"
$loadReq = Join-Path $Logs "req_model_load.json"
(@{ modelPath = $Model } | ConvertTo-Json -Compress) | Set-Content $loadReq -NoNewline
$cLoad = & curl.exe -sS -o (Join-Path $Logs "load.body.txt") -w "%{http_code}" `
  -X POST "http://127.0.0.1:$Port/api/model/load" `
  -H "Content-Type: application/json" -H "Origin: $authOrigin" -H "X-Api-Key: $key" `
  --data-binary "@$loadReq" --max-time 300
WLog "LOAD_HTTP=$cLoad"
"LOAD_HTTP=$cLoad" | Set-Content (Join-Path $Logs "load.meta.txt")

# Wait RUNTIME_READY=1 in stderr (fail-closed if never seen)
$runtimeReady = $false
$readyDeadline = (Get-Date).AddSeconds(180)
while ((Get-Date) -lt $readyDeadline) {
  if ($p.HasExited) { break }
  if (Test-Path $stderr) {
    $errTxt = Get-Content $stderr -Raw -ErrorAction SilentlyContinue
    if ($errTxt -match "RUNTIME_READY\s*=\s*1" -or $errTxt -match "initialized successfully" -or $errTxt -match "model_loaded") {
      if ($errTxt -match "RUNTIME_READY\s*=\s*1") { $runtimeReady = $true; break }
    }
  }
  # also probe a light status endpoint if present
  try {
    $st = & curl.exe -sS -o (Join-Path $Logs "status_probe.body.txt") -w "%{http_code}" `
      "http://127.0.0.1:$Port/api/status" -H "Origin: $authOrigin" -H "X-Api-Key: $key" --max-time 5
    $body = Get-Content (Join-Path $Logs "status_probe.body.txt") -Raw -ErrorAction SilentlyContinue
    if ($body -match "RUNTIME_READY.?1|runtime_ready.?true|model_loaded.?true|ready.?true") {
      if ($body -match "RUNTIME_READY" -or $st -eq "200") {
        # only mark ready on explicit RUNTIME_READY=1 elsewhere; keep polling stderr
      }
    }
  } catch {}
  Start-Sleep -Seconds 2
}
# Soft fallback: if stderr has initialized successfully after successful load, note it
$errAll = ""
if (Test-Path $stderr) { $errAll = Get-Content $stderr -Raw -ErrorAction SilentlyContinue }
$hasInit = [bool]($errAll -match "initialized successfully")
$hasReadyFlag = [bool]($errAll -match "RUNTIME_READY\s*=\s*1")
WLog "RUNTIME_READY_FLAG=$hasReadyFlag INIT_SUCCESS_MSG=$hasInit"
@"
RUNTIME_READY_FLAG=$([int]$hasReadyFlag)
INIT_SUCCESS_MSG=$([int]$hasInit)
LOAD_HTTP=$cLoad
"@ | Set-Content (Join-Path $Logs "runtime_ready_probe.txt")

# Agent run — max_tokens<=64 per FOLLOWUP
$req = Join-Path $Logs "req_agent_run.json"
'{"prompt":"hi","cancel":false,"max_tokens":16,"max_iter":1}' | Set-Content $req -NoNewline
$cRun = & curl.exe -sS -D (Join-Path $Logs "agent_run.hdr.txt") -o (Join-Path $Logs "agent_run.body.txt") -w "%{http_code}" `
  -X POST "http://127.0.0.1:$Port/api/agent/run" `
  -H "Content-Type: application/json" -H "Origin: $authOrigin" -H "X-Api-Key: $key" `
  --data-binary "@$req" --max-time 180
$alive = [bool](Get-Process -Id $p.Id -ErrorAction SilentlyContinue)
$runBody = Get-Content (Join-Path $Logs "agent_run.body.txt") -Raw -ErrorAction SilentlyContinue
WLog "AGENT_RUN_HTTP=$cRun ALIVE=$alive BODY_LEN=$($runBody.Length)"
"RUN_HTTP=$cRun ALIVE=$alive EXITED=$($p.HasExited)" | Set-Content (Join-Path $Logs "agent_run.meta.txt")

$entered = 0
if ($cRun -match '^2' -and $runBody -and $runBody -notmatch 'model_not_loaded' -and $runBody -notmatch 'runtime_warming') {
  $entered = 1
}
$agentDisp = "FAIL_CLOSED"
if ($entered -eq 1) { $agentDisp = "ENTERED_HTTP_OK" }
elseif ($cRun -eq "503") { $agentDisp = "FAIL_CLOSED_HTTP_503" }
elseif (-not $alive) { $agentDisp = "FAIL_CLOSED_PROCESS_DEATH" }
elseif ($cRun -eq "000" -or $cRun -eq "") { $agentDisp = "NOT_RUN_OR_CURL_FAIL" }
else { $agentDisp = "FAIL_CLOSED_HTTP_$cRun" }

# Swarm Path A
$orchReq = Join-Path $Logs "req_swarm_orch.json"
(@{ n = 2; input = "int main(){ return 0; }`n"; cleanup = $true } | ConvertTo-Json -Compress) | Set-Content $orchReq -NoNewline
$cOrch = & curl.exe -sS -D (Join-Path $Logs "swarm_orch.hdr.txt") -o (Join-Path $Logs "swarm_orch.body.txt") -w "%{http_code}" `
  -X POST "http://127.0.0.1:$Port/api/swarm/orch" `
  -H "Content-Type: application/json" -H "Origin: $authOrigin" -H "X-Api-Key: $key" `
  --data-binary "@$orchReq" --max-time 300
$orchBody = Get-Content (Join-Path $Logs "swarm_orch.body.txt") -Raw -ErrorAction SilentlyContinue
WLog "SWARM_ORCH_HTTP=$cOrch BODY_LEN=$($orchBody.Length)"
"ORCH_HTTP=$cOrch" | Set-Content (Join-Path $Logs "swarm_orch.meta.txt")

$noEngine = [bool]($orchBody -match "No Inference Engine")
$swarmDisp = "FAIL_CLOSED"
if ($noEngine) { $swarmDisp = "FAIL_CLOSED_NO_INFERENCE_ENGINE" }
elseif ($cOrch -match '^2') { $swarmDisp = "HTTP_OK_NO_ENGINE_STRING" }
elseif ($cOrch -eq "503") { $swarmDisp = "FAIL_CLOSED_HTTP_503" }
else { $swarmDisp = "FAIL_CLOSED_HTTP_$cOrch" }

# Path B GUI — not launched this harness (headless only)
$pathBDisp = "RUNTIME_REACHED=NOT_RUN"
$pathBReason = "GUI_PATH_NOT_LAUNCHED_THIS_HARNESS; headless-only prove; PathB 4111 CmdDiag requires GUI WM_COMMAND"

if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep 1

$utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
@"
TIP_CANDIDATE_AGENT_RUN_005 / REPROVE_SEAL
=========================================
ASOF_UTC=$utc
CANDIDATE_SHA=$sha
PROMOTE=0
TIP_CLIMB=HOLD
ABSORB=NOT_AUTHORIZED
PRODUCT_CERTIFIED=0
NO_INVENT_PASS=1
TIP_748B_UNTOUCHED=1

AGENT_RUN_LOOP
--------------
DISPOSITION=$agentDisp
HTTP=$cRun
ENTERED=$entered
ALIVE_AFTER=$([int]$alive)
RUNTIME_READY_FLAG=$([int]$hasReadyFlag)
INIT_SUCCESS_MSG=$([int]$hasInit)
LOAD_HTTP=$cLoad
BODY_FILE=logs/reprove/agent_run.body.txt
NOT_RUN_NE_PASS=1

SWARM_PATH_A
------------
DISPOSITION=$swarmDisp
HTTP=$cOrch
NO_INFERENCE_ENGINE=$([int]$noEngine)
BODY_FILE=logs/reprove/swarm_orch.body.txt

PATH_B_4111
-----------
DISPOSITION=$pathBDisp
REASON=$pathBReason
RUNTIME_PASS=0

LAW
---
SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS
"@ | Set-Content (Join-Path $OutDir "REPROVE_SEAL.txt") -Encoding UTF8

WLog "DONE AGENT=$agentDisp SWARM=$swarmDisp PATHB=$pathBDisp"
Write-Output "AGENT=$agentDisp SWARM=$swarmDisp PATHB=$pathBDisp"
