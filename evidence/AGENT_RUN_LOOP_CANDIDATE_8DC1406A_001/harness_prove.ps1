# AGENT_RUN_LOOP_CANDIDATE_8DC1406A_001 — prove AgentRunLoop + Swarm Path A + PathB on FROZEN candidate only
# PROMOTE=0 TIP_CLIMB=HOLD ABSORB=NOT_AUTHORIZED PRODUCT_CERTIFIED=0 NO_INVENT_PASS=1
$ErrorActionPreference = "Continue"
$Seal = "G:\~dev\rawrxd\evidence\AGENT_RUN_LOOP_CANDIDATE_8DC1406A_001"
$CandRoot = "G:\~dev\rawrxd\evidence\TIP_CANDIDATE_AGENT_RUN_005"
$Logs = Join-Path $Seal "logs"
New-Item -ItemType Directory -Force -Path $Logs | Out-Null
$CandExe = Join-Path $CandRoot "bin\RawrXD-Win32IDE.exe"
$TipExe = "G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe"
$ExpectCand = "8DC1406A0118AC6A2F6A1E991378A2730AAC07D5593BA3C9BF5E8852E468235B"
$TipExpect = "748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145"
$B421 = "B4212E46598F6490241A531C88C8D9A8DA37532B8C940A2C38BB35226C5D869F"
$Port = 18997
$Model = "G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"
$RunLog = Join-Path $Logs "RUNLOG.txt"
Set-Content $RunLog ""

function WLog([string]$m) {
  $line = "[{0}] {1}" -f (Get-Date -Format "o"), $m
  Add-Content $RunLog $line
  Write-Output $line
}

$sha = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
$tipSha = (Get-FileHash -LiteralPath $TipExe -Algorithm SHA256).Hash
@"
CANDIDATE_SHA=$sha
CANDIDATE_MATCH=$([int]($sha -eq $ExpectCand))
TIP_SHA=$tipSha
TIP_MATCH=$([int]($tipSha -eq $TipExpect))
CANDIDATE_NE_TIP=$([int]($sha -ne $tipSha))
CANDIDATE_NE_B421=$([int]($sha -ne $B421))
"@ | Set-Content (Join-Path $Logs "hash_verify.txt")
WLog "CANDIDATE_SHA=$sha MATCH=$([int]($sha -eq $ExpectCand)) TIP=$tipSha TIP_MATCH=$([int]($tipSha -eq $TipExpect))"
if ($sha -ne $ExpectCand) { throw "CANDIDATE_SHA_DRIFT" }
if ($tipSha -ne $TipExpect) { throw "TIP_SHA_DRIFT_DO_NOT_PROCEED" }
if ($sha -eq $TipExpect -or $sha -eq $B421) { throw "FAIL_CLOSED SHA_IS_TIP_OR_B421" }

Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | ForEach-Object {
  WLog "KILL_PRIOR pid=$($_.Id)"; Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep 2

Remove-Item Env:RAWRXD_HOSTED_API_KEY, Env:RAWRXD_HOSTED_API_SCOPES, Env:RAWRXD_IDE_EXEC_GRANT, Env:RAWRXD_GUI -ErrorAction SilentlyContinue
$key = "cand8dc-" + [guid]::NewGuid().ToString("N").Substring(0, 12)
$env:RAWRXD_HOSTED_API_KEY = $key
$env:RAWRXD_HOSTED_API_SCOPES = "read,inference,models,github,admin,*"
$env:RAWRXD_HEADLESS = "1"
$env:LOCAL_ONLY = "1"
$env:RAWRXD_WEIGHT_BUDGET_MIB = "E8B0M"
$env:RAWRXD_MODELS = "G:\~dev\rawrxd\models"
$key | Set-Content (Join-Path $Logs "api_key.txt")

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
if (-not $ready) {
  if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
  throw "NOT_READY"
}

$authOrigin = "http://127.0.0.1:$Port"
$loadReq = Join-Path $Logs "req_model_load.json"
(@{ modelPath = $Model } | ConvertTo-Json -Compress) | Set-Content $loadReq -NoNewline
$cLoad = & curl.exe -sS -o (Join-Path $Logs "load.body.txt") -w "%{http_code}" `
  -X POST "http://127.0.0.1:$Port/api/model/load" `
  -H "Content-Type: application/json" -H "Origin: $authOrigin" -H "X-Api-Key: $key" `
  --data-binary "@$loadReq" --max-time 300
WLog "LOAD_HTTP=$cLoad"
"LOAD_HTTP=$cLoad" | Set-Content (Join-Path $Logs "load.meta.txt")

# Wait STRICT RUNTIME_READY=1 (not HEADLESS_READY alone)
$runtimeReady = $false
$readyDeadline = (Get-Date).AddSeconds(240)
while ((Get-Date) -lt $readyDeadline) {
  if ($p.HasExited) { break }
  if (Test-Path $stderr) {
    $errTxt = Get-Content $stderr -Raw -ErrorAction SilentlyContinue
    if ($errTxt -match "RUNTIME_READY\s*=\s*1") { $runtimeReady = $true; break }
  }
  Start-Sleep -Seconds 1
}
$errAll = ""
if (Test-Path $stderr) { $errAll = Get-Content $stderr -Raw -ErrorAction SilentlyContinue }
$hasReadyFlag = [bool]($errAll -match "RUNTIME_READY\s*=\s*1")
$hasHeadless = [bool]($errAll -match "HEADLESS_READY")
WLog "RUNTIME_READY=$([int]$hasReadyFlag) HEADLESS_READY_SEEN=$([int]$hasHeadless)"
@"
RUNTIME_READY=$([int]$hasReadyFlag)
HEADLESS_READY_SEEN=$([int]$hasHeadless)
LOAD_HTTP=$cLoad
WAIT_LOOP_HIT=$([int]$runtimeReady)
"@ | Set-Content (Join-Path $Logs "runtime_ready_probe.txt")

# Agent run — max_tokens<=64
$req = Join-Path $Logs "req_agent_run.json"
'{"prompt":"hi","cancel":false,"max_tokens":16,"max_iter":1}' | Set-Content $req -NoNewline
$cRun = & curl.exe -sS -D (Join-Path $Logs "agent_run.hdr.txt") -o (Join-Path $Logs "agent_run.body.txt") -w "%{http_code}" `
  -X POST "http://127.0.0.1:$Port/api/agent/run" `
  -H "Content-Type: application/json" -H "Origin: $authOrigin" -H "X-Api-Key: $key" `
  --data-binary "@$req" --max-time 180
$alive = [bool](Get-Process -Id $p.Id -ErrorAction SilentlyContinue)
$runBody = ""
if (Test-Path (Join-Path $Logs "agent_run.body.txt")) {
  $runBody = Get-Content (Join-Path $Logs "agent_run.body.txt") -Raw -ErrorAction SilentlyContinue
}
WLog "AGENT_RUN_HTTP=$cRun ALIVE=$alive BODY_LEN=$($runBody.Length)"
"RUN_HTTP=$cRun ALIVE=$alive EXITED=$($p.HasExited)" | Set-Content (Join-Path $Logs "agent_run.meta.txt")

$entered = 0
if ($hasReadyFlag -and ($cRun -match '^2') -and $runBody -and ($runBody -notmatch 'model_not_loaded') -and ($runBody -notmatch 'runtime_warming')) {
  $entered = 1
}
$agentDisp = "FAIL_CLOSED"
if (-not $hasReadyFlag) { $agentDisp = "FAIL_CLOSED_RUNTIME_READY_MISSING" }
elseif ($entered -eq 1) { $agentDisp = "ENTERED_HTTP_OK" }
elseif ($cRun -eq "503") { $agentDisp = "FAIL_CLOSED_HTTP_503" }
elseif (-not $alive) { $agentDisp = "FAIL_CLOSED_PROCESS_DEATH" }
elseif ($cRun -eq "000" -or $cRun -eq "") { $agentDisp = "NOT_RUN_OR_CURL_FAIL" }
else { $agentDisp = "FAIL_CLOSED_HTTP_$cRun" }

# Swarm Path A — allow longer; capture curl errno
$orchReq = Join-Path $Logs "req_swarm_orch.json"
(@{ n = 2; input = "int main(){ return 0; }`n"; cleanup = $true } | ConvertTo-Json -Compress) | Set-Content $orchReq -NoNewline
$cOrch = & curl.exe -sS -D (Join-Path $Logs "swarm_orch.hdr.txt") -o (Join-Path $Logs "swarm_orch.body.txt") -w "%{http_code}" `
  -X POST "http://127.0.0.1:$Port/api/swarm/orch" `
  -H "Content-Type: application/json" -H "Origin: $authOrigin" -H "X-Api-Key: $key" `
  --data-binary "@$orchReq" --max-time 420 2> (Join-Path $Logs "swarm_orch.curl_err.txt")
$aliveAfterSwarm = [bool](Get-Process -Id $p.Id -ErrorAction SilentlyContinue)
$orchBody = ""
if (Test-Path (Join-Path $Logs "swarm_orch.body.txt")) {
  $orchBody = Get-Content (Join-Path $Logs "swarm_orch.body.txt") -Raw -ErrorAction SilentlyContinue
}
WLog "SWARM_ORCH_HTTP=$cOrch ALIVE=$aliveAfterSwarm BODY_LEN=$($orchBody.Length)"
"ORCH_HTTP=$cOrch ALIVE=$([int]$aliveAfterSwarm)" | Set-Content (Join-Path $Logs "swarm_orch.meta.txt")

$noEngine = [bool]($orchBody -match "No Inference Engine")
$noModel = [bool]($orchBody -match "No model loaded")
$swarmDisp = "FAIL_CLOSED"
if ($noEngine) { $swarmDisp = "FAIL_CLOSED_NO_INFERENCE_ENGINE" }
elseif ($cOrch -match '^2' -and -not $noEngine) { $swarmDisp = "HTTP_OK_PATH_A_NO_ENGINE_STRING" }
elseif ($cOrch -eq "503") { $swarmDisp = "FAIL_CLOSED_HTTP_503" }
elseif ($cOrch -eq "000" -or $cOrch -eq "") { $swarmDisp = "FAIL_CLOSED_HTTP_000" }
else { $swarmDisp = "FAIL_CLOSED_HTTP_$cOrch" }

# Path B GUI — headless prove only
$pathBDisp = "RUNTIME_REACHED=NOT_RUN"
$pathBReason = "GUI_UNAVAILABLE_HEADLESS_PROVE; PathB 4111 CmdDiag requires GUI WM_COMMAND"

if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep 1

# Re-verify tip untouched after run
$tipShaAfter = (Get-FileHash -LiteralPath $TipExe -Algorithm SHA256).Hash
$tipOk = [int]($tipShaAfter -eq $TipExpect)

$utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$sealTxt = @"
AGENT_RUN_LOOP_CANDIDATE_8DC1406A_001 / SEAL
============================================
ASOF_UTC=$utc
CANDIDATE_SHA=$sha
CANDIDATE_MATCH=1
TIP_SHA=$tipShaAfter
TIP_MATCH=$tipOk
TIP_748B_UNTOUCHED=$tipOk
PROMOTE=0
TIP_CLIMB=HOLD
ABSORB=NOT_AUTHORIZED
PRODUCT_CERTIFIED=0
NO_INVENT_PASS=1
PORT=$Port

AGENT_RUN_LOOP
--------------
DISPOSITION=$agentDisp
HTTP=$cRun
ENTERED=$entered
ALIVE_AFTER=$([int]$alive)
RUNTIME_READY=$([int]$hasReadyFlag)
LOAD_HTTP=$cLoad
BODY_FILE=logs/agent_run.body.txt
NOT_RUN_NE_PASS=1

SWARM_PATH_A
------------
DISPOSITION=$swarmDisp
HTTP=$cOrch
NO_INFERENCE_ENGINE=$([int]$noEngine)
NO_MODEL_LOADED_STRING=$([int]$noModel)
BODY_FILE=logs/swarm_orch.body.txt
ALIVE_AFTER=$([int]$aliveAfterSwarm)

PATH_B_4111
-----------
DISPOSITION=$pathBDisp
REASON=$pathBReason
RUNTIME_PASS=0

LAW
---
SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS
CANDIDATE_NE_PRODUCT_TIP=1
"@
$sealTxt | Set-Content (Join-Path $Seal "SEAL.txt") -Encoding UTF8
$sealTxt | Set-Content (Join-Path $CandRoot "prove\SEAL.txt") -Encoding UTF8 -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path (Join-Path $CandRoot "prove") | Out-Null
$sealTxt | Set-Content (Join-Path $CandRoot "prove\SEAL.txt") -Encoding UTF8

WLog "DONE AGENT=$agentDisp SWARM=$swarmDisp PATHB=$pathBDisp ENTERED=$entered"
Write-Output "AGENT=$agentDisp SWARM=$swarmDisp PATHB=$pathBDisp ENTERED=$entered"
