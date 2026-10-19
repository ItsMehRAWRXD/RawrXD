# R24_PRODUCTOPEN_TENSORS_GT0_001 — narrow ProductOpen gate (no rollup substitute)
# Usage (copy to %TEMP% if G:\~dev breaks -File):
#   powershell -NoProfile -ExecutionPolicy Bypass -File run_productopen_tensors.ps1 -Family phi3
param(
  [ValidateSet('tinyllama','phi3','gemma3','llama32','deepseek8b','codestral')]
  [string]$Family = 'phi3',
  [int]$Port = 28921
)
$ErrorActionPreference = 'Continue'
$gate = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\R24_PRODUCTOPEN_TENSORS_GT0_001'
New-Item -ItemType Directory -Force -Path $gate | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding $false
$smoke = Join-Path $env:TEMP 'R24_PRODUCTOPEN_TENSORS_GT0'
New-Item -ItemType Directory -Force -Path $smoke | Out-Null
$exeSrc = Join-Path $env:TEMP 'G3_IDE_R24_10MODEL\RawrXD-Win32IDE.exe'
$exe = Join-Path $smoke 'RawrXD-Win32IDE.exe'
if (-not (Test-Path $exeSrc)) { throw "Missing frozen EXE: $exeSrc" }
Copy-Item $exeSrc $exe -Force
$sha = (Get-FileHash $exe -Algorithm SHA256).Hash

$paths = @{
  tinyllama = 'G:/~dev/rawrxd/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'
  phi3      = 'G:/~dev/rawrxd/models/phi3-mini-Q2_K.gguf'
  gemma3    = 'G:/~dev/rawrxd/models/gemma3-1b-Q2_K.gguf'
  llama32   = 'G:/~dev/rawrxd/models/llama3.2-3b-Q2_K.gguf'
  deepseek8b= 'F:/OllamaModels/DeepSeek-R1-0528-Qwen3-8B-GGUF/DeepSeek-R1-0528-Qwen3-8B-Q4_K_M.gguf'
  codestral = 'F:/OllamaModels/rawrxd_test_models/Codestral-22B-v0.1-Q4_K_M.gguf'
}
$modelPath = $paths[$Family]
if (-not (Test-Path $modelPath)) { throw "MODEL_MISSING=$modelPath" }

Remove-Item Env:RAWRXD_HTTP_PORT,Env:RAWRXD_HEADLESS -EA SilentlyContinue
$env:RAWRXD_HOST_DECODE = '1'
$env:DEEP2_MINIMAL_ENHANCE = '1'
$env:DEEP2_DUALSTICK_ARM = '0'
$env:DEEP2_MARS = '0'
$env:DEEP2_LIVE_PATH = '0'
$env:RAWRXD_LIVE_PATH = '0'
$env:DEEP2_LIVE_POLICY = 'OFF'
$env:DEEP2_LIVE_MECH = 'none'
$env:RAWRXD_DEEP2_ALLOW_ELASTIC = '0'
$env:DEEP2_WEIGHT_BUDGET_MIB = '2048'

function Get-ServerPid {
  $c = Get-NetTCPConnection -LocalPort $Port -State Listen -EA SilentlyContinue | Select-Object -First 1
  if ($c) { [int]$c.OwningProcess } else { 0 }
}
function HttpReq([string]$method, [string]$path, [string]$json, [string]$outFile, [int]$timeoutSec = 300) {
  $url = "http://127.0.0.1:$Port$path"
  $code = 0; $body = ''
  try {
    if ($method -eq 'GET') {
      $r = Invoke-WebRequest -Uri $url -Method GET -UseBasicParsing -TimeoutSec $timeoutSec
    } else {
      $bytes = $utf8.GetBytes($json)
      $r = Invoke-WebRequest -Uri $url -Method POST -Body $bytes -ContentType 'application/json; charset=utf-8' -UseBasicParsing -TimeoutSec $timeoutSec
    }
    $code = [int]$r.StatusCode; $body = [string]$r.Content
  } catch {
    $resp = $_.Exception.Response
    if ($resp) {
      $code = [int]$resp.StatusCode
      try { $sr = New-Object IO.StreamReader($resp.GetResponseStream()); $body = $sr.ReadToEnd(); $sr.Close() } catch {}
    }
  }
  if ($outFile) { [IO.File]::WriteAllText($outFile, $body, $utf8) }
  @{ code = $code; body = $body }
}

$old = Get-ServerPid
if ($old -gt 0) { Stop-Process -Id $old -Force -EA SilentlyContinue; Start-Sleep 2 }
Get-Process RawrXD-Win32IDE -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1

$stdout = Join-Path $gate 'stdout.txt'
$stderr = Join-Path $gate 'stderr.txt'
Remove-Item $stdout, $stderr -Force -EA SilentlyContinue
$proc = Start-Process -FilePath $exe -ArgumentList @('--headless','--local','--port',"$Port",'--dir','G:\~dev\rawrxd') `
  -WorkingDirectory $smoke -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
$spid = [int]$proc.Id
$ready = $false
for ($i = 0; $i -lt 60; $i++) {
  Start-Sleep 1
  if ($proc.HasExited) { throw "EXIT_EARLY=$($proc.ExitCode)" }
  if ((Get-ServerPid) -ne $spid) { continue }
  $h = HttpReq GET '/health' '' (Join-Path $gate 'boot_health.txt') 5
  if ($h.code -eq 200) { $ready = $true; break }
}
if (-not $ready) { Stop-Process -Id $spid -Force -EA SilentlyContinue; throw 'HEALTH_TIMEOUT' }

$loadBody = "{`"modelPath`":`"$modelPath`"}"
$load = HttpReq POST '/api/model/load' $loadBody (Join-Path $gate 'load.txt') 600
Start-Sleep 1
$errText = ''
if (Test-Path $stderr) { $errText = [IO.File]::ReadAllText($stderr) }

$headlessOk = [int]($errText -match 'HEADLESS_LOADMODEL=OK')
$headlessFail = [int]($errText -match 'HEADLESS_LOADMODEL=FAIL')
$sessionOk = [int]($errText -match 'PRODUCT_OPEN_SESSION=OK')
$sessionFail = [int]($errText -match 'PRODUCT_OPEN_SESSION=FAIL')
$residency = [int]($errText -match 'DEEP2_RESIDENCY_ENTERED=1')
$tensorsGt0 = 0
if ($errText -match 'PRODUCT_OPEN_SESSION=OK\s+tensors=1') { $tensorsGt0 = 1 }
elseif ($errText -match 'PRODUCT_OPEN_SESSION=FAIL\s+tensors=(\d+)') { $tensorsGt0 = [int]($Matches[1] -gt 0) }
elseif ($errText -match 'PRODUCT_OPEN=FAIL reason=NO_TENSOR_PAYLOAD') { $tensorsGt0 = 0 }

# Frozen EXE predates OK/HEADLESS markers — still honor FAIL / NO_TENSOR lines.
$loadCalled = [int](($load.code -ne 0) -or $headlessOk -or $headlessFail -or $sessionOk -or $sessionFail)
$sessionCreated = $sessionOk
# Legacy fail path without OK telemetry: cannot invent session_created from HTTP 200.
if ($sessionFail -eq 1) { $sessionCreated = 0 }
$headlessReal = [int]($headlessOk -eq 1 -or ($loadCalled -eq 1 -and ($sessionOk -eq 1 -or $sessionFail -eq 1 -or ($errText -match 'PRODUCT_OPEN=FAIL'))))
# If frozen EXE: load HTTP issued + product open line seen => loadModel real path entered.
if ($headlessOk -eq 0 -and $headlessFail -eq 0) {
  $headlessReal = [int]($load.code -ne 0 -and ($sessionOk -eq 1 -or $sessionFail -eq 1 -or ($errText -match 'PRODUCT_OPEN')))
}

$pSession = $sessionCreated
$pHeadless = $headlessReal
$pResidency = $residency
$pTensors = $tensorsGt0
# Frozen EXE has no DEEP2_RESIDENCY_ENTERED=1 line; residency only true with OK telemetry or tensors.
if ($pResidency -eq 0 -and $sessionOk -eq 1 -and $tensorsGt0 -eq 1) { $pResidency = 1 }

$failOwner = 'NONE'
if ($pSession -eq 0) { $failOwner = 'ProductOpenSession_created' }
elseif ($pHeadless -eq 0) { $failOwner = 'Headless_loadModel_real_path' }
elseif ($pResidency -eq 0) { $failOwner = 'Deep2_residency_entered' }
elseif ($pTensors -eq 0) { $failOwner = 'tensors_resolved_gt0' }

$pass = [int]($pSession -eq 1 -and $pHeadless -eq 1 -and $pResidency -eq 1 -and $pTensors -eq 1)
$ideReady = $pass

$receipt = @"
GATE=R24_PRODUCTOPEN_TENSORS_GT0_001
ASOF=$((Get-Date).ToString('o'))
PROMOTE=0
TIP_CLIMB=HOLD
PROMOTE_MULTI_FAMILY_PRODUCTOPEN=0
NO_HTTP_ONLY_SUBSTITUTE=1
NO_CAPABILITY_ORPHAN_SUBSTITUTE=1
NO_ROLLUP_PASS_SUBSTITUTE=1

MODEL_FAMILY_SELECTED=$Family
MODEL_PATH=$modelPath
EXE_SHA256=$sha
EXE_NOTE=R24_freeze_EF2FF_or_copy; OK/HEADLESS markers require source rebuild

HEADLESS_LOAD_HTTP=$($load.code)
HEADLESS_LOADMODEL_CALLED=$loadCalled
HEADLESS_LOADMODEL_REAL_PATH=$pHeadless
PRODUCTOPEN_SESSION_CREATED=$pSession
DEEP2_RESIDENCY_ENTERED=$pResidency
TENSORS_RESOLVED_GT0=$pTensors
IDE_READY_DERIVED_FROM_PRODUCTOPEN=$ideReady

PRODUCT_OPEN_SESSION_OK_LINE=$sessionOk
PRODUCT_OPEN_SESSION_FAIL_LINE=$sessionFail
HEADLESS_LOADMODEL_OK_LINE=$headlessOk
FROZEN_EXE_OK_TELEMETRY=$(([int]($sessionOk -eq 0 -and $headlessOk -eq 0)))

PASS=$pass
FAIL_OWNER=$failOwner
OLLAMA_CONTACT=0
"@

[IO.File]::WriteAllText((Join-Path $gate 'RECEIPT.txt'), $receipt, $utf8)
[IO.File]::WriteAllText((Join-Path $gate 'KEY_LINES.txt'), @"
GATE=R24_PRODUCTOPEN_TENSORS_GT0_001
FAMILY=$Family PASS=$pass FAIL_OWNER=$failOwner
PRODUCTOPEN_SESSION_CREATED=$pSession HEADLESS=$pHeadless RESIDENCY=$pResidency TENSORS_GT0=$pTensors
IDE_READY=$ideReady PROMOTE=0
"@, $utf8)

Stop-Process -Id $spid -Force -EA SilentlyContinue
Write-Host $receipt
exit $(if ($pass -eq 1) { 0 } else { 1 })
