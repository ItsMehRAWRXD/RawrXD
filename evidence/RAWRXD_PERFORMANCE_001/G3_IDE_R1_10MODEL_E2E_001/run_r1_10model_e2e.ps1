# Robust G3_IDE_R1_10MODEL_E2E_001 harness — cmd redirect, TCP ready, HOST_DECODE
$ErrorActionPreference = "Continue"
$EV = "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_IDE_R1_10MODEL_E2E_001"
$ROOT = "G:\~dev\rawrxd"
$EXE = "G:\~dev\rawrxd\smoke_bin\RawrXD-Win32IDE_r1_10model.exe"
$PORT = 11435
$BASE = "http://127.0.0.1:$PORT"
New-Item -ItemType Directory -Force -Path $EV | Out-Null

$models = @(
  @{ Id="01_tinyllama"; Path="G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"; Family="tinyllama-1.1b" },
  @{ Id="02_phi3_mini"; Path="F:\OllamaModels\Phi-3-mini-4k-instruct-q8_0.gguf"; Family="phi3-mini-q8" },
  @{ Id="03_nemotron_nano"; Path="F:\OllamaModels\NVIDIA-Nemotron-3-Nano-4B-GGUF\NVIDIA-Nemotron-3-Nano-4B-Q8_0.gguf"; Family="nemotron-nano-4b" },
  @{ Id="04_deepseek_r1_qwen3_8b"; Path="F:\OllamaModels\DeepSeek-R1-0528-Qwen3-8B-GGUF\DeepSeek-R1-0528-Qwen3-8B-Q4_K_M.gguf"; Family="deepseek-r1-qwen3-8b" },
  @{ Id="05_gemma4_e4b"; Path="F:\OllamaModels\gemma-4-E4B-it-GGUF\gemma-4-E4B-it-Q4_K_M.gguf"; Family="gemma4-e4b" },
  @{ Id="06_phi3_medium_14b"; Path="F:\OllamaModels\Phi-3-medium-128k-instruct-14B-Q4_K_M\Phi-3-medium-128k-instruct-Q4_K_M.gguf"; Family="phi3-medium-14b" },
  @{ Id="07_codestral_22b"; Path="F:\OllamaModels\rawrxd_test_models\Codestral-22B-v0.1-Q4_K_M.gguf"; Family="codestral-22b" },
  @{ Id="08_qwen38_27b"; Path="F:\OllamaModels\Qwen3.8-27B-AD-Q4_K_M\Qwen3.8-27B-AD-Q4_K_M.gguf"; Family="qwen3.8-27b" },
  @{ Id="09_gemma4_31b"; Path="F:\OllamaModels\gemma-4-31B-it-GGUF\gemma-4-31B-it-Q4_K_M.gguf"; Family="gemma4-31b" },
  @{ Id="10_bigdaddyg_cheetah"; Path="F:\OllamaModels\BigDaddyG-Q2_K-CHEETAH.gguf"; Family="bigdaddyg-q2k-cheetah" }
)

function Write-Log([string]$msg) {
  $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-ddTHH:mm:ss"), $msg
  Add-Content -Path (Join-Path $EV "RUN_LOG.txt") -Value $line
  Write-Host $line
}

function Test-Alive([int]$ProcessId) {
  try { $p = Get-Process -Id $ProcessId -ErrorAction Stop; return (-not $p.HasExited) } catch { return $false }
}

function Invoke-RawHttp([string]$Method, [string]$Url, [string]$Body = $null, [int]$TimeoutSec = 600) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  try {
    $params = @{ Uri=$Url; Method=$Method; TimeoutSec=$TimeoutSec; UseBasicParsing=$true }
    if ($null -ne $Body) { $params.Body = $Body; $params.ContentType = "application/json" }
    $resp = Invoke-WebRequest @params
    $sw.Stop()
    return @{ Ok=$true; Status=[int]$resp.StatusCode; Body=[string]$resp.Content; Ms=$sw.ElapsedMilliseconds; Exception="" }
  } catch {
    $sw.Stop()
    $status = 0; $body = ""
    if ($_.Exception.Response) {
      try { $status = [int]$_.Exception.Response.StatusCode.value__ } catch {
        try { $status = [int]$_.Exception.Response.StatusCode } catch {}
      }
      try {
        $stream = $_.Exception.Response.GetResponseStream()
        if ($stream) { $reader = New-Object IO.StreamReader($stream); $body = $reader.ReadToEnd(); $reader.Close() }
      } catch {}
    }
    if ($status -eq 0 -and $_.ErrorDetails) { $body = [string]$_.ErrorDetails.Message }
    return @{ Ok=$false; Status=$status; Body=$body; Ms=$sw.ElapsedMilliseconds; Exception=$_.Exception.Message }
  }
}

function Get-TokenCount([string]$body) {
  if ([string]::IsNullOrEmpty($body)) { return 0 }
  try {
    $j = $body | ConvertFrom-Json
    foreach ($k in @("eval_count","tokens","completion_tokens","generated_tokens","token_count")) {
      if ($null -ne $j.$k) { $n=0; if ([int]::TryParse([string]$j.$k,[ref]$n) -and $n -gt 0) { return $n } }
    }
    if ($j.usage -and $j.usage.completion_tokens) {
      $n=0; if ([int]::TryParse([string]$j.usage.completion_tokens,[ref]$n) -and $n -gt 0) { return $n }
    }
    $text = ""
    if ($j.response) { $text = [string]$j.response }
    elseif ($j.output) { $text = [string]$j.output }
    elseif ($j.text) { $text = [string]$j.text }
    elseif ($j.choices -and $j.choices.Count -gt 0) {
      $c = $j.choices[0]
      if ($c.message.content) { $text = [string]$c.message.content }
      elseif ($c.text) { $text = [string]$c.text }
    }
    if ($text.Length -gt 0) { return [Math]::Max(1, [Math]::Ceiling($text.Length / 4.0)) }
  } catch {}
  return 0
}

function Wait-TcpReady([int]$Port, [int]$TimeoutSec = 180) {
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ((Get-Date) -lt $deadline) {
    try {
      $c = New-Object Net.Sockets.TcpClient
      $iar = $c.BeginConnect("127.0.0.1", $Port, $null, $null)
      $ok = $iar.AsyncWaitHandle.WaitOne(1000, $false)
      if ($ok -and $c.Connected) { $c.Close(); return $true }
      $c.Close()
    } catch {}
    Start-Sleep -Milliseconds 250
  }
  return $false
}

# Clear prior logs (keep sibling artifacts if present)
Remove-Item (Join-Path $EV "RUN_LOG.txt") -ErrorAction SilentlyContinue
Remove-Item (Join-Path $EV "MATRIX.csv") -ErrorAction SilentlyContinue
Remove-Item (Join-Path $EV "SUMMARY_RAW.txt") -ErrorAction SilentlyContinue
Remove-Item (Join-Path $EV "HTTP_PARITY.txt") -ErrorAction SilentlyContinue

# Ensure EXE is fresh from build-fd
if (-not (Test-Path "G:\~dev\rawrxd\build-fd\bin\RawrXD-Win32IDE.exe")) {
  Write-Log "MISSING build-fd EXE"; exit 3
}
Copy-Item -Force "G:\~dev\rawrxd\build-fd\bin\RawrXD-Win32IDE.exe" $EXE
$sha = (Get-FileHash $EXE -Algorithm SHA256).Hash
Set-Content (Join-Path $EV "EXE_SHA.txt") $sha
Write-Log "EXE_SHA=$sha"

# Kill listeners on our port only
Get-NetTCPConnection -LocalPort $PORT -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
  try { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue } catch {}
}
Start-Sleep -Seconds 1

$outLog = Join-Path $EV "headless.out.txt"
$errLog = Join-Path $EV "headless.err.txt"
Remove-Item $outLog,$errLog -ErrorAction SilentlyContinue

$env:RAWRXD_HOST_DECODE = "1"
$env:RAWRXD_TIP_CLIMB = "HOLD"
$env:TIP_CLIMB = "HOLD"
$env:OLLAMA_HOST = "http://127.0.0.1:9"
# Avoid smoke_bin settings auto model — run with working dir = ROOT, no --model
$arg = "--headless --local --port $PORT --dir `"$ROOT`""
$cmd = "cmd.exe"
$cmdArgs = "/c `"set RAWRXD_HOST_DECODE=1&& set RAWRXD_TIP_CLIMB=HOLD&& set TIP_CLIMB=HOLD&& set OLLAMA_HOST=http://127.0.0.1:9&& `"$EXE`" $arg > `"$outLog`" 2> `"$errLog`""
$proc = Start-Process -FilePath $cmd -ArgumentList $cmdArgs -WorkingDirectory $ROOT -PassThru -WindowStyle Hidden
# The cmd wrapper is parent; find actual IDE child
Start-Sleep -Seconds 2
$ide = Get-Process | Where-Object { $_.ProcessName -like "RawrXD-Win32IDE*" -and $_.Id -ne $proc.Id } |
  Where-Object {
    try {
      $cl = (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine
      $cl -and $cl.Contains("--port $PORT")
    } catch { $false }
  } | Select-Object -First 1
if (-not $ide) {
  # fallback: any listen on port
  $lp = Get-NetTCPConnection -LocalPort $PORT -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($lp) { $ide = Get-Process -Id $lp.OwningProcess -ErrorAction SilentlyContinue }
}
if (-not $ide) { Write-Log "FAIL_NO_IDE_PROCESS"; exit 4 }
$idePid = $ide.Id
Set-Content (Join-Path $EV "headless.pid") $idePid
Write-Log "STARTED idePid=$idePid cmdPid=$($proc.Id)"

if (-not (Wait-TcpReady -Port $PORT -TimeoutSec 180)) {
  Write-Log "FAIL_TCP_NOT_READY"
  "READY=0" | Set-Content (Join-Path $EV "READY.txt")
  try { Stop-Process -Id $idePid -Force } catch {}
  exit 2
}
# HTTP probe
$readyHttp = $false
for ($i=0; $i -lt 60; $i++) {
  if (-not (Test-Alive $idePid)) { Write-Log "DIED_BEFORE_HTTP"; break }
  $r = Invoke-RawHttp "GET" "$BASE/api/backend/status" $null 5
  if ($r.Status -eq 200) { $readyHttp = $true; Write-Log "READY $($r.Body)"; break }
  Start-Sleep -Milliseconds 500
}
if (-not $readyHttp) {
  Write-Log "FAIL_HTTP_NOT_READY"
  "READY=0" | Set-Content (Join-Path $EV "READY.txt")
  try { Stop-Process -Id $idePid -Force } catch {}
  exit 2
}
"READY=1 PID=$idePid" | Set-Content (Join-Path $EV "READY.txt")

$csvPath = Join-Path $EV "MATRIX.csv"
"id,family,path,load_http,load_ok,gen_http,gen_tokens,unload_http,reload_http,reload_gen_http,reload_gen_tokens,survived,av,c0000374,notes" | Set-Content $csvPath
$passCount=0; $failCount=0; $avTotal=0; $heapTotal=0; $survivedAll=1

foreach ($m in $models) {
  $notes = New-Object System.Collections.Generic.List[string]
  $loadHttp=0; $loadOk=0; $genHttp=0; $genTokens=0; $unloadHttp=0
  $reloadHttp=0; $reloadGenHttp=0; $reloadGenTokens=0; $survived=1; $av=0; $c374=0
  Write-Log "==== MODEL $($m.Id) $($m.Family) ===="
  if (-not (Test-Path $m.Path)) {
    $notes.Add("FILE_MISSING"); $failCount++
    $survived = if (Test-Alive $idePid) {1} else {0}
    Add-Content $csvPath "$($m.Id),$($m.Family),`"$($m.Path)`",0,0,0,0,0,0,0,0,$survived,0,0,FILE_MISSING"
    continue
  }
  $loadBody = (@{ modelPath = $m.Path } | ConvertTo-Json -Compress)
  $load = Invoke-RawHttp "POST" "$BASE/api/model/load" $loadBody 2400
  $loadHttp = $load.Status
  if (-not (Test-Alive $idePid)) { $survived=0; $notes.Add("DIED_ON_LOAD"); $av=1 }
  if ($load.Status -eq 200 -and $load.Body -match '"success"\s*:\s*true') { $loadOk=1 }
  else {
    $notes.Add("LOAD_FAIL")
    if ($load.Body -match "workspace_path_denied") { $notes.Add("WORKSPACE_PATH_DENIED") }
    $snip=$load.Body; if ($snip.Length -gt 180) { $snip=$snip.Substring(0,180) }
    $notes.Add("LOAD_BODY=$snip")
  }
  Write-Log "LOAD http=$loadHttp ok=$loadOk ms=$($load.Ms)"

  if ($loadOk -eq 1 -and $survived -eq 1) {
    $genBody = '{"prompt":"2+2=","stream":false,"options":{"num_predict":8}}'
    $gen = Invoke-RawHttp "POST" "$BASE/api/generate" $genBody 2400
    $genHttp=$gen.Status; $genTokens=Get-TokenCount $gen.Body
    if (-not (Test-Alive $idePid)) { $survived=0; $notes.Add("DIED_ON_GEN"); $av=1 }
    Set-Content (Join-Path $EV "gen_$($m.Id).txt") $gen.Body
    $snip=$gen.Body; if ($snip.Length -gt 220) { $snip=$snip.Substring(0,220) }
    Write-Log "GEN http=$genHttp tokens=$genTokens ms=$($gen.Ms) body=$snip"
    if ($genHttp -ne 200) { $notes.Add("GEN_HTTP=$genHttp") }
    if ($genTokens -le 0) { $notes.Add("GEN_TOKENS_0") }
  }

  if ($survived -eq 1) {
    $ul = Invoke-RawHttp "POST" "$BASE/api/model/unload" "{}" 600
    $unloadHttp=$ul.Status
    if (-not (Test-Alive $idePid)) { $survived=0; $notes.Add("DIED_ON_UNLOAD"); $av=1 }
    Write-Log "UNLOAD http=$unloadHttp"
  }

  if ($survived -eq 1) {
    $rl = Invoke-RawHttp "POST" "$BASE/api/model/load" $loadBody 2400
    $reloadHttp=$rl.Status
    $reloadOk = ($rl.Status -eq 200 -and $rl.Body -match '"success"\s*:\s*true')
    if (-not (Test-Alive $idePid)) { $survived=0; $notes.Add("DIED_ON_RELOAD"); $av=1 }
    Write-Log "RELOAD http=$reloadHttp ok=$reloadOk"
    if (-not $reloadOk) { $notes.Add("RELOAD_FAIL") }
    if ($reloadOk -and $survived -eq 1) {
      $gen2 = Invoke-RawHttp "POST" "$BASE/api/generate" '{"prompt":"2+2=","stream":false,"options":{"num_predict":8}}' 2400
      $reloadGenHttp=$gen2.Status; $reloadGenTokens=Get-TokenCount $gen2.Body
      if (-not (Test-Alive $idePid)) { $survived=0; $notes.Add("DIED_ON_RELOAD_GEN"); $av=1 }
      Write-Log "RELOAD_GEN http=$reloadGenHttp tokens=$reloadGenTokens"
    }
    $ul2 = Invoke-RawHttp "POST" "$BASE/api/model/unload" "{}" 600
    Write-Log "UNLOAD2 http=$($ul2.Status)"
    if (-not (Test-Alive $idePid)) { $survived=0; $notes.Add("DIED_ON_UNLOAD2"); $av=1 }
  }

  if (Test-Path $errLog) {
    $tail = Get-Content $errLog -Tail 120 -ErrorAction SilentlyContinue | Out-String
    if ($tail -match "0xC0000005|ACCESS_VIOLATION|c0000005") { $av=1; $notes.Add("ERR_AV") }
    if ($tail -match "C0000374|0xC0000374") { $c374=1; $notes.Add("ERR_HEAP") }
  }

  $coreOk = ($loadOk -eq 1 -and $unloadHttp -eq 200 -and $reloadHttp -eq 200 -and $survived -eq 1 -and $av -eq 0 -and $c374 -eq 0)
  $genOk = ($genHttp -eq 200 -and $genTokens -gt 0 -and $reloadGenHttp -eq 200 -and $reloadGenTokens -gt 0)
  if ($coreOk -and $genOk) { $notes.Add("PRODUCT_PASS"); $passCount++ }
  elseif ($coreOk) { $notes.Add("SURVIVE_PASS_GEN_PARTIAL"); $failCount++ }
  else { $notes.Add("FAIL"); $failCount++; if ($survived -eq 0) { $survivedAll=0 } }
  $avTotal += $av; $heapTotal += $c374
  $noteStr = ($notes -join ";") -replace ",",";"
  $row = "$($m.Id),$($m.Family),`"$($m.Path)`",$loadHttp,$loadOk,$genHttp,$genTokens,$unloadHttp,$reloadHttp,$reloadGenHttp,$reloadGenTokens,$survived,$av,$c374,$noteStr"
  Add-Content $csvPath $row
  Write-Log "ROW $row"
}

# Parity + ask/v1 on tinyllama
Write-Log "==== PARITY ===="
$parityPath = Join-Path $EV "HTTP_PARITY.txt"
Remove-Item $parityPath -ErrorAction SilentlyContinue
$tiny = $models[0].Path
$lt = Invoke-RawHttp "POST" "$BASE/api/model/load" ((@{modelPath=$tiny}|ConvertTo-Json -Compress)) 1200
Add-Content $parityPath "POST /api/model/load tiny -> HTTP=$($lt.Status) BODY=$($lt.Body.Substring(0,[Math]::Min(200,$lt.Body.Length)))"
$ask = Invoke-RawHttp "POST" "$BASE/ask" '{"prompt":"2+2=","stream":false,"options":{"num_predict":8}}' 1200
Add-Content $parityPath "POST /ask -> HTTP=$($ask.Status) LEN=$($ask.Body.Length) BODY=$($ask.Body.Substring(0,[Math]::Min(280,$ask.Body.Length)))"
$v1 = Invoke-RawHttp "POST" "$BASE/v1/chat/completions" '{"model":"tinyllama","messages":[{"role":"user","content":"2+2="}],"max_tokens":8,"stream":false}' 1200
Add-Content $parityPath "POST /v1/chat/completions -> HTTP=$($v1.Status) LEN=$($v1.Body.Length) BODY=$($v1.Body.Substring(0,[Math]::Min(280,$v1.Body.Length)))"

$parity404=0
$routes = @(
  @{M="GET";U="/api/policies"},@{M="GET";U="/api/policies/suggestions"},@{M="GET";U="/api/policies/heuristics"},@{M="GET";U="/api/policies/stats"},
  @{M="POST";U="/api/policies/apply";B="{}"},@{M="GET";U="/api/extensions"},@{M="GET";U="/api/extensions/host/status"},
  @{M="POST";U="/api/extensions/install";B="{}"},@{M="POST";U="/api/browse";B="{}"},
  @{M="GET";U="/api/agents/explain"},@{M="GET";U="/api/agents/explain/stats"},
  @{M="POST";U="/api/backends/use";B='{"backend":"deep2"}'},@{M="GET";U="/metrics"},
  @{M="POST";U="/complete";B='{"prompt":"hi","stream":false,"options":{"num_predict":4}}'},
  @{M="POST";U="/api/stat-file";B='{"path":"AGENTS.md"}'},@{M="POST";U="/api/list-directory";B='{"path":"."}'}
)
foreach ($rt in $routes) {
  $r = Invoke-RawHttp $rt.M ($BASE+$rt.U) $rt.B 30
  if ($r.Status -eq 404) { $parity404++ }
  $snip=$r.Body; if ($snip.Length -gt 140) { $snip=$snip.Substring(0,140) }
  Add-Content $parityPath "$($rt.M) $($rt.U) -> HTTP=$($r.Status) BODY=$snip"
}
$ou = Invoke-RawHttp "POST" "$BASE/api/backends/use" '{"backend":"ollama"}' 30
Add-Content $parityPath "POST /api/backends/use ollama -> HTTP=$($ou.Status) BODY=$($ou.Body)"
$localOnlyOk = ($ou.Status -eq 422)

$pre = Invoke-RawHttp "POST" "$BASE/api/tool" '{"tool":"list_tools"}' 30
Add-Content $parityPath "POST /api/tool list_tools pre-motd -> HTTP=$($pre.Status) BODY=$($pre.Body.Substring(0,[Math]::Min(180,$pre.Body.Length)))"
$rm = Invoke-RawHttp "POST" "$BASE/api/tool" '{"tool":"read_motd"}' 30
Add-Content $parityPath "POST /api/tool read_motd -> HTTP=$($rm.Status) BODY=$($rm.Body.Substring(0,[Math]::Min(180,$rm.Body.Length)))"
$post = Invoke-RawHttp "POST" "$BASE/api/tool" '{"tool":"list_tools"}' 30
Add-Content $parityPath "POST /api/tool list_tools post-motd -> HTTP=$($post.Status) BODY=$($post.Body.Substring(0,[Math]::Min(400,$post.Body.Length)))"
$null = Invoke-RawHttp "POST" "$BASE/api/model/unload" "{}" 120

$ollamaContact=0
try {
  $conns = Get-NetTCPConnection -OwningProcess $idePid -ErrorAction SilentlyContinue | Where-Object { $_.RemotePort -eq 11434 }
  if ($conns) { $ollamaContact=1 }
} catch {}

$finalSurvived = if (Test-Alive $idePid) {1} else {0}
if ($finalSurvived -eq 0) { $survivedAll=0 }
Write-Log "STOPPING idePid=$idePid"
try { Stop-Process -Id $idePid -Force } catch {}
try { Stop-Process -Id $proc.Id -Force } catch {}
Start-Sleep -Seconds 2

@"
GATE=G3_IDE_R1_10MODEL_E2E_001
ASOF=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
PROMOTE=0
TIP_CLIMB=HOLD
EXE=$EXE
SHA256=$sha
SHA16=$($sha.Substring(0,16))
PORT=127.0.0.1:$PORT
HOST_DECODE=1
LOCAL_ONLY=1
OLLAMA_CONTACT_PRODUCT=$ollamaContact
ACCESS_VIOLATION_TOTAL=$avTotal
C0000374_TOTAL=$heapTotal
PROCESS_SURVIVED_FINAL=$finalSurvived
PROCESS_SURVIVED_ALL_MODELS=$survivedAll
MATRIX_PASS=$passCount
MATRIX_FAIL=$failCount
FAIL_COUNT_404=$parity404
LOCAL_ONLY_OLLAMA_422=$localOnlyOk
ASK_HTTP=$($ask.Status)
V1_HTTP=$($v1.Status)
"@ | Set-Content (Join-Path $EV "SUMMARY_RAW.txt")
Write-Log "DONE pass=$passCount fail=$failCount av=$avTotal survived=$finalSurvived ollama=$ollamaContact parity404=$parity404"
exit 0
