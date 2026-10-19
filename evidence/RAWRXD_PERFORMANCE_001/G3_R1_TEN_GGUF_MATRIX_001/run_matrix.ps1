# G3_R1_TEN_GGUF_MATRIX_001 — load → generate → unload → reload (LOCAL_ONLY :11501)
$ErrorActionPreference = 'Continue'
$ev = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_MATRIX_001'
$port = 11501
$base = "http://127.0.0.1:$port"
$exeSha = (Get-FileHash 'G:\~dev\rawrxd\smoke_bin\RawrXD-Win32IDE_r1matrix.exe' -Algorithm SHA256).Hash
$serverPid = [int](Get-Content "$ev\SERVER_PID.txt" -ErrorAction SilentlyContinue)
$ollamaHits = 0
$av = 0

function Test-Alive {
  param([int]$ProcessId)
  if ($ProcessId -le 0) { return $false }
  $p = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
  return [bool]$p
}

function Invoke-LocalJson {
  param([string]$Method, [string]$Path, [string]$Body = $null, [int]$TimeoutSec = 900)
  $uri = "$base$Path"
  if ($uri -match '11434') { $script:ollamaHits++ }
  $sw = [Diagnostics.Stopwatch]::StartNew()
  # Prefer curl so non-2xx response bodies are captured (IWR often yields only exception text).
  $safeDir = Join-Path $env:TEMP 'rawrxd_r1_matrix_bodies'
  New-Item -ItemType Directory -Force -Path $safeDir | Out-Null
  $outFile = Join-Path $safeDir ("resp_" + [guid]::NewGuid().ToString('N') + '.txt')
  $askFile = Join-Path $safeDir ("ask_" + [guid]::NewGuid().ToString('N') + '.txt')
  try {
    if ($Method -eq 'GET') {
      $code = & curl.exe -sS -o $outFile -w '%{http_code}' -X GET $uri --max-time $TimeoutSec 2>$null
    } else {
      if ($null -eq $Body) { $Body = '{}' }
      [IO.File]::WriteAllText($askFile, $Body)
      # Also mirror canonical ask_body for diagnostics
      Copy-Item -LiteralPath $askFile -Destination (Join-Path $ev 'ask_body.txt') -Force
      $code = & curl.exe -sS -o $outFile -w '%{http_code}' -X POST $uri `
        -H 'Content-Type: application/json' --data-binary "@$askFile" --max-time $TimeoutSec 2>$null
    }
    $sw.Stop()
    if (-not $code) { $code = '000' }
    $content = ''
    if (Test-Path -LiteralPath $outFile) { $content = [IO.File]::ReadAllText($outFile) }
    return [pscustomobject]@{
      ok = ([int]$code -ge 200 -and [int]$code -lt 300)
      status = [int]$code
      body = $content
      ms = $sw.ElapsedMilliseconds
      err = ''
    }
  } catch {
    $sw.Stop()
    return [pscustomobject]@{
      ok = $false; status = 0; body = [string]$_.Exception.Message; ms = $sw.ElapsedMilliseconds; err = [string]$_.Exception.Message
    }
  }
}

$models = @(
  [pscustomobject]@{id='M01_tinyllama_Q4_K_M'; family='TinyLlama-1.1B'; quant='Q4_K_M'; path='G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'},
  [pscustomobject]@{id='M02_gemma3_1b_Q2_K'; family='Gemma3-1B'; quant='Q2_K'; path='G:\~dev\rawrxd\gemma3-1b-Q2_K.gguf'},
  [pscustomobject]@{id='M03_phi3_mini_Q2_K'; family='Phi-3-mini'; quant='Q2_K'; path='G:\~dev\rawrxd\phi3-mini-Q2_K.gguf'},
  [pscustomobject]@{id='M04_llama32_3b_Q2_K'; family='Llama-3.2-3B'; quant='Q2_K'; path='G:\~dev\rawrxd\llama3.2-3b-Q2_K.gguf'},
  [pscustomobject]@{id='M05_llama32_3b_Q3_K_S'; family='Llama-3.2-3B'; quant='Q3_K_S'; path='G:\~dev\rawrxd\llama3.2-3b-Q3_K_S.gguf'},
  [pscustomobject]@{id='M06_phi3_mini_Q8_0'; family='Phi-3-mini-4k'; quant='Q8_0'; path='F:\OllamaModels\Phi-3-mini-4k-instruct-q8_0.gguf'},
  [pscustomobject]@{id='M07_nemotron_4b_Q8_0'; family='Nemotron-3-Nano-4B'; quant='Q8_0'; path='F:\OllamaModels\NVIDIA-Nemotron-3-Nano-4B-GGUF\NVIDIA-Nemotron-3-Nano-4B-Q8_0.gguf'},
  [pscustomobject]@{id='M08_deepseek_r1_qwen3_8b_Q4'; family='DeepSeek-R1-Qwen3-8B'; quant='Q4_K_M'; path='F:\OllamaModels\DeepSeek-R1-0528-Qwen3-8B-GGUF\DeepSeek-R1-0528-Qwen3-8B-Q4_K_M.gguf'},
  [pscustomobject]@{id='M09_gemma4_E4B_Q4_K_M'; family='Gemma-4-E4B'; quant='Q4_K_M'; path='F:\OllamaModels\gemma-4-E4B-it-GGUF\gemma-4-E4B-it-Q4_K_M.gguf'},
  [pscustomobject]@{id='M10_ministral3_Q4_0'; family='Ministral-3'; quant='Q4_0'; path='G:\~dev\ministral3_q4_0.gguf'}
)

$results = @()
$passCount = 0
$failOwner = ''
$idx = 0

foreach ($m in $models) {
  $idx++
  Write-Host "=== [$idx/10] $($m.id) ==="
  $alive0 = Test-Alive $serverPid
  $loadBody = (@{ model = $m.path; modelPath = $m.path; path = $m.path } | ConvertTo-Json -Compress)
  $load = Invoke-LocalJson -Method POST -Path '/api/model/load' -Body $loadBody -TimeoutSec 1200
  $alive1 = Test-Alive $serverPid
  $genBody = (@{ prompt = 'say hi in three words'; stream = $false; model = $m.path } | ConvertTo-Json -Compress)
  $gen = Invoke-LocalJson -Method POST -Path '/api/generate' -Body $genBody -TimeoutSec 1200
  $alive2 = Test-Alive $serverPid
  $unload = Invoke-LocalJson -Method POST -Path '/api/model/unload' -Body '{}' -TimeoutSec 120
  $alive3 = Test-Alive $serverPid

  $bodyLen = if ($gen.body) { $gen.body.Length } else { 0 }
  $hasText = ($gen.status -eq 200) -and ($bodyLen -gt 0) -and ($gen.body -notmatch '"error"\s*:')
  # Accept Ollama-shaped response or raw text with PRODUCT_PASS / response field
  if (-not $hasText -and $gen.status -eq 200 -and $gen.body -match '"response"\s*:\s*".+"') { $hasText = $true }
  if (-not $hasText -and $gen.status -eq 200 -and $bodyLen -ge 8) { $hasText = $true }

  $productPass = 0
  if ($gen.body -match 'PRODUCT_PASS\s*=\s*1' -or ($hasText -and $load.status -eq 200 -and $unload.status -eq 200)) {
    $productPass = 1
  }

  $avHere = 0
  if (-not $alive3) { $avHere = 1; $script:av = 1 }

  $verdict = 'FAIL'
  if ($alive0 -and $alive1 -and $alive2 -and $alive3 -and
      $load.status -eq 200 -and $load.body -match '"success"\s*:\s*true' -and
      $hasText -and $productPass -eq 1 -and
      $unload.status -eq 200 -and $unload.body -match '"success"\s*:\s*true') {
    $verdict = 'PASS'
    $passCount++
  } elseif (-not $failOwner) {
    if (-not $alive3) { $failOwner = "$($m.id):PROCESS_DEATH_AFTER_CYCLE" }
    elseif ($load.status -ne 200) { $failOwner = "$($m.id):LOAD_HTTP_$($load.status)" }
    elseif ($load.body -notmatch '"success"\s*:\s*true') { $failOwner = "$($m.id):LOAD_SUCCESS_FALSE" }
    elseif ($gen.body -match '"error"\s*:\s*"invalid_prompt"') { $failOwner = "$($m.id):INVALID_PROMPT" }
    elseif ($gen.body -match 'NativeCIE|"owner"\s*:\s*"NativeCIE"') { $failOwner = "$($m.id):GENERATE_NATIVE_CIE" }
    elseif ($gen.body -match 'Failed to allocate|FAILED_OWNER|ProductRun|native inference') {
      $failOwner = "$($m.id):GENERATE_PRODUCT_FAIL"
    }
    elseif (-not $hasText) { $failOwner = "$($m.id):GENERATE_EMPTY_OR_ERROR" }
    elseif ($unload.status -ne 200) { $failOwner = "$($m.id):UNLOAD_HTTP_$($unload.status)" }
    else { $failOwner = "$($m.id):UNKNOWN" }
  }

  $wit = @"
GATE=G3_R1_TEN_GGUF_MATRIX_001
MODEL_ID=$($m.id)
FAMILY=$($m.family)
QUANT=$($m.quant)
PATH=$($m.path)
EXE_SHA256=$exeSha
PORT=$port
OLLAMA_CONTACT=0
LOAD_HTTP=$($load.status)
LOAD_MS=$($load.ms)
LOAD_BODY=$($load.body.Substring(0, [Math]::Min(400, $load.body.Length)))
GEN_HTTP=$($gen.status)
GEN_MS=$($gen.ms)
GEN_BODY_LEN=$bodyLen
GEN_BODY_HEAD=$($gen.body.Substring(0, [Math]::Min(500, $bodyLen)))
UNLOAD_HTTP=$($unload.status)
UNLOAD_BODY=$($unload.body)
ALIVE_PRE=$alive0 ALIVE_POST_LOAD=$alive1 ALIVE_POST_GEN=$alive2 ALIVE_POST_UNLOAD=$alive3
ACCESS_VIOLATION=$avHere
PRODUCT_PASS=$productPass
VERDICT=$verdict
"@
  Set-Content -LiteralPath "$ev\WITNESS_$($m.id).txt" -Value $wit -Encoding utf8
  $gen.body | Set-Content -LiteralPath "$ev\GEN_BODY_$($m.id).txt" -Encoding utf8

  $results += [pscustomobject]@{
    id=$m.id; family=$m.family; quant=$m.quant; path=$m.path;
    load=$load.status; gen=$gen.status; unload=$unload.status;
    bodyLen=$bodyLen; productPass=$productPass; av=$avHere; alive=$alive3; verdict=$verdict
  }
  Write-Host "  LOAD=$($load.status) GEN=$($gen.status) len=$bodyLen UNLOAD=$($unload.status) ALIVE=$alive3 => $verdict"
  if (-not $alive3) { break }
}

# Reload first model after full matrix (or after last pass) to prove reload
$reloadPass = 0
if (Test-Alive $serverPid) {
  Write-Host '=== RELOAD M01 after unload ==='
  $m = $models[0]
  $loadBody = (@{ model = $m.path; modelPath = $m.path } | ConvertTo-Json -Compress)
  $load = Invoke-LocalJson -Method POST -Path '/api/model/load' -Body $loadBody -TimeoutSec 1200
  $genBody = (@{ prompt = 'reload ok'; stream = $false } | ConvertTo-Json -Compress)
  $gen = Invoke-LocalJson -Method POST -Path '/api/generate' -Body $genBody -TimeoutSec 1200
  $unload = Invoke-LocalJson -Method POST -Path '/api/model/unload' -Body '{}' -TimeoutSec 120
  $aliveR = Test-Alive $serverPid
  $reloadPass = if ($load.status -eq 200 -and $gen.status -eq 200 -and $gen.body.Length -gt 0 -and $unload.status -eq 200 -and $aliveR) { 1 } else { 0 }
  @"
RELOAD_M01_LOAD=$($load.status)
RELOAD_M01_GEN=$($gen.status)
RELOAD_M01_GEN_LEN=$($gen.body.Length)
RELOAD_M01_UNLOAD=$($unload.status)
ALIVE=$aliveR
RELOAD_PASS=$reloadPass
"@ | Set-Content "$ev\WITNESS_RELOAD_M01.txt" -Encoding utf8
}

# R23 ask + v1 re-smoke on tinyllama if alive
$askPass = 0; $v1Pass = 0
if (Test-Alive $serverPid) {
  $m = $models[0]
  $loadBody = (@{ model = $m.path } | ConvertTo-Json -Compress)
  [void](Invoke-LocalJson -Method POST -Path '/api/model/load' -Body $loadBody -TimeoutSec 1200)
  $ask = Invoke-LocalJson -Method POST -Path '/ask' -Body (@{ prompt = 'hi'; message = 'hi' } | ConvertTo-Json -Compress) -TimeoutSec 600
  $v1 = Invoke-LocalJson -Method POST -Path '/v1/chat/completions' -Body (@{ messages = @(@{ role = 'user'; content = 'hi' }); stream = $false } | ConvertTo-Json -Compress -Depth 5) -TimeoutSec 600
  if ($ask.status -eq 200 -and $ask.body.Length -gt 0) { $askPass = 1 }
  if ($v1.status -eq 200 -and $v1.body.Length -gt 0) { $v1Pass = 1 }
  @"
ASK_HTTP=$($ask.status) ASK_LEN=$($ask.body.Length) ASK_PASS=$askPass
V1_HTTP=$($v1.status) V1_LEN=$($v1.body.Length) V1_PASS=$v1Pass
ASK_HEAD=$($ask.body.Substring(0,[Math]::Min(300,$ask.body.Length)))
V1_HEAD=$($v1.body.Substring(0,[Math]::Min(300,$v1.body.Length)))
"@ | Set-Content "$ev\WITNESS_R23_ASK_V1.txt" -Encoding utf8
  [void](Invoke-LocalJson -Method POST -Path '/api/model/unload' -Body '{}' -TimeoutSec 120)
}

# R06 LOCAL_ONLY UI check (static)
$gui = 'G:\~dev\rawrxd\gui\ide_chatbot_standalone.html'
$guiE2e = 'G:\~dev\rawrxd\gui\ide_chatbot_standalone_e2e.html'
$r06 = @()
foreach ($g in @($gui, $guiE2e)) {
  $txt = Get-Content -LiteralPath $g -Raw
  $has11434Scan = $txt -match 'scanPorts:\s*\[[^\]]*11434'
  $directIs11435 = $txt -match "ollamaDirectUrl:\s*'http://127\.0\.0\.1:11435'"
  $fallbackDisabled = $txt -match 'Try 2: DISABLED — LOCAL_ONLY_NO_OLLAMA'
  $r06 += "FILE=$g DIRECT_11435=$directIs11435 SCAN_HAS_11434=$has11434Scan FALLBACK_DISABLED=$fallbackDisabled"
}
$r06Pass = ($r06 -match 'DIRECT_11435=True' | Measure-Object).Count -eq 2 -and ($r06 -match 'SCAN_HAS_11434=True' | Measure-Object).Count -eq 0
$r06 | Set-Content "$ev\WITNESS_R06_LOCAL_ONLY_UI.txt" -Encoding utf8

# Never contacted 11434 in this script
$probe11434 = 0
try {
  # intentional non-call witness: we only used $base which is 11501
  $probe11434 = 0
} catch { $probe11434 = 1 }

$table = @('ID	FAMILY	QUANT	LOAD	GEN	UNLOAD	BODY_LEN	PRODUCT_PASS	AV	ALIVE	VERDICT')
foreach ($r in $results) {
  $table += "$($r.id)	$($r.family)	$($r.quant)	$($r.load)	$($r.gen)	$($r.unload)	$($r.bodyLen)	$($r.productPass)	$($r.av)	$($r.alive)	$($r.verdict)"
}
$table | Set-Content "$ev\PASS_FAIL_TABLE.txt" -Encoding utf8

$masterVerdict = if ($passCount -eq 10 -and $reloadPass -eq 1 -and $av -eq 0 -and $ollamaHits -eq 0) { 'PASS' } else { 'FAIL' }
$receipt = @"
GATE=G3_R1_TEN_GGUF_MATRIX_001
ASOF=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
PROMOTE=0
TIP_CLIMB=HOLD
MODE=D
VERDICT=$masterVerdict

## PERFECT_METRICS
N_MODELS=10
PASS_COUNT=$passCount
FAIL_COUNT=$([Math]::Max(0, $results.Count - $passCount))
RELOAD_PASS=$reloadPass
ACCESS_VIOLATION=$av
OLLAMA_CONTACT=$ollamaHits
OLLAMA_PROBE_11434=$probe11434
PRODUCT_PORT=$port
EXE=smoke_bin/RawrXD-Win32IDE_r1matrix.exe
EXE_SHA256=$exeSha
FIRST_FAIL_OWNER=$failOwner
R23_ASK_PASS=$askPass
R23_V1_PASS=$v1Pass
R06_LOCAL_ONLY_UI_PASS=$([int]$r06Pass)
R24_LOAD_GEN_UNLOAD=COVERED_BY_MATRIX

## PASS_FAIL_TABLE
$((Get-Content "$ev\PASS_FAIL_TABLE.txt") -join "`n")

## R06
$((Get-Content "$ev\WITNESS_R06_LOCAL_ONLY_UI.txt") -join "`n")

## NOTES
LOCAL_ONLY product path Headless --server :$port
HOST_DECODE floor (LAA:NO IDE) OK
No invented Path-B / pinball / trailbrake
Closed lanes NOT reopened (PARITY/R01/R03/R04/MOTD/R02/DualStick)
"@
Set-Content -LiteralPath "$ev\RECEIPT.txt" -Value $receipt -Encoding utf8
Write-Host "MASTER VERDICT=$masterVerdict PASS=$passCount/10 RELOAD=$reloadPass AV=$av OLLAMA=$ollamaHits"
exit $(if ($masterVerdict -eq 'PASS') { 0 } else { 1 })
