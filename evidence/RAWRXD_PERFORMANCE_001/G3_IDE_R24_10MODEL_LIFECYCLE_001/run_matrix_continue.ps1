# G3_IDE_R24_10MODEL_LIFECYCLE_001 — continue matrix against live server
$ErrorActionPreference = 'Continue'
$gate = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_IDE_R24_10MODEL_LIFECYCLE_001'
$port = 28141
$prompt = 'Say hello in one short sentence.'
$utf8 = New-Object System.Text.UTF8Encoding $false
$ollamaContact = 0

$models = @(
  @{ id='M01'; name='tinyllama_Q4_K_M'; path='G:/~dev/rawrxd/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf' },
  @{ id='M02'; name='gemma3_1b_Q2_K'; path='G:/~dev/rawrxd/gemma3-1b-Q2_K.gguf' },
  @{ id='M03'; name='llama32_3b_Q2_K'; path='G:/~dev/rawrxd/llama3.2-3b-Q2_K.gguf' },
  @{ id='M04'; name='llama32_3b_Q3_K_S'; path='G:/~dev/rawrxd/llama3.2-3b-Q3_K_S.gguf' },
  @{ id='M05'; name='phi3_mini_Q2_K'; path='G:/~dev/rawrxd/phi3-mini-Q2_K.gguf' },
  @{ id='M06'; name='phi3_mini_Q8_0'; path='F:/OllamaModels/Phi-3-mini-4k-instruct-q8_0.gguf' },
  @{ id='M07'; name='deepseek_r1_qwen3_8b'; path='F:/OllamaModels/DeepSeek-R1-0528-Qwen3-8B-GGUF/DeepSeek-R1-0528-Qwen3-8B-Q4_K_M.gguf' },
  @{ id='M08'; name='gemma4_e4b_Q4_K_M'; path='F:/OllamaModels/gemma-4-E4B-it-GGUF/gemma-4-E4B-it-Q4_K_M.gguf' },
  @{ id='M09'; name='bigdaddy_ultra'; path='F:/OllamaModels/BigDaddyG-Q2_K-ULTRA.gguf' },
  @{ id='M10'; name='codestral_22b'; path='F:/OllamaModels/rawrxd_test_models/Codestral-22B-v0.1-Q4_K_M.gguf' }
)

function Get-ServerPid {
  $p = Get-NetTCPConnection -LocalPort $port -State Listen -EA SilentlyContinue |
    Select-Object -First 1 -ExpandProperty OwningProcess
  return $p
}

function CurlGet([string]$path, [string]$outFile, [int]$timeoutSec = 30) {
  $url = "http://127.0.0.1:$port$path"
  $code = & curl.exe -sS -m $timeoutSec -o $outFile -w '%{http_code}' $url 2>"$outFile.cerr"
  if (-not $code) { $code = '000' }
  $body = ''
  if (Test-Path $outFile) { $body = [IO.File]::ReadAllText($outFile) }
  return @{ code = [int]$code; body = $body }
}

function CurlPost([string]$path, [string]$json, [string]$outFile, [int]$timeoutSec = 120) {
  $url = "http://127.0.0.1:$port$path"
  $req = "$outFile.req.json"
  [IO.File]::WriteAllText($req, $json, $utf8)
  $code = & curl.exe -sS -m $timeoutSec -o $outFile -w '%{http_code}' -X POST $url `
    -H 'Content-Type: application/json' --data-binary "@$req" 2>"$outFile.cerr"
  if (-not $code) { $code = '000' }
  $body = ''
  if (Test-Path $outFile) { $body = [IO.File]::ReadAllText($outFile) }
  return @{ code = [int]$code; body = $body }
}

function CountTokensApprox([string]$body) {
  if ([string]::IsNullOrEmpty($body)) { return 0 }
  if ($body -match '"eval_count"\s*:\s*(\d+)') { return [int]$Matches[1] }
  if ($body -match '"tokens"\s*:\s*(\d+)') { return [int]$Matches[1] }
  if ($body -match '"response"\s*:\s*"(.*?)"') {
    $t = $Matches[1] -replace '\\n',' '
    if ($t.Length -gt 0) { return [Math]::Max(1, ($t -split '\s+').Count) }
  }
  if ($body -match '"content"\s*:\s*"(.*?)"') {
    $t = $Matches[1]
    if ($t.Length -gt 0) { return [Math]::Max(1, ($t -split '\s+').Count) }
  }
  if ($body.Length -gt 20 -and $body -notmatch '"error"') { return 1 }
  return 0
}

function SpotCheck([string]$tag) {
  $dir = Join-Path $gate "spot_$tag"
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $h = CurlGet '/health' (Join-Path $dir 'health.txt')
  $b = CurlGet '/api/backends' (Join-Path $dir 'backends.txt')
  $u = CurlPost '/api/backends/use' '{"backend":"ollama"}' (Join-Path $dir 'backends_use_ollama.txt') 15
  $c = CurlPost '/api/chat' '{"messages":[]}' (Join-Path $dir 'chat.txt') 15
  $t = CurlPost '/api/tool' '{"tool":"list_directory","args":{"path":".cursor/rules"}}' (Join-Path $dir 'tool.txt') 15
  $ollamaOk = ($u.code -eq 422) -and ($u.body -match 'LOCAL_ONLY')
  $toolOk = ($t.code -eq 403) -and ($t.body -match 'motd_required')
  $chatOk = ($c.code -ne 404)
  $line = "SPOT_$tag health=$($h.code) backends=$($b.code) ollama_use=$($u.code) chat=$($c.code) tool=$($t.code) ollama_refuse=$([int]$ollamaOk) tool_motd=$([int]$toolOk)"
  [IO.File]::WriteAllText((Join-Path $dir 'SPOT.txt'), $line, $utf8)
  Write-Host $line
  if (-not $ollamaOk) { $script:ollamaContact = 1 }
  return @{ ok = (($h.code -eq 200) -and ($b.code -eq 200) -and $chatOk -and $toolOk -and $ollamaOk); line = $line }
}

$spid = Get-ServerPid
if (-not $spid) { Write-Host 'NO_SERVER'; exit 2 }
"MATRIX_START PID=$spid $(Get-Date -Format o)" | Set-Content "$gate\MATRIX_START.txt"
Write-Host "SERVER_PID=$spid"

$spot1 = SpotCheck 'after_boot'
$spot1.line | Set-Content "$gate\SPOT_BOOT.txt"

$tsv = Join-Path $gate 'MATRIX.tsv'
"ID`tNAME`tLOAD`tINFO`tGEN`tTOKENS`tUNLOAD`tRELOAD`tREUNLOAD`tALIVE`tMS_LOAD`tMS_GEN`tMS_RELOAD`tPASS`tDETAIL" |
  Set-Content $tsv -Encoding ascii

$passCount = 0
$av = 0

foreach ($m in $models) {
  $cur = Get-ServerPid
  if (-not $cur -or $cur -ne $spid) {
    $av = 1
    "$($m.id)`t$($m.name)`t000`t000`t000`t0`t000`t000`t000`t0`t0`t0`t0`t0`tPROCESS_DEAD_OR_REPLACED" | Add-Content $tsv
    Write-Host "DEAD at $($m.id)"
    break
  }

  $rowDir = Join-Path $gate $m.id
  New-Item -ItemType Directory -Force -Path $rowDir | Out-Null
  $loadBody = "{`"modelPath`":`"$($m.path)`"}"
  $genBody = "{`"model`":`"$($m.path)`",`"prompt`":`"$prompt`",`"stream`":false,`"max_tokens`":16,`"options`":{`"num_predict`":16}}"

  $loadTimeout = 900
  $genTimeout = 900
  if ($m.id -in @('M07','M08','M09','M10')) { $loadTimeout = 2400; $genTimeout = 3600 }

  Write-Host "=== $($m.id) LOAD ==="
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $load = CurlPost '/api/model/load' $loadBody (Join-Path $rowDir 'load.txt') $loadTimeout
  $msLoad = $sw.ElapsedMilliseconds
  Write-Host "LOAD=$($load.code) ms=$msLoad body=$($load.body.Substring(0,[Math]::Min(120,$load.body.Length)))"

  $info = CurlGet '/api/model/info' (Join-Path $rowDir 'info.txt') 30

  Write-Host "=== $($m.id) GEN ==="
  $sw.Restart()
  $gen = CurlPost '/api/generate' $genBody (Join-Path $rowDir 'gen.txt') $genTimeout
  $msGen = $sw.ElapsedMilliseconds
  $tok = CountTokensApprox $gen.body
  [IO.File]::WriteAllText((Join-Path $rowDir 'gen_body.txt'), $gen.body, $utf8)
  Write-Host "GEN=$($gen.code) tok=$tok ms=$msGen"

  $unload = CurlPost '/api/model/unload' '{}' (Join-Path $rowDir 'unload.txt') 180
  Write-Host "UNLOAD=$($unload.code)"

  Write-Host "=== $($m.id) RELOAD ==="
  $sw.Restart()
  $reload = CurlPost '/api/model/load' $loadBody (Join-Path $rowDir 'reload.txt') $loadTimeout
  $msReload = $sw.ElapsedMilliseconds
  $reunload = CurlPost '/api/model/unload' '{}' (Join-Path $rowDir 'reunload.txt') 180
  Write-Host "RELOAD=$($reload.code) REUNLOAD=$($reunload.code) ms=$msReload"

  $alive = [int]((Get-ServerPid) -eq $spid)
  if ($alive -eq 0) { $av = 1 }

  $detail = ''
  if ($load.code -ne 200) { $detail += "LOAD_FAIL;" }
  if ($gen.code -ne 200) { $detail += "GEN_FAIL;" }
  if ($tok -le 0) { $detail += "TOK0;" }
  if ($unload.code -ne 200) { $detail += "UNLOAD_FAIL;" }
  if ($reload.code -ne 200) { $detail += "RELOAD_FAIL;" }
  if ($reunload.code -ne 200) { $detail += "REUNLOAD_FAIL;" }
  if ($alive -eq 0) { $detail += "DEAD;" }

  $rowPass = [int](($load.code -eq 200) -and ($gen.code -eq 200) -and ($tok -gt 0) -and
    ($unload.code -eq 200) -and ($reload.code -eq 200) -and ($reunload.code -eq 200) -and ($alive -eq 1))
  if ($rowPass -eq 1) { $passCount++ }

  $line = "$($m.id)`t$($m.name)`t$($load.code)`t$($info.code)`t$($gen.code)`t$tok`t$($unload.code)`t$($reload.code)`t$($reunload.code)`t$alive`t$msLoad`t$msGen`t$msReload`t$rowPass`t$detail"
  $line | Add-Content $tsv -Encoding ascii
  [IO.File]::WriteAllText((Join-Path $rowDir 'ROW.txt'), $line, $utf8)
  Write-Host $line
}

$spot2 = SpotCheck 'after_matrix'
$spot2.line | Set-Content "$gate\SPOT_END.txt"

$finalAlive = [int]((Get-ServerPid) -eq $spid)
# stop server after matrix
if ($finalAlive -eq 1) {
  Stop-Process -Id $spid -Force -EA SilentlyContinue
}

$gateOk = ($passCount -eq 10) -and ($av -eq 0) -and ($ollamaContact -eq 0) -and $spot1.ok -and $spot2.ok

@(
  "GATE=G3_IDE_R24_10MODEL_LIFECYCLE_001"
  "PASS_COUNT=$passCount/10"
  "ACCESS_VIOLATION=$av"
  "OLLAMA_CONTACT=$ollamaContact"
  "SPOT_BOOT_OK=$([int]$spot1.ok)"
  "SPOT_END_OK=$([int]$spot2.ok)"
  "PROCESS_FINAL_ALIVE_BEFORE_STOP=$finalAlive"
  "GATE_OK=$([int]$gateOk)"
  "R01_REOPENED=0"
  "LINK_REOPENED=0"
  "DUALSTICK_REOPENED=0"
  "PROMOTE=0"
  "TIP_CLIMB=HOLD"
  "ENDED=$(Get-Date -Format o)"
) | Set-Content "$gate\SUMMARY.txt"

Get-Content "$gate\SUMMARY.txt"
Get-Content $tsv
if (-not $gateOk) { exit 1 }
exit 0
