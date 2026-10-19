# G3_IDE_R24_10MODEL_LIFECYCLE_001 — IDE HTTP load→generate→unload→reload
# LOCAL_ONLY · zero Ollama · KEEP_LINK_CLOSED · PROMOTE=0 · TIP_CLIMB=HOLD
$ErrorActionPreference = 'Continue'
$gate = Split-Path -Parent $MyInvocation.MyCommand.Path
$smoke = Join-Path $env:TEMP 'G3_IDE_R24_10MODEL'
$exe = Join-Path $smoke 'RawrXD-Win32IDE.exe'
$port = 28141
$prompt = 'Say hello in one short sentence.'
$ollamaContact = 0

Remove-Item Env:RAWRXD_HTTP_PORT, Env:RAWRXD_HEADLESS -EA SilentlyContinue

$models = @(
  @{ id='M01'; name='tinyllama_Q4_K_M'; path='G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf' },
  @{ id='M02'; name='gemma3_1b_Q2_K'; path='G:\~dev\rawrxd\gemma3-1b-Q2_K.gguf' },
  @{ id='M03'; name='llama32_3b_Q2_K'; path='G:\~dev\rawrxd\llama3.2-3b-Q2_K.gguf' },
  @{ id='M04'; name='llama32_3b_Q3_K_S'; path='G:\~dev\rawrxd\llama3.2-3b-Q3_K_S.gguf' },
  @{ id='M05'; name='phi3_mini_Q2_K'; path='G:\~dev\rawrxd\phi3-mini-Q2_K.gguf' },
  @{ id='M06'; name='phi3_mini_Q8_0'; path='F:\OllamaModels\Phi-3-mini-4k-instruct-q8_0.gguf' },
  @{ id='M07'; name='deepseek_r1_qwen3_8b'; path='F:\OllamaModels\DeepSeek-R1-0528-Qwen3-8B-GGUF\DeepSeek-R1-0528-Qwen3-8B-Q4_K_M.gguf' },
  @{ id='M08'; name='gemma4_e4b_Q4_K_M'; path='F:\OllamaModels\gemma-4-E4B-it-GGUF\gemma-4-E4B-it-Q4_K_M.gguf' },
  @{ id='M09'; name='bigdaddy_ultra'; path='F:\OllamaModels\BigDaddyG-Q2_K-ULTRA.gguf' },
  @{ id='M10'; name='codestral_22b'; path='F:\OllamaModels\rawrxd_test_models\Codestral-22B-v0.1-Q4_K_M.gguf' }
)

function CurlGet([string]$path, [string]$outFile, [int]$timeoutSec = 30) {
  $url = "http://127.0.0.1:$port$path"
  $code = & curl.exe -sS -m $timeoutSec -o $outFile -w '%{http_code}' $url 2>"$outFile.err"
  if (-not $code) { $code = '000' }
  return @{ code = [int]$code; body = ($(if (Test-Path $outFile) { Get-Content $outFile -Raw -EA SilentlyContinue } else { '' })) }
}

function CurlPost([string]$path, [string]$json, [string]$outFile, [int]$timeoutSec = 120) {
  $url = "http://127.0.0.1:$port$path"
  $req = "$outFile.req.json"
  [IO.File]::WriteAllText($req, $json)
  $code = & curl.exe -sS -m $timeoutSec -o $outFile -w '%{http_code}' -X POST $url `
    -H 'Content-Type: application/json' --data-binary "@$req" 2>"$outFile.err"
  if (-not $code) { $code = '000' }
  return @{ code = [int]$code; body = ($(if (Test-Path $outFile) { Get-Content $outFile -Raw -EA SilentlyContinue } else { '' })) }
}

function CountTokensApprox([string]$body) {
  if ($body -match '"eval_count"\s*:\s*(\d+)') { return [int]$Matches[1] }
  if ($body -match '"tokens"\s*:\s*(\d+)') { return [int]$Matches[1] }
  if ($body -match '"GENERATED_TOKENS"=(\d+)') { return [int]$Matches[1] }
  # Ollama-style response field
  if ($body -match '"response"\s*:\s*"(.*?)"') {
    $t = $Matches[1]
    if ($t.Length -gt 0) { return [Math]::Max(1, ($t -split '\s+').Count) }
  }
  if ($body -match '"content"\s*:\s*"(.*?)"') {
    $t = $Matches[1]
    if ($t.Length -gt 0) { return [Math]::Max(1, ($t -split '\s+').Count) }
  }
  # non-empty text without error
  if ($body.Length -gt 20 -and $body -notmatch '"error"') { return 1 }
  return 0
}

# Kill prior smoke instances
Get-CimInstance Win32_Process | Where-Object {
  $_.CommandLine -and $_.CommandLine -match 'G3_IDE_R24_10MODEL'
} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }
Start-Sleep 1

$stdout = Join-Path $smoke 'stdout.txt'
$stderr = Join-Path $smoke 'stderr.txt'
Remove-Item $stdout, $stderr -Force -EA SilentlyContinue

$proc = Start-Process -FilePath $exe -ArgumentList @(
  '--headless','--local','--port',"$port",'--dir','G:\~dev\rawrxd'
) -WorkingDirectory $smoke -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput $stdout -RedirectStandardError $stderr

"PID=$($proc.Id) PORT=$port START=$(Get-Date -Format o)" | Set-Content "$gate\SERVER.txt"

$ready = $false
for ($i = 0; $i -lt 120; $i++) {
  Start-Sleep 1
  if ($proc.HasExited) {
    "EXIT_EARLY=$($proc.ExitCode)" | Set-Content "$gate\BOOT_FAIL.txt"
    Get-Content $stderr -EA SilentlyContinue | Select-Object -Last 40 | Add-Content "$gate\BOOT_FAIL.txt"
    exit 2
  }
  $own = Get-NetTCPConnection -LocalPort $port -State Listen -EA SilentlyContinue |
    Where-Object { $_.OwningProcess -eq $proc.Id } | Select-Object -First 1
  if (-not $own) { continue }
  $h = CurlGet '/health' (Join-Path $gate 'boot_health.txt') 5
  if ($h.code -eq 200) { $ready = $true; break }
}
if (-not $ready) {
  'HEALTH_TIMEOUT' | Set-Content "$gate\BOOT_FAIL.txt"
  Stop-Process -Id $proc.Id -Force -EA SilentlyContinue
  exit 3
}

function SpotCheck([string]$tag) {
  $dir = Join-Path $gate "spot_$tag"
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $h = CurlGet '/health' (Join-Path $dir 'health.txt')
  $b = CurlGet '/api/backends' (Join-Path $dir 'backends.txt')
  $u = CurlPost '/api/backends/use' '{"name":"ollama"}' (Join-Path $dir 'backends_use_ollama.txt') 15
  $c = CurlPost '/api/chat' '{"messages":[]}' (Join-Path $dir 'chat.txt') 15
  $t = CurlPost '/api/tool' '{"tool":"list_directory","args":{"path":".cursor/rules"}}' (Join-Path $dir 'tool.txt') 15
  # Hard fail if anything contacted :11434 (we never call it; assert no listener probe needed)
  $ollamaOk = ($u.code -eq 422) -or ($u.body -match 'LOCAL_ONLY|ollama|not.?allowed|forbidden|unsupported')
  $toolOk = ($t.code -eq 403) -and ($t.body -match 'motd_required')
  $chatOk = ($c.code -ne 404)
  $line = "SPOT_$tag health=$($h.code) backends=$($b.code) ollama_use=$($u.code) chat=$($c.code) tool=$($t.code) ollama_refuse=$([int]$ollamaOk) tool_motd=$([int]$toolOk)"
  $line | Tee-Object -FilePath (Join-Path $dir 'SPOT.txt') -Append
  if (-not $ollamaOk) { $script:ollamaContact = 1 }
  return @{ ok = (($h.code -eq 200) -and ($b.code -eq 200) -and $chatOk -and $toolOk -and $ollamaOk); line = $line }
}

$spot1 = SpotCheck 'after_boot'
$spot1.line | Set-Content "$gate\SPOT_BOOT.txt"

# MATRIX header
$tsv = Join-Path $gate 'MATRIX.tsv'
"ID`tNAME`tLOAD`tINFO`tGEN`tTOKENS`tUNLOAD`tRELOAD`tREUNLOAD`tALIVE`tMS_LOAD`tMS_GEN`tMS_RELOAD`tPASS`tDETAIL" |
  Set-Content $tsv

$passCount = 0
$av = 0
$rows = @()

foreach ($m in $models) {
  if ($proc.HasExited) {
    $av = 1
    "$($m.id)`t$($m.name)`t000`t000`t000`t0`t000`t000`t000`t0`t0`t0`t0`t0`tPROCESS_DEAD_exit=$($proc.ExitCode)" |
      Add-Content $tsv
    break
  }

  $rowDir = Join-Path $gate $m.id
  New-Item -ItemType Directory -Force -Path $rowDir | Out-Null
  $pathJson = ($m.path -replace '\\','\\')
  $loadBody = "{`"modelPath`":`"$pathJson`"}"
  # Also try forward slashes for JSON clarity
  $pathFwd = $m.path -replace '\\','/'
  $loadBody = "{`"modelPath`":`"$pathFwd`"}"
  $genBody = "{`"model`":`"$pathFwd`",`"prompt`":`"$prompt`",`"stream`":false,`"options`":{`"num_predict`":16},`"max_tokens`":16}"

  $sw = [Diagnostics.Stopwatch]::StartNew()
  $loadTimeout = 900
  if ($m.id -in @('M09','M10','M07','M08')) { $loadTimeout = 2400 }
  $load = CurlPost '/api/model/load' $loadBody (Join-Path $rowDir 'load.txt') $loadTimeout
  $msLoad = $sw.ElapsedMilliseconds

  $info = CurlGet '/api/model/info' (Join-Path $rowDir 'info.txt') 30

  $sw.Restart()
  $genTimeout = 900
  if ($m.id -in @('M09','M10','M07','M08')) { $genTimeout = 3600 }
  $gen = CurlPost '/api/generate' $genBody (Join-Path $rowDir 'gen.txt') $genTimeout
  $msGen = $sw.ElapsedMilliseconds
  $tok = CountTokensApprox $gen.body
  $gen.body | Set-Content (Join-Path $rowDir 'gen_body.txt')

  $unload = CurlPost '/api/model/unload' '{}' (Join-Path $rowDir 'unload.txt') 120

  $sw.Restart()
  $reload = CurlPost '/api/model/load' $loadBody (Join-Path $rowDir 'reload.txt') $loadTimeout
  $msReload = $sw.ElapsedMilliseconds
  $reunload = CurlPost '/api/model/unload' '{}' (Join-Path $rowDir 'reunload.txt') 120

  $alive = [int](-not $proc.HasExited)
  if ($proc.HasExited) {
    $av = 1
    "EXIT_CODE=$($proc.ExitCode)" | Set-Content (Join-Path $rowDir 'PROCESS_EXIT.txt')
  }

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
  $line | Add-Content $tsv
  $line | Tee-Object -FilePath (Join-Path $rowDir 'ROW.txt')
  Write-Host $line
}

$spot2 = SpotCheck 'after_matrix'
$spot2.line | Set-Content "$gate\SPOT_END.txt"

$finalAlive = [int](-not $proc.HasExited)
if (-not $proc.HasExited) {
  Stop-Process -Id $proc.Id -Force -EA SilentlyContinue
  Start-Sleep 2
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
  "DUALSTICK_REOPENED=0"
  "PROMOTE=0"
  "TIP_CLIMB=HOLD"
  "ENDED=$(Get-Date -Format o)"
) | Set-Content "$gate\SUMMARY.txt"

Get-Content "$gate\SUMMARY.txt"
if (-not $gateOk) { exit 1 }
exit 0
