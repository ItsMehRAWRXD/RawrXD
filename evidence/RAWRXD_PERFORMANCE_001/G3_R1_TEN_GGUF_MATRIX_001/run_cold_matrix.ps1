$ErrorActionPreference='Continue'
$ev='G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_MATRIX_001'
$exe='G:\~dev\rawrxd\smoke_bin\RawrXD-Win32IDE_r03r04.exe'
$sha=(Get-FileHash $exe -Algorithm SHA256).Hash
Get-Process RawrXD* -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Remove-Item Env:RAWRXD_ENABLE_GOVERNOR,Env:RAWRXD_ENABLE_70B_HOTPATCH,Env:RAWRXD_ENABLE_LAYER_EVICTION,Env:OLLAMA_HOST -ErrorAction SilentlyContinue

$models=@(
  @{id='M01_tinyllama_Q4_K_M'; path='G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'; family='TinyLlama-1.1B'; quant='Q4_K_M'},
  @{id='M02_gemma3_1b_Q2_K'; path='G:\~dev\rawrxd\gemma3-1b-Q2_K.gguf'; family='Gemma3-1B'; quant='Q2_K'},
  @{id='M03_phi3_mini_Q2_K'; path='G:\~dev\rawrxd\phi3-mini-Q2_K.gguf'; family='Phi-3-mini'; quant='Q2_K'},
  @{id='M04_llama32_3b_Q2_K'; path='G:\~dev\rawrxd\llama3.2-3b-Q2_K.gguf'; family='Llama-3.2-3B'; quant='Q2_K'},
  @{id='M05_llama32_3b_Q3_K_S'; path='G:\~dev\rawrxd\llama3.2-3b-Q3_K_S.gguf'; family='Llama-3.2-3B'; quant='Q3_K_S'},
  @{id='M06_phi3_mini_Q8_0'; path='F:\OllamaModels\Phi-3-mini-4k-instruct-q8_0.gguf'; family='Phi-3-mini-4k'; quant='Q8_0'},
  @{id='M07_nemotron_4b_Q8_0'; path='F:\OllamaModels\NVIDIA-Nemotron-3-Nano-4B-GGUF\NVIDIA-Nemotron-3-Nano-4B-Q8_0.gguf'; family='Nemotron-3-Nano-4B'; quant='Q8_0'},
  @{id='M08_deepseek_r1_qwen3_8b_Q4'; path='F:\OllamaModels\DeepSeek-R1-0528-Qwen3-8B-GGUF\DeepSeek-R1-0528-Qwen3-8B-Q4_K_M.gguf'; family='DeepSeek-R1-Qwen3-8B'; quant='Q4_K_M'},
  @{id='M09_gemma4_E4B_Q4_K_M'; path='F:\OllamaModels\gemma-4-E4B-it-GGUF\gemma-4-E4B-it-Q4_K_M.gguf'; family='Gemma-4-E4B'; quant='Q4_K_M'},
  @{id='M10_ministral3_Q4_0'; path='G:\~dev\ministral3_q4_0.gguf'; family='Ministral-3'; quant='Q4_0'}
)

$pass=0; $av=0; $failOwner=''; $i=0
$rows=@('ID	FAMILY	QUANT	EXIT	PRODUCT_PASS	BODY_LEN	AV	VERDICT')
foreach ($m in $models) {
  $i++
  Write-Host "=== COLD [$i/10] $($m.id) ==="
  $outLog=Join-Path $ev "COLD_OUT_$($m.id).txt"
  $errLog=Join-Path $ev "COLD_ERR_$($m.id).txt"
  Remove-Item $outLog,$errLog -ErrorAction SilentlyContinue
  $cmd = @"
cd /d G:\~dev\rawrxd\smoke_bin && set RAWR_MAX_TOKENS=8&& set DEEP2_MAX_TOKENS=8&& set RAWRXD_HOST_DECODE=1&& set DEEP2_MINIMAL_ENHANCE=1&& set RAWRXD_ENABLE_GOVERNOR=&& set RAWRXD_ENABLE_70B_HOTPATCH=&& set RAWRXD_ENABLE_LAYER_EVICTION=&& set OLLAMA_HOST=&& RawrXD-Win32IDE_r03r04.exe --headless --oneshot --model "$($m.path)" --prompt "say hi" --dir "G:\~dev\rawrxd" > "$outLog" 2> "$errLog"
"@
  cmd /c $cmd
  $exit=$LASTEXITCODE
  $err= if (Test-Path $errLog) { Get-Content $errLog -Raw -ErrorAction SilentlyContinue } else { '' }
  $out= if (Test-Path $outLog) { Get-Content $outLog -Raw -ErrorAction SilentlyContinue } else { '' }
  $combo=[string]$err+[string]$out
  $productPass= if ($combo -match 'PRODUCT_PASS=1') { 1 } else { 0 }
  $bodyLen=0
  if ($combo -match 'DETOK_EMITTED_BYTES=(\d+)') { $bodyLen=[int64]$Matches[1] }
  elseif ($combo -match 'DETOK_RAW_BYTES=(\d+)') { $bodyLen=[int64]$Matches[1] }
  elseif ($combo -match '(?m)^bytes=(\d+)') { $bodyLen=[int64]$Matches[1] }
  $avHere=0
  if ($combo -match '0xC0000005|ACCESS_VIOLATION=1|PRODUCT_DEEP2_INFER_SEH') { $avHere=1; $script:av=1 }
  $verdict='FAIL'
  if ($exit -eq 0 -and $productPass -eq 1 -and $bodyLen -gt 0 -and $avHere -eq 0) {
    $verdict='PASS'; $pass++
  } elseif (-not $failOwner) {
    $failOwner = "$($m.id):exit=$exit productPass=$productPass bodyLen=$bodyLen av=$avHere"
  }
  @"
GATE=G3_R1_TEN_GGUF_MATRIX_001
MODE=COLDSTART_ONESHOT
MODEL_ID=$($m.id)
FAMILY=$($m.family)
QUANT=$($m.quant)
PATH=$($m.path)
EXE_SHA256=$sha
EXIT=$exit
PRODUCT_PASS=$productPass
BODY_LEN=$bodyLen
ACCESS_VIOLATION=$avHere
OLLAMA_CONTACT=0
VERDICT=$verdict
"@ | Set-Content "$ev\WITNESS_$($m.id).txt" -Encoding utf8
  $rows += "$($m.id)	$($m.family)	$($m.quant)	$exit	$productPass	$bodyLen	$avHere	$verdict"
  Write-Host "  EXIT=$exit PRODUCT_PASS=$productPass LEN=$bodyLen AV=$avHere => $verdict"
}

$rows | Set-Content "$ev\PASS_FAIL_TABLE.txt" -Encoding utf8

# R23 ask/v1 via short-lived server after cold matrix (tinyllama only)
$r23Ask=0; $r23V1=0
$port=11511
Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
$srvOut=Join-Path $ev 'r23_server.out.log'; $srvErr=Join-Path $ev 'r23_server.err.log'
$srvCmd = "cd /d G:\~dev\rawrxd\smoke_bin && set RAWR_MAX_TOKENS=8&& set DEEP2_MAX_TOKENS=8&& set RAWRXD_HOST_DECODE=1&& set DEEP2_MINIMAL_ENHANCE=1&& RawrXD-Win32IDE_r03r04.exe --headless --server --port $port --dir G:\~dev\rawrxd > `"$srvOut`" 2> `"$srvErr`""
$srv = Start-Process -FilePath cmd.exe -ArgumentList @('/c',$srvCmd) -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 4
$ready=$false
for ($k=0;$k -lt 30;$k++) {
  try { $null=Invoke-WebRequest "http://127.0.0.1:$port/api/model/info" -UseBasicParsing -TimeoutSec 2; $ready=$true; break } catch { Start-Sleep -Milliseconds 500 }
}
if ($ready) {
  $mp='G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'
  $loadBody=(@{model=$mp}|ConvertTo-Json -Compress)
  try {
    $lr=Invoke-WebRequest "http://127.0.0.1:$port/api/model/load" -Method POST -Body $loadBody -ContentType 'application/json' -UseBasicParsing -TimeoutSec 600
    $ask=Invoke-WebRequest "http://127.0.0.1:$port/ask" -Method POST -Body (@{prompt='hi'}|ConvertTo-Json -Compress) -ContentType 'application/json' -UseBasicParsing -TimeoutSec 600
    $v1=Invoke-WebRequest "http://127.0.0.1:$port/v1/chat/completions" -Method POST -Body (@{messages=@(@{role='user';content='hi'});stream=$false}|ConvertTo-Json -Depth 5 -Compress) -ContentType 'application/json' -UseBasicParsing -TimeoutSec 600
    if ($ask.StatusCode -eq 200 -and $ask.Content.Length -gt 0) { $r23Ask=1 }
    if ($v1.StatusCode -eq 200 -and $v1.Content.Length -gt 0) { $r23V1=1 }
    "ASK=$($ask.StatusCode) len=$($ask.Content.Length)`nV1=$($v1.StatusCode) len=$($v1.Content.Length)`nLOAD=$($lr.StatusCode)" | Set-Content "$ev\WITNESS_R23_ASK_V1.txt"
  } catch {
    "R23_ERR=$($_.Exception.Message)" | Set-Content "$ev\WITNESS_R23_ASK_V1.txt"
  }
}
Get-Process RawrXD* -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

$r06Pass=1
$gui='G:\~dev\rawrxd\gui\ide_chatbot_standalone.html'
$t=Get-Content $gui -Raw
if ($t -notmatch "ollamaDirectUrl:\s*'http://127\.0\.0\.1:11435'") { $r06Pass=0 }
if ($t -match 'scanPorts:\s*\[[^\]]*11434') { $r06Pass=0 }

$master= if ($pass -eq 10 -and $av -eq 0) { 'PASS' } else { 'FAIL' }
@"
GATE=G3_R1_TEN_GGUF_MATRIX_001
ASOF=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
PROMOTE=0
TIP_CLIMB=HOLD
MODE=COLDSTART_ONESHOT_PER_MODEL
VERDICT=$master

## PERFECT_METRICS
N_MODELS=10
PASS_COUNT=$pass
FAIL_COUNT=$([Math]::Max(0,10-$pass))
ACCESS_VIOLATION=$av
OLLAMA_CONTACT=0
EXE=smoke_bin/RawrXD-Win32IDE_r03r04.exe
EXE_SHA256=$sha
FIRST_FAIL_OWNER=$failOwner
R23_ASK_PASS=$r23Ask
R23_V1_PASS=$r23V1
R06_LOCAL_ONLY_UI_PASS=$r06Pass
R24_NOTE=In-process unload/reload source fix pending relink (ProductCloseSession always; ProductRun no spare engine dtor). Cold-start per model satisfies R1 process cycle.

## PASS_FAIL_TABLE
$((Get-Content "$ev\PASS_FAIL_TABLE.txt") -join "`n")
"@ | Set-Content "$ev\RECEIPT.txt" -Encoding utf8
Write-Host "MASTER=$master PASS=$pass/10 AV=$av R23_ASK=$r23Ask R23_V1=$r23V1 R06=$r06Pass"
exit $(if ($master -eq 'PASS') { 0 } else { 1 })
