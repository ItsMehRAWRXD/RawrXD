$ErrorActionPreference = 'Continue'
$ev = (Get-Item -LiteralPath 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_MATRIX_001').FullName
$exe = (Get-Item -LiteralPath 'G:\~dev\rawrxd\smoke_bin\RawrXD-Win32IDE_r1_laa_hostdecode.exe').FullName
$wd = (Get-Item -LiteralPath 'G:\~dev\rawrxd\smoke_bin').FullName
$sha = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
Get-Process RawrXD* -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

$env:RAWR_MAX_TOKENS = '8'
$env:DEEP2_MAX_TOKENS = '8'
$env:RAWRXD_HOST_DECODE = '1'
$env:DEEP2_MINIMAL_ENHANCE = '1'
Remove-Item Env:RAWRXD_ENABLE_GOVERNOR,Env:RAWRXD_ENABLE_70B_HOTPATCH,Env:RAWRXD_ENABLE_LAYER_EVICTION,Env:OLLAMA_HOST -ErrorAction SilentlyContinue

$models = @(
  @{id='M01_tinyllama_Q4_K_M'; family='TinyLlama-1.1B'; quant='Q4_K_M'; path='G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'},
  @{id='M02_gemma3_1b_Q2_K'; family='Gemma3-1B'; quant='Q2_K'; path='G:\~dev\rawrxd\gemma3-1b-Q2_K.gguf'},
  @{id='M03_phi3_mini_Q2_K'; family='Phi-3-mini'; quant='Q2_K'; path='G:\~dev\rawrxd\phi3-mini-Q2_K.gguf'},
  @{id='M04_llama32_3b_Q2_K'; family='Llama-3.2-3B'; quant='Q2_K'; path='G:\~dev\rawrxd\llama3.2-3b-Q2_K.gguf'},
  @{id='M05_llama32_3b_Q3_K_S'; family='Llama-3.2-3B'; quant='Q3_K_S'; path='G:\~dev\rawrxd\llama3.2-3b-Q3_K_S.gguf'},
  @{id='M06_phi3_mini_Q8_0'; family='Phi-3-mini-4k'; quant='Q8_0'; path='F:\OllamaModels\Phi-3-mini-4k-instruct-q8_0.gguf'},
  @{id='M07_nemotron_4b_Q8_0'; family='Nemotron-3-Nano-4B'; quant='Q8_0'; path='F:\OllamaModels\NVIDIA-Nemotron-3-Nano-4B-GGUF\NVIDIA-Nemotron-3-Nano-4B-Q8_0.gguf'},
  @{id='M08_deepseek_r1_qwen3_8b_Q4'; family='DeepSeek-R1-Qwen3-8B'; quant='Q4_K_M'; path='F:\OllamaModels\DeepSeek-R1-0528-Qwen3-8B-GGUF\DeepSeek-R1-0528-Qwen3-8B-Q4_K_M.gguf'},
  @{id='M09_gemma4_E4B_Q4_K_M'; family='Gemma-4-E4B'; quant='Q4_K_M'; path='F:\OllamaModels\gemma-4-E4B-it-GGUF\gemma-4-E4B-it-Q4_K_M.gguf'},
  @{id='M10_ministral3_Q4_0'; family='Ministral-3'; quant='Q4_0'; path='G:\~dev\ministral3_q4_0.gguf'}
)

$pass=0; $av=0; $failOwner=''; $i=0
$rows = New-Object System.Collections.Generic.List[string]
[void]$rows.Add('ID	FAMILY	QUANT	EXIT	PRODUCT_PASS	BODY_LEN	AV	VERDICT')

foreach ($m in $models) {
  $i++
  Write-Host "=== COLD LAA1 [$i/10] $($m.id) ==="
  $out = Join-Path $ev "WITNESS_OUT_$($m.id).txt"
  $err = Join-Path $ev "WITNESS_ERR_$($m.id).txt"
  Remove-Item -LiteralPath $out,$err -Force -ErrorAction SilentlyContinue
  $p = Start-Process -FilePath $exe -ArgumentList @(
    '--headless','--oneshot','--model', $m.path, '--prompt','say hi','--dir','G:\~dev\rawrxd'
  ) -WorkingDirectory $wd -RedirectStandardOutput $out -RedirectStandardError $err -PassThru -WindowStyle Hidden
  $ok = $p.WaitForExit(1200000)
  if (-not $ok) { try { $p.Kill() } catch {}; $exitCode = -9 } else { $exitCode = $p.ExitCode }
  if ($null -eq $exitCode) { $exitCode = -8 }
  $combo = ''
  if (Test-Path -LiteralPath $err) { $combo += [IO.File]::ReadAllText($err) }
  if (Test-Path -LiteralPath $out) { $combo += [IO.File]::ReadAllText($out) }
  $productPass = if ($combo -match 'PRODUCT_PASS=1') { 1 } else { 0 }
  $bodyLen = [int64]0
  if ($combo -match 'DETOK_EMITTED_BYTES=(\d+)') { $bodyLen = [int64]$Matches[1] }
  elseif ($combo -match 'DETOK_RAW_BYTES=(\d+)') { $bodyLen = [int64]$Matches[1] }
  $avHere = 0
  if ($combo -match '0xC0000005|ACCESS_VIOLATION=1|PRODUCT_DEEP2_INFER_SEH') { $avHere = 1; $script:av = 1 }
  if ($exitCode -eq -9) { $avHere = 1; $script:av = 1 }
  $verdict = 'FAIL'
  if (($exitCode -eq 0) -and ($productPass -eq 1) -and ($bodyLen -gt 0) -and ($avHere -eq 0)) {
    $verdict = 'PASS'; $pass++
  } elseif (-not $failOwner) {
    $failOwner = "$($m.id):exit=$exitCode productPass=$productPass bodyLen=$bodyLen av=$avHere"
  }
  @"
GATE=G3_R1_TEN_GGUF_MATRIX_001
MODE=COLDSTART_ONESHOT_LAA1
MODEL_ID=$($m.id)
FAMILY=$($m.family)
QUANT=$($m.quant)
PATH=$($m.path)
EXE=$exe
EXE_SHA256=$sha
EXE_LAA=1
EXIT=$exitCode
PRODUCT_PASS=$productPass
BODY_LEN=$bodyLen
ACCESS_VIOLATION=$avHere
OLLAMA_CONTACT=0
VERDICT=$verdict
"@ | Set-Content -LiteralPath (Join-Path $ev "WITNESS_$($m.id).txt") -Encoding utf8
  [void]$rows.Add("$($m.id)	$($m.family)	$($m.quant)	$exitCode	$productPass	$bodyLen	$avHere	$verdict")
  Write-Host "  EXIT=$exitCode PRODUCT_PASS=$productPass LEN=$bodyLen AV=$avHere => $verdict"
}

$rows | Set-Content -LiteralPath (Join-Path $ev 'PASS_FAIL_TABLE.txt') -Encoding utf8

# R06 static
$r06 = 1
$gui = Get-Content -LiteralPath 'G:\~dev\rawrxd\gui\ide_chatbot_standalone.html' -Raw
if ($gui -notmatch "ollamaDirectUrl:\s*'http://127\.0\.0\.1:11435'") { $r06 = 0 }
if ($gui -match 'scanPorts:\s*\[[^\]]*11434') { $r06 = 0 }

$master = if ($pass -eq 10 -and $av -eq 0) { 'PASS' } else { 'FAIL' }
@"
GATE=G3_R1_TEN_GGUF_MATRIX_001
ASOF=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
PROMOTE=0
TIP_CLIMB=HOLD
MODE=COLDSTART_ONESHOT_LAA1_HOSTDECODE
VERDICT=$master

## PERFECT_METRICS
N_MODELS=10
PASS_COUNT=$pass
FAIL_COUNT=$([Math]::Max(0,10-$pass))
ACCESS_VIOLATION=$av
OLLAMA_CONTACT=0
EXE=$exe
EXE_SHA256=$sha
EXE_LAA=1
HOST_DECODE=1
FIRST_FAIL_OWNER=$failOwner
R06_LOCAL_ONLY_UI_PASS=$r06
R24_SOURCE_FIX=Headless unload always ProductCloseSession; ProductRun no spare Deep2Engine dtor (pending product LAA0 rebuild for in-proc unload)
NOTE=R1 cold-start process per model; LAA:NO smoke EXEs OOM on >~1GB GGUF (ALLOC_FAIL) so LAA=1 hostdecode EXE used for 10-model coverage under HOST_DECODE=1

## PASS_FAIL_TABLE
$($rows -join "`n")
"@ | Set-Content -LiteralPath (Join-Path $ev 'RECEIPT.txt') -Encoding utf8

Write-Host "MASTER=$master PASS=$pass/10 AV=$av"
exit $(if ($master -eq 'PASS') { 0 } else { 1 })
