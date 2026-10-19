# R1 multi-model via rawr CLI (LAA ProductRun) — cold×2 per model, zero Ollama
$ErrorActionPreference = 'Continue'
$ev = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_MULTI_MODEL_E2E_001'
$rawr = 'G:\~dev\rawrxd\build-fd\bin\rawr.exe'
New-Item -ItemType Directory -Force -Path $ev | Out-Null

Get-Process ollama -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
$env:RAWRXD_HOST_DECODE = '1'
$env:DEEP2_MINIMAL_ENHANCE = '1'
$env:DEEP2_WEIGHT_BUDGET_MIB = '8192'
$env:RAWRXD_NO_OLLAMA = '1'

$models = @(
  @{ Id='m01'; Family='tinyllama'; Path='G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf' }
  @{ Id='m02'; Family='phi3-mini-q8'; Path='F:\OllamaModels\Phi-3-mini-4k-instruct-q8_0.gguf' }
  @{ Id='m03'; Family='nemotron-nano-4b'; Path='F:\OllamaModels\NVIDIA-Nemotron-3-Nano-4B-GGUF\NVIDIA-Nemotron-3-Nano-4B-Q8_0.gguf' }
  @{ Id='m04'; Family='deepseek-r1-qwen3-8b'; Path='F:\OllamaModels\DeepSeek-R1-0528-Qwen3-8B-GGUF\DeepSeek-R1-0528-Qwen3-8B-Q4_K_M.gguf' }
  @{ Id='m05'; Family='gemma4-e4b'; Path='F:\OllamaModels\gemma-4-E4B-it-GGUF\gemma-4-E4B-it-Q4_K_M.gguf' }
  @{ Id='m06'; Family='phi3-medium-14b'; Path='F:\OllamaModels\Phi-3-medium-128k-instruct-14B-Q4_K_M\Phi-3-medium-128k-instruct-Q4_K_M.gguf' }
  @{ Id='m07'; Family='codestral-22b'; Path='F:\OllamaModels\rawrxd_test_models\Codestral-22B-v0.1-Q4_K_M.gguf' }
  @{ Id='m08'; Family='qwen25-coder-14b'; Path='F:\OllamaModels\Qwen2.5-Coder-14B-Instruct-Q8_0\qwen2.5-coder-14b-instruct-q8_0.gguf' }
  @{ Id='m09'; Family='glm47-flash'; Path='F:\OllamaModels\GLM-4.7-Flash-GGUF\GLM-4.7-Flash-Q4_K_M.gguf' }
  @{ Id='m10'; Family='gemma4-31b'; Path='F:\OllamaModels\gemma-4-31B-it-GGUF\gemma-4-31B-it-Q4_K_M.gguf' }
)

function Invoke-RawrCycle([string]$path, [string]$tag) {
  $out = Join-Path $ev "$tag.out.txt"
  $err = Join-Path $ev "$tag.err.txt"
  Remove-Item $out, $err -EA SilentlyContinue
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $p = Start-Process -FilePath $rawr -ArgumentList @('run', $path, '--max-tokens', '8', '--prompt', 'Say hi in one short sentence.') `
    -WorkingDirectory 'G:\~dev\rawrxd' -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput $out -RedirectStandardError $err
  $okWait = $p.WaitForExit(7200000)  # 2h max per run
  if (-not $okWait) {
    Stop-Process -Id $p.Id -Force -EA SilentlyContinue
    return @{ Pass = $false; Av = 1; Tokens = 0; Ms = $sw.ElapsedMilliseconds; Detail = 'TIMEOUT' }
  }
  $sw.Stop()
  $errText = ''
  if (Test-Path $err) { $errText = Get-Content -Raw $err }
  $tokens = 0
  if ($errText -match 'GENERATED_TOKENS=(\d+)') { $tokens = [int]$Matches[1] }
  $productPass = ($errText -match 'PRODUCT_PASS=1')
  $allocFail = ($errText -match 'Failed to allocate')
  $av = ($p.ExitCode -eq -1073741819 -or $errText -match 'ACCESS_VIOLATION|C0000005')  # 0xC0000005
  $pass = $productPass -and ($tokens -gt 0) -and (-not $av)
  return @{
    Pass = $pass
    Av = [int]$av
    Tokens = $tokens
    Ms = $sw.ElapsedMilliseconds
    Exit = $p.ExitCode
    Detail = $(if ($pass) { 'OK' } elseif ($allocFail) { 'ALLOC_FAIL' } elseif ($av) { 'AV' } else { "EXIT=$($p.ExitCode) tok=$tokens" })
  }
}

Remove-Item (Join-Path $ev 'MATRIX_RAWR_LIVE.txt') -EA SilentlyContinue
$rows = @()
$passN = 0
$ollamaHits = 0

foreach ($m in $models) {
  $mdir = Join-Path $ev $m.Id
  New-Item -ItemType Directory -Force -Path $mdir | Out-Null
  if (-not (Test-Path $m.Path)) {
    $line = "$($m.Id)`t$($m.Family)`tMISSING`tFAIL"
    $rows += $line
    Add-Content (Join-Path $ev 'MATRIX_RAWR_LIVE.txt') $line
    Write-Host $line
    continue
  }

  Get-Process ollama -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
  if ((netstat -ano | Select-String ':11434\s').Count -gt 0) { $ollamaHits++ }

  $c1 = Invoke-RawrCycle $m.Path "$($m.Id)_run1"
  Start-Sleep 2
  $c2 = Invoke-RawrCycle $m.Path "$($m.Id)_run2"

  $verdict = 'FAIL'
  if ($c1.Pass -and $c2.Pass -and $c1.Av -eq 0 -and $c2.Av -eq 0) {
    $verdict = 'PASS'
    $passN++
  }

  $line = "$($m.Id)`t$($m.Family)`t$($c1.Detail)`tTOK1=$($c1.Tokens)`t$($c1.Ms)ms`t$($c2.Detail)`tTOK2=$($c2.Tokens)`t$($c2.Ms)ms`tAV=$($c1.Av+$c2.Av)`t$verdict"
  $rows += $line
  Set-Content (Join-Path $mdir 'ROW.txt') $line
  Add-Content (Join-Path $ev 'MATRIX_RAWR_LIVE.txt') $line
  Write-Host $line
}

# IDE Headless TinyLlama parity smoke (r1matrix LAA:NO floor)
$ideExe = 'G:\~dev\rawrxd\smoke_bin\RawrXD-Win32IDE_r1matrix.exe'
if (-not (Test-Path 'R:\models')) { subst R: 'G:\~dev\rawrxd' | Out-Null }
Get-Process | Where-Object { $_.ProcessName -match 'RawrXD' } | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
$ide = Start-Process $ideExe -ArgumentList '--headless','--port','11492','--dir','R:\','--model','R:\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf' -WorkingDirectory 'R:\' -PassThru -WindowStyle Hidden -RedirectStandardOutput "$ev\ide_parity.out.txt" -RedirectStandardError "$ev\ide_parity.err.txt"
Start-Sleep 12
$parity = @()
foreach ($path in @('/api/health','/api/backends','/api/agents','/api/failures')) {
  try {
    $r = Invoke-WebRequest "http://127.0.0.1:11492$path" -Headers @{Origin='null'} -UseBasicParsing -TimeoutSec 10
    $parity += "$($r.StatusCode) $path"
  } catch {
    $code = 0
    if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
    $parity += "$code $path"
  }
}
[IO.File]::WriteAllText("$ev\ide_gen.json", '{"prompt":"Say hi","stream":false,"max_tokens":8}')
curl.exe -s -w "`nHTTP=%{http_code}" -H 'Origin: null' -H 'Content-Type: application/json' --data-binary "@$ev\ide_gen.json" --max-time 180 http://127.0.0.1:11492/api/generate | Out-File "$ev\ide_gen.txt" -Encoding utf8
$ideGen = Get-Content -Raw "$ev\ide_gen.txt"
$ideGenOk = ($ideGen -match 'HTTP=200' -and $ideGen -match 'done')
$parity += $(if ($ideGenOk) { '200 /api/generate' } else { 'FAIL /api/generate' })
Set-Content (Join-Path $ev 'IDE_PARITY.txt') ($parity -join "`n")
Stop-Process -Id $ide.Id -Force -EA SilentlyContinue

Set-Content (Join-Path $ev 'MATRIX.txt') (("ID`tFAMILY`tRUN1`tTOK1`tMS1`tRUN2`tTOK2`tMS2`tAV`tVERDICT") + "`n" + ($rows -join "`n"))
$gatePass = ($passN -eq 10) -and ($ollamaHits -eq 0) -and $ideGenOk
$receipt = @"
GATE=G3_MULTI_MODEL_E2E_001
ASOF=$(Get-Date -Format o)
PROMOTE=0
TIP_CLIMB=HOLD
ENGINE=rawr.exe ProductRun (LAA) + IDE Headless TinyLlama parity
OLLAMA_CONTACT=$ollamaHits
PASS_COUNT=$passN/10
IDE_GENERATE_TINYLLAMA=$(if ($ideGenOk) { 'PASS' } else { 'FAIL' })
VERDICT=$(if ($gatePass) { 'PASS' } else { 'FAIL' })
CYCLE=cold rawr run → tokens → exit(unload) → cold rawr run → tokens
LAW=fail-closed; zero Ollama; no invented PASS
NOTE=Win32IDE LAA:NO PE cannot host >~1GB working sets (alloc fail); product multi-model authority is rawr/LAA ProductRun. IDE HTTP generate sealed for TinyLlama on r1matrix HOST_DECODE floor.
"@
Set-Content (Join-Path $ev 'RECEIPT.txt') $receipt
Write-Host $receipt
exit $(if ($gatePass) { 0 } else { 1 })
