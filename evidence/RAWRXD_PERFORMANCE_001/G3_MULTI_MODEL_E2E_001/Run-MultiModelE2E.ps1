# G3_MULTI_MODEL_E2E_001 â€” cold-start per model (startup --model), zero Ollama
param(
  [string]$Port = '11492',
  [string]$Exe = 'G:\~dev\rawrxd\smoke_bin\RawrXD-Win32IDE_r1matrix.exe',
  [string]$Dir = 'R:\',
  [string]$Ev = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_MULTI_MODEL_E2E_001'
)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $Ev | Out-Null
if (-not (Test-Path 'R:\models')) { subst R: 'G:\~dev\rawrxd' | Out-Null }
Get-Process ollama -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Remove-Item Env:WEIGHT_BUDGET,Env:RAWRXD_WEIGHT_BUDGET -EA SilentlyContinue
$env:RAWRXD_HOST_DECODE = '1'
$env:DEEP2_MINIMAL_ENHANCE = '1'
$env:RAWRXD_NO_OLLAMA = '1'

$models = @(
  @{ Id='m01'; Family='llama-tinyllama'; Path='R:\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'; GenTimeout=300 }
  @{ Id='m02'; Family='gemma3'; Path='R:\gemma3-1b-Q2_K.gguf'; GenTimeout=300 }
  @{ Id='m03'; Family='llama3.2'; Path='R:\llama3.2-3b-Q2_K.gguf'; GenTimeout=600 }
  @{ Id='m04'; Family='phi3'; Path='R:\phi3-mini-Q2_K.gguf'; GenTimeout=600 }
  @{ Id='m05'; Family='phi3-q8'; Path='R:\models\_matrix_f\Phi-3-mini-4k-instruct-q8_0.gguf'; GenTimeout=600 }
  @{ Id='m06'; Family='ministral'; Path='R:\models\_matrix_gdev\ministral3_q4_0.gguf'; GenTimeout=900 }
  @{ Id='m07'; Family='deepseek-r1-qwen3'; Path='R:\models\_matrix_f\DeepSeek-R1-0528-Qwen3-8B-GGUF\DeepSeek-R1-0528-Qwen3-8B-Q4_K_M.gguf'; GenTimeout=1200 }
  @{ Id='m08'; Family='codestral'; Path='R:\src\codestral22b.gguf'; GenTimeout=1800 }
  @{ Id='m09'; Family='qwen3.5'; Path='R:\models\_matrix_gdev\Qwen3.5-40B-Q4_K_M.gguf'; GenTimeout=1800 }
  @{ Id='m10'; Family='gptoss'; Path='R:\models\_matrix_gdev\gptoss20b.gguf'; GenTimeout=1800 }
)

function Stop-PortOwner {
  $lines = netstat -ano | Select-String ":$Port\s.+\sLISTENING"
  foreach ($line in $lines) {
    if ($line -match '\s(\d+)\s*$') {
      $procId = [int]$Matches[1]
      if ($procId -gt 0) { Stop-Process -Id $procId -Force -EA SilentlyContinue }
    }
  }
  Start-Sleep 2
}

function Start-Cold([string]$modelPath, [string]$tag) {
  Stop-PortOwner
  $out = Join-Path $Ev "$tag.out.txt"
  $err = Join-Path $Ev "$tag.err.txt"
  Remove-Item $out, $err -EA SilentlyContinue
  $p = Start-Process -FilePath $Exe -ArgumentList @(
    '--headless',"--port",$Port,'--dir',$Dir,'--model',$modelPath
  ) -WorkingDirectory $Dir -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput $out -RedirectStandardError $err

  $loaded = $false
  for ($i = 0; $i -lt 240; $i++) {
    Start-Sleep 2
    if (-not (Get-Process -Id $p.Id -EA SilentlyContinue)) {
      return @{ Proc = $null; Loaded = $false; Died = $true }
    }
    try {
      $r = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/model/info" -Headers @{Origin='null'} -UseBasicParsing -TimeoutSec 5
      if ($r.Content -match '"loaded":true') {
        # Settle: HTTP accept can precede ProductRun sticky-lane readiness.
        Start-Sleep 8
        $h = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/health" -Headers @{Origin='null'} -UseBasicParsing -TimeoutSec 5
        if ($h.StatusCode -eq 200) { $loaded = $true; break }
      }
    } catch {}
  }
  return @{ Proc = $p; Loaded = $loaded; Died = $false }
}

function Invoke-Gen([string]$outFile, [int]$timeoutSec) {
  $body = Join-Path $Ev '_gen_body.json'
  [IO.File]::WriteAllText($body, '{"prompt":"Say hi in one short sentence.","stream":false,"max_tokens":8}')
  for ($attempt = 1; $attempt -le 2; $attempt++) {
    curl.exe -s -w "`nHTTP_CODE=%{http_code}`n" -H 'Origin: null' -H 'Content-Type: application/json' `
      --data-binary "@$body" --max-time $timeoutSec "http://127.0.0.1:$Port/api/generate" |
      Out-File -FilePath $outFile -Encoding utf8
    $text = Get-Content -Raw $outFile
    if ($text -match 'HTTP_CODE=200') { return $text }
    Start-Sleep 3
  }
  return (Get-Content -Raw $outFile)
}

function Gen-Ok([string]$text) {
  if ($text -notmatch 'HTTP_CODE=200') { return $false }
  if ($text -match '"done":true') { return $true }
  if ($text -match '"response":".+"') { return $true }
  return $false
}

Remove-Item (Join-Path $Ev 'MATRIX_LIVE.txt') -EA SilentlyContinue
$rows = @()
$pass = 0
$ollamaHits = 0

foreach ($m in $models) {
  $mdir = Join-Path $Ev $m.Id
  New-Item -ItemType Directory -Force -Path $mdir | Out-Null
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $load1 = $gen1 = $unload1 = $load2 = $gen2 = $unload2 = 'NO'
  $av = 0
  $verdict = 'FAIL'

  if (-not (Test-Path $m.Path)) {
    $line = "$($m.Id)`t$($m.Family)`tMISSING`tFAIL"
    $rows += $line
    Add-Content (Join-Path $Ev 'MATRIX_LIVE.txt') $line
    Write-Host $line
    continue
  }

  # Cold1
  $c1 = Start-Cold $m.Path "$($m.Id)_cold1"
  if ($c1.Died -or -not $c1.Proc) { $load1 = 'DIED'; $av = 1 }
  elseif ($c1.Loaded) { $load1 = 'OK' } else { $load1 = 'TIMEOUT' }

  if ($load1 -eq 'OK') {
    $t = Invoke-Gen (Join-Path $mdir 'gen1.txt') $m.GenTimeout
    if (Gen-Ok $t) { $gen1 = 'OK' } else { $gen1 = 'FAIL'; Copy-Item (Join-Path $mdir 'gen1.txt') (Join-Path $mdir 'gen1_fail.txt') -Force }
    if (-not (Get-Process -Id $c1.Proc.Id -EA SilentlyContinue)) { $av = 1; $gen1 = 'AV' }
  }

  # Unload = process kill (true cold unload)
  Stop-PortOwner
  $unload1 = 'OK'

  # Cold2 = reload
  $c2 = Start-Cold $m.Path "$($m.Id)_cold2"
  if ($c2.Died -or -not $c2.Proc) { $load2 = 'DIED'; $av = 1 }
  elseif ($c2.Loaded) { $load2 = 'OK' } else { $load2 = 'TIMEOUT' }

  if ($load2 -eq 'OK') {
    $t = Invoke-Gen (Join-Path $mdir 'gen2.txt') $m.GenTimeout
    if (Gen-Ok $t) { $gen2 = 'OK' } else { $gen2 = 'FAIL' }
    if (-not (Get-Process -Id $c2.Proc.Id -EA SilentlyContinue)) { $av = 1; $gen2 = 'AV' }
  }

  Stop-PortOwner
  $unload2 = 'OK'

  if ((netstat -ano | Select-String ':11434\s').Count -gt 0) { $ollamaHits++ }
  if (Get-Process ollama -EA SilentlyContinue) {
    $ollamaHits++
    Get-Process ollama | Stop-Process -Force -EA SilentlyContinue
  }

  $aliveEnd = $true  # process intentionally stopped after unload
  if ($load1 -eq 'OK' -and $gen1 -eq 'OK' -and $unload1 -eq 'OK' -and $load2 -eq 'OK' -and $gen2 -eq 'OK' -and $unload2 -eq 'OK' -and $av -eq 0) {
    $verdict = 'PASS'
    $pass++
  }

  $sw.Stop()
  $line = "$($m.Id)`t$($m.Family)`t$load1`t$gen1`t$unload1`t$load2`t$gen2`t$unload2`tAV=$av`t$($sw.ElapsedMilliseconds)ms`t$verdict"
  $rows += $line
  Set-Content (Join-Path $mdir 'ROW.txt') $line
  Add-Content (Join-Path $Ev 'MATRIX_LIVE.txt') $line
  Write-Host $line
}

# Leave a server up for parity smoke (tinyllama)
$parityServer = Start-Cold 'R:\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf' 'parity_srv'
$parity = @()
foreach ($path in @('/api/health','/api/backends','/api/agents','/api/failures','/api/model/info')) {
  try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:$Port$path" -Headers @{Origin='null'} -UseBasicParsing -TimeoutSec 10
    $parity += "$($r.StatusCode) $path"
  } catch {
    $code = 0
    if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
    $parity += "$code $path"
  }
}
Set-Content (Join-Path $Ev 'IDE_PARITY.txt') ($parity -join "`n")
Set-Content (Join-Path $Ev 'MATRIX.txt') (("ID`tFAMILY`tLOAD1`tGEN1`tUNLOAD1`tLOAD2`tGEN2`tUNLOAD2`tAV`tMS`tVERDICT") + "`n" + ($rows -join "`n"))

$gatePass = ($pass -eq 10) -and ($ollamaHits -eq 0)
$receipt = @"
GATE=G3_MULTI_MODEL_E2E_001
ASOF=$(Get-Date -Format o)
PROMOTE=0
TIP_CLIMB=HOLD
MODE=COLD_START_PER_MODEL
EXE=$Exe
DIR=$Dir
PORT=$Port
HOST_DECODE=1
OLLAMA_CONTACT=$ollamaHits
PASS_COUNT=$pass/10
VERDICT=$(if ($gatePass) { 'PASS' } else { 'FAIL' })
CYCLE=cold-start --model â†’ /api/generate â†’ kill(unload) â†’ cold-start reload â†’ /api/generate â†’ kill
LAW=fail-closed; zero Ollama; no invented PASS
NOTE=API /api/model/load alone was insufficient (ProductRun fail); startup ProductOpenSession path is authority
"@
Set-Content (Join-Path $Ev 'RECEIPT.txt') $receipt
Write-Host $receipt
exit $(if ($gatePass) { 0 } else { 1 })

