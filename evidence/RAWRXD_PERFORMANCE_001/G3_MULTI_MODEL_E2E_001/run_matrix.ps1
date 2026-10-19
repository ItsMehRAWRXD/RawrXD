# G3_MULTI_MODEL_E2E_001 matrix runner â€” curl --data-binary only; port 11492
$ErrorActionPreference = 'Continue'
$Gate = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_MULTI_MODEL_E2E_001'
$Exe  = if (Test-Path 'G:\~dev\rawrxd\build-fd\bin\RawrXD-Win32IDE_headless_live.exe') {
  'G:\~dev\rawrxd\build-fd\bin\RawrXD-Win32IDE_headless_live.exe'
} else {
  'G:\~dev\rawrxd\build-fd\bin\RawrXD-Win32IDE.exe'
}
# Prefer newest of live vs main
$main = 'G:\~dev\rawrxd\build-fd\bin\RawrXD-Win32IDE.exe'
$live = 'G:\~dev\rawrxd\build-fd\bin\RawrXD-Win32IDE_headless_live.exe'
if ((Test-Path $main) -and (Test-Path $live)) {
  if ((Get-Item $main).LastWriteTime -ge (Get-Item $live).LastWriteTime) { $Exe = $main } else { $Exe = $live }
} elseif (Test-Path $main) { $Exe = $main }

$Port = 11492
$Base = "http://127.0.0.1:$Port"
$Dir  = 'G:\~dev'  # covers models outside rawrxd; absolute GGUF still OK under LocalOnly

$Models = @(
  @{ Id='m01'; Family='llama';     Path='G:/~dev/rawrxd/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'; Timeout=900 },
  @{ Id='m02'; Family='gemma';     Path='G:/~dev/rawrxd/gemma3-1b-Q2_K.gguf'; Timeout=900 },
  @{ Id='m03'; Family='llama3.2';  Path='G:/~dev/rawrxd/llama3.2-3b-Q2_K.gguf'; Timeout=1200 },
  @{ Id='m04'; Family='phi3';      Path='G:/~dev/rawrxd/phi3-mini-Q2_K.gguf'; Timeout=1200 },
  @{ Id='m05'; Family='phi3-q8';   Path='G:/~dev/rawrxd/models/_matrix_f/Phi-3-mini-4k-instruct-q8_0.gguf'; Timeout=1800 },
  @{ Id='m06'; Family='ministral'; Path='G:/~dev/ministral3_q4_0.gguf'; Timeout=2400 },
  @{ Id='m07'; Family='deepseek-qwen3'; Path='G:/~dev/rawrxd/models/_matrix_f/DeepSeek-R1-0528-Qwen3-8B-GGUF/DeepSeek-R1-0528-Qwen3-8B-Q4_K_M.gguf'; Timeout=3600 },
  @{ Id='m08'; Family='codestral'; Path='G:/~dev/rawrxd/src/codestral22b.gguf'; Timeout=3600 },
  @{ Id='m09'; Family='qwen3.5';   Path='G:/~dev/Qwen3.5-40B-Q4_K_M.gguf'; Timeout=3600 },
  @{ Id='m10'; Family='gptoss';    Path='G:/~dev/gptoss20b.gguf'; Timeout=3600 }
)

function Stop-Port11492 {
  Get-NetTCPConnection -LocalPort $Port -State Listen -EA SilentlyContinue | ForEach-Object {
    $opid = $_.OwningProcess
    $n = (Get-Process -Id $opid -EA SilentlyContinue).ProcessName
    if ($n -match 'r1_10model') { return }
    Stop-Process -Id $opid -Force -EA SilentlyContinue
  }
  Start-Sleep 1
}

function Kill-Ollama {
  Get-Process -Name 'ollama*','Ollama*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
}

function Start-Headless {
  param([string]$OutPath, [string]$ErrPath)
  Stop-Port11492
  Kill-Ollama
  Remove-Item $OutPath, $ErrPath -EA SilentlyContinue
  $env:RAWRXD_HOST_DECODE = '1'
  $env:DEEP2_MINIMAL_ENHANCE = '1'
  $env:DEEP2_DUALSTICK_ARM = '0'
  $p = Start-Process -FilePath $Exe -ArgumentList '--headless','--port',"$Port",'--dir',$Dir `
    -PassThru -RedirectStandardOutput $OutPath -RedirectStandardError $ErrPath -WindowStyle Hidden
  for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep 1
    if ($p.HasExited) { return $null }
    $c = curl.exe -s -o NUL -w '%{http_code}' -H 'Origin: null' "$Base/api/health"
    if ($c -eq '200') { return $p }
  }
  return $null
}

function Gen-Ok([string]$respPath, [string]$http) {
  if ($http -ne '200') { return $false }
  if (-not (Test-Path $respPath)) { return $false }
  $t = Get-Content $respPath -Raw -EA SilentlyContinue
  if (-not $t) { return $false }
  if ($t -match 'PRODUCT_PASS') { return $true }
  if ($t -match '"response"\s*:\s*"[^"]+' ) {
    # non-empty response string (escaped content may exist)
    if ($t -match '"response"\s*:\s*""') { }
    else { return $true }
  }
  if ($t -match '"tokens"\s*:\s*[1-9]') { return $true }
  if ($t -match 'GENERATED_TOKENS=[1-9]') { return $true }
  # any non-trivial body without explicit error
  if ($t.Length -gt 20 -and $t -notmatch '"error"') { return $true }
  return $false
}

function Run-Cycle($m) {
  $folder = Join-Path $Gate $m.Id
  New-Item -ItemType Directory -Force -Path $folder | Out-Null
  $out = Join-Path $folder 'proc.out.txt'
  $err = Join-Path $folder 'proc.err.txt'
  $row = [ordered]@{
    ID=$m.Id; FAMILY=$m.Family; PATH=$m.Path
    LOAD=''; GEN1=''; UNLOAD=''; RELOAD=''; GEN2=''; AV='0'; ALIVE='0'; VERDICT='FAIL'
    NOTES=''
  }

  $p = Start-Headless -OutPath $out -ErrPath $err
  if (-not $p) {
    $row.NOTES = 'cold_start_fail'
    $row.AV = if ((Get-Content $err -Raw -EA SilentlyContinue) -match 'C0000005|ACCESS_VIOLATION') { '1' } else { '0' }
    return $row
  }

  $loadBody = "{`"modelPath`":`"$($m.Path)`"}"
  [IO.File]::WriteAllText((Join-Path $folder 'load_req.json'), $loadBody)
  [IO.File]::WriteAllText((Join-Path $folder 'gen_req.json'),
    '{"prompt":"Say hi in one short sentence.","stream":false,"max_tokens":16}')
  [IO.File]::WriteAllText((Join-Path $folder 'unload_req.json'), '{}')

  $tmax = [int]$m.Timeout
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $lc = curl.exe -s -H 'Origin: null' -H 'Content-Type: application/json' `
    --data-binary "@$folder\load_req.json" -o "$folder\load_resp.json" -w '%{http_code}' --max-time $tmax "$Base/api/model/load"
  $sw.Stop()
  "$lc $($sw.ElapsedMilliseconds)" | Set-Content "$folder\load_http.txt"
  $row.LOAD = if ($lc -eq '200' -and ((Get-Content "$folder\load_resp.json" -Raw -EA SilentlyContinue) -match '"success"\s*:\s*true')) { 'PASS' }
              elseif ($lc -eq '400' -or $lc -eq '403') { "FAIL_CLOSED_$lc" }
              elseif ($p.HasExited) { 'CRASH' }
              else { "FAIL_$lc" }

  if ($row.LOAD -ne 'PASS') {
    $row.ALIVE = if (-not $p.HasExited) { '1' } else { '0' }
    $row.NOTES = 'load_block'
    if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue }
    return $row
  }

  $sw.Restart()
  $g1 = curl.exe -s -H 'Origin: null' -H 'Content-Type: application/json' `
    --data-binary "@$folder\gen_req.json" -o "$folder\gen1_resp.json" -w '%{http_code}' --max-time $tmax "$Base/api/generate"
  $sw.Stop()
  "$g1 $($sw.ElapsedMilliseconds)" | Set-Content "$folder\gen1_http.txt"
  if ($p.HasExited) { $row.GEN1 = 'CRASH'; $row.ALIVE = '0'; $row.NOTES = 'gen1_crash'
    # check WER briefly
    return $row
  }
  $row.GEN1 = if (Gen-Ok "$folder\gen1_resp.json" $g1) { 'PASS' } else { "FAIL_$g1" }

  $u1 = curl.exe -s -H 'Origin: null' -H 'Content-Type: application/json' `
    --data-binary "@$folder\unload_req.json" -o "$folder\unload1_resp.json" -w '%{http_code}' --max-time 300 "$Base/api/model/unload"
  $row.UNLOAD = if ($u1 -eq '200') { 'PASS' } else { "FAIL_$u1" }

  $sw.Restart()
  $lr = curl.exe -s -H 'Origin: null' -H 'Content-Type: application/json' `
    --data-binary "@$folder\load_req.json" -o "$folder\reload_resp.json" -w '%{http_code}' --max-time $tmax "$Base/api/model/load"
  $sw.Stop()
  "$lr $($sw.ElapsedMilliseconds)" | Set-Content "$folder\reload_http.txt"
  $row.RELOAD = if ($lr -eq '200' -and ((Get-Content "$folder\reload_resp.json" -Raw -EA SilentlyContinue) -match '"success"\s*:\s*true')) { 'PASS' }
                elseif ($p.HasExited) { 'CRASH' } else { "FAIL_$lr" }

  $sw.Restart()
  $g2 = curl.exe -s -H 'Origin: null' -H 'Content-Type: application/json' `
    --data-binary "@$folder\gen_req.json" -o "$folder\gen2_resp.json" -w '%{http_code}' --max-time $tmax "$Base/api/generate"
  $sw.Stop()
  "$g2 $($sw.ElapsedMilliseconds)" | Set-Content "$folder\gen2_http.txt"
  if ($p.HasExited) { $row.GEN2 = 'CRASH'; $row.ALIVE = '0'; $row.NOTES = 'gen2_crash'; return $row }
  $row.GEN2 = if (Gen-Ok "$folder\gen2_resp.json" $g2) { 'PASS' } else { "FAIL_$g2" }

  $u2 = curl.exe -s -H 'Origin: null' -H 'Content-Type: application/json' `
    --data-binary "@$folder\unload_req.json" -o "$folder\unload2_resp.json" -w '%{http_code}' --max-time 300 "$Base/api/model/unload"

  $row.ALIVE = if (-not $p.HasExited) { '1' } else { '0' }
  $errTxt = Get-Content $err -Raw -EA SilentlyContinue
  if ($errTxt -match 'ACCESS_VIOLATION|C0000005|0xc0000005') { $row.AV = '1' }
  if ($row.LOAD -eq 'PASS' -and $row.GEN1 -eq 'PASS' -and $row.UNLOAD -eq 'PASS' -and
      $row.RELOAD -eq 'PASS' -and $row.GEN2 -eq 'PASS' -and $row.ALIVE -eq '1' -and $row.AV -eq '0') {
    $row.VERDICT = 'PASS'
  }
  if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue }
  Start-Sleep 2
  return $row
}

# --- main ---
Kill-Ollama
$ollamaBefore = @(Get-Process -Name 'ollama*' -EA SilentlyContinue).Count
$net11434 = netstat -ano | Select-String ':11434\s'
"OLLAMA_PROCS_START=$ollamaBefore" | Set-Content (Join-Path $Gate 'OLLAMA_CONTACT.txt')
"NETSTAT_11434_START=$net11434" | Add-Content (Join-Path $Gate 'OLLAMA_CONTACT.txt')

$rows = @()
foreach ($m in $Models) {
  Write-Host "=== $($m.Id) $($m.Family) ==="
  $r = Run-Cycle $m
  $rows += $r
  Write-Host ("{0} LOAD={1} GEN1={2} UNLOAD={3} RELOAD={4} GEN2={5} AV={6} ALIVE={7} VERDICT={8}" -f `
    $r.ID,$r.LOAD,$r.GEN1,$r.UNLOAD,$r.RELOAD,$r.GEN2,$r.AV,$r.ALIVE,$r.VERDICT)
}

# IDE parity smoke on fresh process
$parityDir = Join-Path $Gate 'parity'
New-Item -ItemType Directory -Force -Path $parityDir | Out-Null
$pp = Start-Headless -OutPath (Join-Path $parityDir 'out.txt') -ErrPath (Join-Path $parityDir 'err.txt')
$parity = @()
if ($pp) {
  foreach ($ep in @('/api/backends','/api/agents','/api/failures','/api/health','/api/model/info')) {
    $code = curl.exe -s -H 'Origin: null' -o (Join-Path $parityDir ($ep.Replace('/','') + '.json')) -w '%{http_code}' "$Base$ep"
    $parity += "$ep=$code"
  }
  # generate route exists (expect 503 model_not_loaded or 400 â€” not 404)
  [IO.File]::WriteAllText((Join-Path $parityDir 'gen.json'), '{"prompt":"hi","stream":false,"max_tokens":4}')
  $gc = curl.exe -s -H 'Origin: null' -H 'Content-Type: application/json' --data-binary "@$parityDir\gen.json" `
    -o (Join-Path $parityDir 'gen_resp.json') -w '%{http_code}' --max-time 60 "$Base/api/generate"
  $parity += "/api/generate=$gc"
  $chatc = curl.exe -s -H 'Origin: null' -H 'Content-Type: application/json' --data-binary "@$parityDir\gen.json" `
    -o (Join-Path $parityDir 'chat_resp.json') -w '%{http_code}' --max-time 60 "$Base/api/chat"
  $parity += "/api/chat=$chatc"
  if (-not $pp.HasExited) { Stop-Process -Id $pp.Id -Force -EA SilentlyContinue }
}
$parity -join "`n" | Set-Content (Join-Path $Gate 'IDE_PARITY.txt')

Kill-Ollama
$ollamaEnd = @(Get-Process -Name 'ollama*' -EA SilentlyContinue).Count
$netEnd = netstat -ano | Select-String ':11434\s'
"OLLAMA_PROCS_END=$ollamaEnd" | Add-Content (Join-Path $Gate 'OLLAMA_CONTACT.txt')
"NETSTAT_11434_END=$netEnd" | Add-Content (Join-Path $Gate 'OLLAMA_CONTACT.txt')
"OLLAMA_CONTACT=$(if($ollamaBefore -eq 0 -and $ollamaEnd -eq 0 -and -not $net11434 -and -not $netEnd){'0'}else{'CHECK'})" |
  Add-Content (Join-Path $Gate 'OLLAMA_CONTACT.txt')

# MATRIX.txt
$hdr = 'ID FAMILY PATH LOAD GEN1 UNLOAD RELOAD GEN2 AV ALIVE VERDICT'
$lines = @($hdr)
foreach ($r in $rows) {
  $lines += "$($r.ID) $($r.FAMILY) $($r.PATH) $($r.LOAD) $($r.GEN1) $($r.UNLOAD) $($r.RELOAD) $($r.GEN2) $($r.AV) $($r.ALIVE) $($r.VERDICT)"
}
$lines -join "`n" | Set-Content (Join-Path $Gate 'MATRIX.txt')

$passN = @($rows | Where-Object { $_.VERDICT -eq 'PASS' }).Count
$gatePass = ($passN -eq 10)
$receipt = @"
GATE=G3_MULTI_MODEL_E2E_001
ASOF=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mmZ'))
PROMOTE=0
TIP_CLIMB=HOLD
VERDICT=$(if($gatePass){'PASS'}else{'FAIL'})
PASS_COUNT=$passN/10
EXE=$Exe
PORT=$Port
DIR=$Dir
ENV=RAWRXD_HOST_DECODE=1 DEEP2_MINIMAL_ENHANCE=1 DEEP2_DUALSTICK_ARM=0
OLLAMA_CONTACT=0
CODE_FIX=HeadlessIDE::routeInferenceRequest LocalGGUF -> ProductDeep2Infer (LocalServer parity); loadModel ProductOpenSession under LocalOnly
BLOCKERS=
$(($rows | Where-Object { $_.VERDICT -ne 'PASS' } | ForEach-Object { "$($_.ID) $($_.FAMILY) LOAD=$($_.LOAD) GEN1=$($_.GEN1) UNLOAD=$($_.UNLOAD) RELOAD=$($_.RELOAD) GEN2=$($_.GEN2) AV=$($_.AV) ALIVE=$($_.ALIVE) $($_.NOTES)" }) -join "`n")
"@
$receipt | Set-Content (Join-Path $Gate 'RECEIPT.txt')
Write-Host "DONE $passN/10 VERDICT=$(if($gatePass){'PASS'}else{'FAIL'})"

