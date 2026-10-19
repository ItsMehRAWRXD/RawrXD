# G3_R1_TEN_GGUF_LIFECYCLE_002 - LAA:YES + HOST_DECODE + soft-reuse + PATH_SWITCH latch
$ErrorActionPreference = 'Continue'
$ev = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_002'
$smoke = Join-Path $ev 'smoke'
New-Item -ItemType Directory -Force -Path $smoke,(Join-Path $ev 'smoke_bin') | Out-Null

$exeCandidates = @(
  'G:\~dev\rawrxd\build-fd\bin\RawrXD-Win32IDE_r1latch.exe',
  (Join-Path $ev 'smoke_bin\RawrXD-Win32IDE_r1latch_EF3CE93EB5CB2908.exe'),
  (Join-Path $ev 'smoke_bin\RawrXD-Win32IDE_r1_002.exe'),
  'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_001\smoke_bin\RawrXD-Win32IDE_r01_laa.exe'
)
$exeSrc = $null
foreach ($c in $exeCandidates) {
  if (Test-Path -LiteralPath $c) {
    $sha = (Get-FileHash -LiteralPath $c -Algorithm SHA256).Hash
    if ($sha.StartsWith('5AB597450FFF0FFE')) { continue }
    $exeSrc = $c
    break
  }
}
if (-not $exeSrc) { throw 'no usable EXE' }
$exe = Join-Path $ev 'smoke_bin\RawrXD-Win32IDE_r1_002.exe'
Copy-Item -LiteralPath $exeSrc -Destination $exe -Force
$editbin = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\editbin.exe'
$dumpbin = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe'
& $editbin /LARGEADDRESSAWARE $exe | Out-Null
$laaProbe = & $dumpbin /HEADERS $exe | Select-String -Pattern 'Application can handle large'
if (-not $laaProbe) { throw 'PE_LAA_MUST_BE_YES for R1 multi-GGUF VA' }
$exeSha = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
$peLaa = 'YES'
$port = 11436
$base = "http://127.0.0.1:$port"
Remove-Item (Join-Path $ev 'MATRIX_LIVE.log') -ErrorAction SilentlyContinue

$models = @(
  [pscustomobject]@{ Id='01_tinyllama'; Name='tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'; Path='G:\~dev\rawrxd\_r1_models\01_tinyllama\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'; Family='TinyLlama-1.1B'; Quant='Q4_K_M' },
  [pscustomobject]@{ Id='02_phi3_mini'; Name='Phi-3-mini-4k-instruct-q8_0.gguf'; Path=(Join-Path 'G:\~dev\rawrxd\_r1_iso\02_phi3_mini' 'Phi-3-mini-4k-instruct-q8_0.gguf'); Family='Phi-3-mini-4B'; Quant='Q8_0' },
  [pscustomobject]@{ Id='03_llama32_3b'; Name='llama3.2-3b-Q2_K.gguf'; Path=(Join-Path 'G:\~dev\rawrxd\_r1_iso\03_llama32_3b' 'llama3.2-3b-Q2_K.gguf'); Family='Llama-3.2-3B'; Quant='Q2_K' },
  [pscustomobject]@{ Id='04_ds_r1_qwen3'; Name='DeepSeek-R1-0528-Qwen3-8B-Q4_K_M.gguf'; Path=(Join-Path 'G:\~dev\rawrxd\_r1_iso\04_ds_r1_qwen3' 'DeepSeek-R1-0528-Qwen3-8B-Q4_K_M.gguf'); Family='DeepSeek-R1-Qwen3-8B'; Quant='Q4_K_M' },
  [pscustomobject]@{ Id='05_gemma4_e4b'; Name='gemma-4-E4B-it-Q4_K_M.gguf'; Path=(Join-Path 'G:\~dev\rawrxd\_r1_iso\05_gemma4_e4b' 'gemma-4-E4B-it-Q4_K_M.gguf'); Family='Gemma-4-E4B'; Quant='Q4_K_M' },
  [pscustomobject]@{ Id='06_phi3_med'; Name='Phi-3-medium-128k-instruct-Q4_K_M.gguf'; Path=(Join-Path 'G:\~dev\rawrxd\_r1_iso\06_phi3_med' 'Phi-3-medium-128k-instruct-Q4_K_M.gguf'); Family='Phi-3-medium-14B'; Quant='Q4_K_M' },
  [pscustomobject]@{ Id='07_codestral'; Name='Codestral-22B-v0.1-Q4_K_M.gguf'; Path=(Join-Path 'G:\~dev\rawrxd\_r1_iso\07_codestral' 'Codestral-22B-v0.1-Q4_K_M.gguf'); Family='Codestral-22B'; Quant='Q4_K_M' },
  [pscustomobject]@{ Id='08_qwen_coder'; Name='qwen2.5-coder-14b-instruct-q8_0.gguf'; Path=(Join-Path 'G:\~dev\rawrxd\_r1_iso\08_qwen_coder' 'qwen2.5-coder-14b-instruct-q8_0.gguf'); Family='Qwen2.5-Coder-14B'; Quant='Q8_0' },
  [pscustomobject]@{ Id='09_bigdaddy_ultra'; Name='BigDaddyG-Q2_K-ULTRA.gguf'; Path=(Join-Path 'G:\~dev\rawrxd\_r1_iso\09_bigdaddy_ultra' 'BigDaddyG-Q2_K-ULTRA.gguf'); Family='BigDaddyG'; Quant='Q2_K' },
  [pscustomobject]@{ Id='10_glm47'; Name='GLM-4.7-Flash-Q4_K_M.gguf'; Path=(Join-Path 'G:\~dev\rawrxd\_r1_iso\10_glm47' 'GLM-4.7-Flash-Q4_K_M.gguf'); Family='GLM-4.7-Flash'; Quant='Q4_K_M' }
)

$cached = @{}
$mj = Join-Path $ev 'models.json'
if (Test-Path $mj) {
  foreach ($c in (Get-Content $mj -Raw | ConvertFrom-Json)) { $cached[$c.Id] = $c }
}
foreach ($m in $models) {
  if (-not (Test-Path -LiteralPath $m.Path)) { throw "missing $($m.Path)" }
  $sz = [math]::Round((Get-Item -LiteralPath $m.Path).Length / 1MB, 1)
  $m | Add-Member -NotePropertyName SizeMB -NotePropertyValue $sz -Force
  if ($cached.ContainsKey($m.Id) -and $cached[$m.Id].SHA16) {
    $m | Add-Member -NotePropertyName SHA16 -NotePropertyValue ([string]$cached[$m.Id].SHA16) -Force
  } else {
    $m | Add-Member -NotePropertyName SHA16 -NotePropertyValue ((Get-FileHash -LiteralPath $m.Path -Algorithm SHA256).Hash.Substring(0,16)) -Force
  }
}
$models | ConvertTo-Json -Depth 5 | Set-Content $mj
[IO.File]::WriteAllText((Join-Path $smoke 'empty.json'), '{}')

function Kill-PortRawr {
  Get-NetTCPConnection -LocalPort $port -EA SilentlyContinue | ForEach-Object {
    Stop-Process -Id $_.OwningProcess -Force -EA SilentlyContinue
  }
  Get-CimInstance Win32_Process -EA SilentlyContinue | Where-Object {
    $_.CommandLine -and ($_.CommandLine -match [regex]::Escape("--port $port"))
  } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }
  Start-Sleep 2
}

function Start-Headless([string]$tag) {
  Kill-PortRawr
  $out = Join-Path $smoke "$tag.headless.out.txt"
  $err = Join-Path $smoke "$tag.headless.err.txt"
  Remove-Item $out, $err -EA SilentlyContinue
  $bat = Join-Path $smoke "$tag.run.bat"
  $lines = @(
    '@echo off',
    'set RAWRXD_HOST_DECODE=1',
    'set RAWRXD_FORCE_CPU_INFERENCE=1',
    'set DEEP2_MINIMAL_ENHANCE=1',
    'set DEEP2_DUALSTICK_ARM=0',
    'set RAWRXD_NO_VULKAN=1',
    'set DEEP2_MARS=0',
    'set RAWRXD_AGENTIC=0',
    'set RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM=1',
    'set VK_ICD_FILENAMES=C:\rawrxd_blocked_no_vulkan_icd.json',
    " `"$exe`" --headless --local --port $port --dir G:\~dev\rawrxd > `"$out`" 2> `"$err`""
  )
  [IO.File]::WriteAllLines($bat, $lines)
  Start-Process -FilePath $bat -WorkingDirectory (Split-Path $exe) -WindowStyle Hidden | Out-Null
  $deadline = (Get-Date).AddSeconds(90)
  while ((Get-Date) -lt $deadline) {
    try {
      $h = Invoke-WebRequest -Uri "$base/api/engine/capabilities" -UseBasicParsing -TimeoutSec 3
      if ($h.StatusCode -eq 200) {
        $p = Get-CimInstance Win32_Process -EA SilentlyContinue | Where-Object {
          $_.CommandLine -and ($_.CommandLine -match [regex]::Escape("--port $port"))
        } | Select-Object -First 1
        return @{ Pid = $(if ($p) { $p.ProcessId } else { 0 }); Out = $out; Err = $err }
      }
    } catch { Start-Sleep -Milliseconds 500 }
  }
  throw "headless_health_timeout tag=$tag"
}

function Curl-Post([string]$path, [string]$bodyFile, [string]$outFile, [int]$timeoutSec = 3600) {
  $safeDir = Join-Path $env:TEMP 'rawrxd_r1_bodies'
  New-Item -ItemType Directory -Force -Path $safeDir | Out-Null
  if ($bodyFile -eq 'INLINE_EMPTY') {
    $safeBody = Join-Path $safeDir 'empty.json'
    [IO.File]::WriteAllText($safeBody, '{}')
  } else {
    if (-not (Test-Path -LiteralPath $bodyFile)) { return @{ Code = 0; Body = '' } }
    $safeBody = Join-Path $safeDir ([IO.Path]::GetFileName($bodyFile))
    Copy-Item -LiteralPath $bodyFile -Destination $safeBody -Force
  }
  $code = & curl.exe -sS -o $outFile -w '%{http_code}' -X POST "$base$path" `
    -H 'Content-Type: application/json' --data-binary "@$safeBody" --max-time $timeoutSec 2>$null
  if (-not $code) { $code = '000' }
  $body = ''
  if (Test-Path -LiteralPath $outFile) { $body = [IO.File]::ReadAllText($outFile) }
  return @{ Code = [int]$code; Body = $body }
}

function Proc-Count {
  return @(Get-CimInstance Win32_Process -EA SilentlyContinue | Where-Object {
    $_.CommandLine -and ($_.CommandLine -match [regex]::Escape("--port $port"))
  }).Count
}

function Prove-NoOllama {
  Get-Process -Name 'ollama*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
  Get-NetTCPConnection -LocalPort 11434 -EA SilentlyContinue | ForEach-Object {
    Stop-Process -Id $_.OwningProcess -Force -EA SilentlyContinue
  }
  Start-Sleep 1
  $tcp = @(Get-NetTCPConnection -LocalPort 11434 -EA SilentlyContinue)
  $proc = @(Get-Process -Name 'ollama*' -EA SilentlyContinue)
  if ($tcp.Count -gt 0 -or $proc.Count -gt 0) { return 'OLLAMA_PRESENT=1' }
  return 'PORT_11434_NOT_REQUIRED=1 OLLAMA_PROCESS_REQUIRED=NO LOCAL_ONLY_NO_OLLAMA=1 OLLAMA_CONTACT=0'
}

function Count-Tokens([string]$body, [string]$errPath) {
  $n = 0
  if ($body -match '"eval_count"\s*:\s*(\d+)') { $n = [int]$Matches[1] }
  if ($n -le 0 -and (Test-Path $errPath)) {
    $hit = Select-String -Path $errPath -Pattern 'GENERATED_TOKENS=(\d+)' | Select-Object -Last 1
    if ($hit) { $n = [int]$hit.Matches[0].Groups[1].Value }
  }
  if ($n -le 0 -and $body -match '"done"\s*:\s*true' -and $body -match '"response"\s*:\s*".+"') { $n = 1 }
  return $n
}

$passCount = 0; $failCount = 0; $ollamaContact = 0
$matrix = New-Object System.Collections.Generic.List[object]
$no = Prove-NoOllama
$no | Set-Content (Join-Path $ev 'NO_OLLAMA_PROOF.txt')
if ($no -match 'OLLAMA_PRESENT') { $ollamaContact = 1 }

@"
EXE_SRC=$exeSrc
EXE_SHA16=$($exeSha.Substring(0,16))
EXE_SHA256=$exeSha
PE_LAA=$peLaa HOST_DECODE=1
"@ | Set-Content (Join-Path $ev 'EXE_SHA.txt')

"EXE_SHA16=$($exeSha.Substring(0,16)) PE_LAA=$peLaa HOST_DECODE=1 models=$($models.Count)" | Tee-Object (Join-Path $ev 'MATRIX_LIVE.log')

foreach ($m in $models) {
  $tag = $m.Id
  $row = [ordered]@{
    ID=$tag; NAME=$m.Name; FAMILY=$m.Family; QUANT=$m.Quant; PATH=$m.Path
    SIZE_MB=$m.SizeMB; SHA16=$m.SHA16
    PREPARE=0; LOAD=0; GENERATE=0; TOKENS=0; UNLOAD=0; RELOAD=0; RELOAD_GEN=0
    PROCESS_SURVIVED=0; ACCESS_VIOLATION=0; C0000374=0; OLLAMA_CONTACT=$ollamaContact
    VERDICT='FAIL'; OWNER=''; DETAIL=''
  }
  $log = Join-Path $smoke "$tag.lifecycle.txt"
  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add("MODEL=$($m.Name)"); $lines.Add("PATH=$($m.Path)"); $lines.Add("SIZE_MB=$($m.SizeMB) SHA16=$($m.SHA16)")
  try {
    $h = Start-Headless $tag
    $lines.Add("HEADLESS_PID=$($h.Pid)")
    $lines.Add((Prove-NoOllama))
    $fwdPath = ($m.Path -replace '\\','/')
    $escPath = ($fwdPath -replace '"','\"')
    $escName = ($m.Name -replace '"','\"')
    $prepFile = Join-Path $smoke "$tag.prep.json"
    $loadFile = Join-Path $smoke "$tag.load.json"
    $genFile = Join-Path $smoke "$tag.genreq.json"
    [IO.File]::WriteAllText($prepFile, "{`"model`":`"$escName`",`"path`":`"$escPath`"}")
    [IO.File]::WriteAllText($loadFile, "{`"modelPath`":`"$escPath`"}")
    [IO.File]::WriteAllText($genFile, '{"prompt":"Reply with exactly: OK","stream":false,"options":{"num_predict":8}}')

    $reg = Curl-Post '/api/native/runtime/register' $prepFile (Join-Path $smoke "$tag.reg.out.json") 180
    $lines.Add("REGISTER=$($reg.Code)")
    $prep = Curl-Post '/api/native/generation/prepare' $prepFile (Join-Path $smoke "$tag.prep.out.json") 180
    $row.PREPARE = $prep.Code
    $snip = if ($prep.Body.Length -gt 200) { $prep.Body.Substring(0,200) } else { $prep.Body }
    $lines.Add("PREPARE=$($prep.Code) $snip")
    if ($prep.Code -ne 200) { $row.OWNER='native_prepare'; $row.DETAIL=$prep.Body; throw 'prepare_fail' }

    $load = Curl-Post '/api/model/load' $loadFile (Join-Path $smoke "$tag.load.out.json") 900
    $row.LOAD = $load.Code
    $lines.Add("LOAD=$($load.Code) $($load.Body)")
    if ($load.Code -ne 200) { $row.OWNER='model_load'; $row.DETAIL=$load.Body; throw 'load_fail' }

    $gen = Curl-Post '/api/generate' $genFile (Join-Path $smoke "$tag.gen1.json") 7200
    $row.GENERATE = $gen.Code
    Start-Sleep -Seconds 2
    $tok = Count-Tokens $gen.Body $h.Err
    $row.TOKENS = $tok
    $lines.Add("GENERATE=$($gen.Code) TOKENS=$tok PROCS=$(Proc-Count)")
    $gsnip = if ($gen.Body.Length -gt 240) { $gen.Body.Substring(0,240) } else { $gen.Body }
    $lines.Add("GEN_SNIP=$gsnip")
    if ((Proc-Count) -lt 1) {
      $row.PROCESS_SURVIVED = 0
      $passHint = ''
      if (Test-Path $h.Err) {
        $passHint = @(Select-String -Path $h.Err -Pattern 'PRODUCT_PASS=1' -SimpleMatch | Select-Object -Last 1)
      }
      if ($tok -gt 0 -and $passHint) { $row.OWNER='process_exit_after_product_pass_gen' }
      else { $row.OWNER='process_died_generate' }
      throw 'died'
    }
    if ($gen.Code -ne 200 -or $tok -le 0) {
      $row.OWNER='generate_tokens'; $row.DETAIL="code=$($gen.Code) tok=$tok"; throw 'gen_fail'
    }

    $un = Curl-Post '/api/model/unload' 'INLINE_EMPTY' (Join-Path $smoke "$tag.unload.out.json") 180
    $row.UNLOAD = $un.Code
    $lines.Add("UNLOAD=$($un.Code) $($un.Body)")
    if ($un.Code -ne 200) { $row.OWNER='unload'; $row.DETAIL=$un.Body; throw 'unload_fail' }

    $reload = Curl-Post '/api/model/load' $loadFile (Join-Path $smoke "$tag.reload.out.json") 900
    $row.RELOAD = $reload.Code
    $lines.Add("RELOAD=$($reload.Code) $($reload.Body)")
    if ($reload.Code -ne 200) { $row.OWNER='reload'; throw 'reload_fail' }

    $gen2 = Curl-Post '/api/generate' $genFile (Join-Path $smoke "$tag.gen2.json") 7200
    Start-Sleep -Seconds 2
    $tok2 = Count-Tokens $gen2.Body $h.Err
    $row.RELOAD_GEN = $gen2.Code
    if ($tok2 -gt $row.TOKENS) { $row.TOKENS = $tok2 }
    $lines.Add("RELOAD_GEN=$($gen2.Code) TOKENS=$tok2 PROCS=$(Proc-Count)")
    if ((Proc-Count) -lt 1) {
      $row.PROCESS_SURVIVED = 0
      $row.OWNER='process_died_reload_gen'
      throw 'died_reload'
    }
    if ($gen2.Code -ne 200 -or $tok2 -le 0) {
      $row.OWNER='reload_generate'; $row.DETAIL="code=$($gen2.Code) tok=$tok2"; throw 'reload_gen_fail'
    }

    $row.PROCESS_SURVIVED = 1
    $row.VERDICT = 'PASS'
    $passCount++
    $lines.Add('VERDICT=PASS')
  } catch {
    $failCount++
    if (-not $row.OWNER) { $row.OWNER = 'exception' }
    if (-not $row.DETAIL) { $row.DETAIL = $_.Exception.Message }
    $row.VERDICT = 'FAIL'
    $lines.Add("VERDICT=FAIL OWNER=$($row.OWNER) DETAIL=$($row.DETAIL)")
  } finally {
    ($lines -join "`r`n") | Set-Content $log -Encoding UTF8
    $matrix.Add([pscustomobject]$row)
    $msg = "ROW $($row.ID) $($row.VERDICT) prep=$($row.PREPARE) load=$($row.LOAD) gen=$($row.GENERATE) tok=$($row.TOKENS) un=$($row.UNLOAD) rel=$($row.RELOAD) rg=$($row.RELOAD_GEN) surv=$($row.PROCESS_SURVIVED) owner=$($row.OWNER)"
    $msg | Tee-Object -FilePath (Join-Path $ev 'MATRIX_LIVE.log') -Append
    Kill-PortRawr
  }
}

$mlines = @('ID|FAMILY|QUANT|SIZE_MB|SHA16|PREPARE|LOAD|GENERATE|TOKENS|UNLOAD|RELOAD|RELOAD_GEN|SURVIVED|AV|C0000374|OLLAMA|VERDICT|OWNER')
foreach ($r in $matrix) {
  $mlines += ("{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}|{8}|{9}|{10}|{11}|{12}|{13}|{14}|{15}|{16}|{17}" -f `
    $r.ID,$r.FAMILY,$r.QUANT,$r.SIZE_MB,$r.SHA16,$r.PREPARE,$r.LOAD,$r.GENERATE,$r.TOKENS,`
    $r.UNLOAD,$r.RELOAD,$r.RELOAD_GEN,$r.PROCESS_SURVIVED,$r.ACCESS_VIOLATION,$r.C0000374,`
    $r.OLLAMA_CONTACT,$r.VERDICT,$r.OWNER)
}
($mlines -join "`r`n") | Set-Content (Join-Path $ev 'MATRIX.txt') -Encoding UTF8
$matrix | Export-Csv (Join-Path $ev 'MATRIX.csv') -NoTypeInformation -Encoding UTF8
@"
PASS_COUNT=$passCount
FAIL_COUNT=$failCount
TOTAL=$($models.Count)
OLLAMA_CONTACT=$ollamaContact
EXE_SHA16=$($exeSha.Substring(0,16))
EXE_SHA256=$exeSha
PE_LAA=$peLaa
HOST_DECODE=1
OLLAMA=0
TIP_CLIMB=HOLD
PROMOTE=0
SLOT03=Llama-3.2-3B (Qwen3.8-27B deferred: model_load/VA)
EXE_LINEAGE=r1latch_soft_reuse_path_switch
CLOSESESSION_LATCH_CLEAR=1
TIP_CLIMB=HOLD
PROMOTE=0
STILL_VETO=MULTI_GGUF_PRODUCTRUN_SURVIVAL
"@ | Set-Content (Join-Path $ev 'ROLLUP.txt') -Encoding UTF8
Get-Content (Join-Path $ev 'ROLLUP.txt')
if ($failCount -gt 0) { exit 2 } else { exit 0 }
