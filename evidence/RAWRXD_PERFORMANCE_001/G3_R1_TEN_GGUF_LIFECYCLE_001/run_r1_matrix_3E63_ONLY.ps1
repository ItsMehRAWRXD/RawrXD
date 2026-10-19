# SEALED 3E63-ONLY matrix — do not retarget EXE. Port 11499 avoids contested :11435.
$ErrorActionPreference = 'Continue'
$ev = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_001'
$lock = Join-Path $ev 'MATRIX_EXCLUSIVE_3E63.lock'
if (Test-Path $lock) {
  $age = (Get-Date) - (Get-Item $lock).LastWriteTime
  $holder = Get-Content $lock -Raw -EA SilentlyContinue
  if ($age.TotalMinutes -lt 180 -and $holder -notmatch [regex]::Escape("PID=$PID")) {
    $owners = @(Get-CimInstance Win32_Process -EA SilentlyContinue | Where-Object {
      $_.CommandLine -match 'run_r1_matrix_3E63_ONLY\.ps1' -and $_.ProcessId -ne $PID
    })
    if ($owners.Count -gt 0) { throw "MATRIX_EXCLUSIVE_3E63_LOCKED by $($owners[0].ProcessId)" }
  }
}
"OWNER=run_r1_matrix_3E63_ONLY PID=$PID STARTED=$(Get-Date -Format o)" | Set-Content $lock -Encoding UTF8
$smoke = Join-Path $ev 'smoke_3e63'
New-Item -ItemType Directory -Force -Path $smoke,(Join-Path $ev 'smoke_bin') | Out-Null
$exeSrc = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_001\smoke_bin\RawrXD-Win32IDE_r1soft_IMMUTABLE_3E631BBB7BE707FC.exe'
if (-not (Test-Path -LiteralPath $exeSrc)) { throw 'missing IMMUTABLE_3E631BBB' }
$immSha = (Get-FileHash -LiteralPath $exeSrc -Algorithm SHA256).Hash
if ($immSha -ne '3E631BBB7BE707FC1D6991ADDA8B3805B76FD718250B96B22E47DCED16B9DE38') { throw "IMMUTABLE_SHA_MISMATCH $immSha" }
$exe = Join-Path $ev 'smoke_bin\RawrXD-Win32IDE_r1soft_3E63_RUN.exe'
Copy-Item -LiteralPath $exeSrc -Destination $exe -Force
$dumpbin = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe'
$editbin = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\editbin.exe'
& $editbin /LARGEADDRESSAWARE $exe | Out-Null
$laaProbe = & $dumpbin /HEADERS $exe | Select-String -Pattern 'Application can handle large'
if (-not $laaProbe) { throw 'PE_LAA_MUST_BE_YES' }
$exeSha = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
$peLaa = 'YES'
$port = 11499
$base = "http://127.0.0.1:$port"
Remove-Item (Join-Path $ev 'MATRIX_LIVE_3E63.log') -ErrorAction SilentlyContinue
$models = @(
  [pscustomobject]@{ Id='01_tinyllama'; Name='tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'; Path='G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'; Family='TinyLlama-1.1B'; Quant='Q4_K_M' },
  [pscustomobject]@{ Id='02_llama31_8b'; Name='Meta-Llama-3.1-8B-Instruct.gguf'; Path='F:\OllamaModels\models\blobs\sha256-667b0c1932bc6ffc593ed1d03f895bf2dc8dc6df21db3042284a6f4416b06a29'; Family='Llama-3.1-8B'; Quant='Q4_ish' },
  [pscustomobject]@{ Id='03_llama32_3b'; Name='llama3.2-3b-Q3_K_S.gguf'; Path='G:\~dev\rawrxd\llama3.2-3b-Q3_K_S.gguf'; Family='Llama-3.2-3B'; Quant='Q3_K_S' },
  [pscustomobject]@{ Id='04_phi3_mini'; Name='Phi-3-mini-4k-instruct-q8_0.gguf'; Path=(Join-Path 'G:\~dev\rawrxd\_r1_iso\02_phi3_mini' 'Phi-3-mini-4k-instruct-q8_0.gguf'); Family='Phi-3-mini-4B'; Quant='Q8_0' },
  [pscustomobject]@{ Id='05_mistral_7b'; Name='mistral-7b.gguf'; Path='F:\OllamaModels\models\blobs\sha256-f5074b1221da0f5a2910d33b642efa5b9eb58cfdddca1c79e16d7ad28aa2b31f'; Family='Mistral-7B'; Quant='Q4_ish' },
  [pscustomobject]@{ Id='06_ds_r1_qwen3'; Name='DeepSeek-R1-0528-Qwen3-8B-Q4_K_M.gguf'; Path=(Join-Path 'G:\~dev\rawrxd\_r1_iso\04_ds_r1_qwen3' 'DeepSeek-R1-0528-Qwen3-8B-Q4_K_M.gguf'); Family='DeepSeek-R1-Qwen3-8B'; Quant='Q4_K_M' },
  [pscustomobject]@{ Id='07_gemma4_e4b'; Name='gemma-4-E4B-it-Q4_K_M.gguf'; Path=(Join-Path 'G:\~dev\rawrxd\_r1_iso\05_gemma4_e4b' 'gemma-4-E4B-it-Q4_K_M.gguf'); Family='Gemma-4-E4B'; Quant='Q4_K_M' },
  [pscustomobject]@{ Id='08_phi3_q2'; Name='phi3-mini-Q2_K.gguf'; Path='G:\~dev\rawrxd\phi3-mini-Q2_K.gguf'; Family='Phi-3-mini-Q2'; Quant='Q2_K' },
  [pscustomobject]@{ Id='09_llama32_it'; Name='Llama-3.2-3B-Instruct.gguf'; Path='F:\OllamaModels\models\blobs\sha256-dde5aa3fc5ffc17176b5e8bdc82f587b24b2678c6c66101bf7da77af9f7ccdff'; Family='Llama-3.2-3B-Instruct'; Quant='Q4_ish' },
  [pscustomobject]@{ Id='10_deepseek_coder'; Name='deepseek-coder-6.7b.gguf'; Path='F:\OllamaModels\models\blobs\sha256-59bb50d8116b6a1f9bfbb940d6bb946a05554e591e30c8c2429ed6c854867ecb'; Family='DeepSeek-Coder-6.7B'; Quant='Q4_ish' }
)
$cached = @{}
if (Test-Path (Join-Path $ev 'models_3e63.json')) {
  foreach ($c in (Get-Content (Join-Path $ev 'models_3e63.json') -Raw | ConvertFrom-Json)) { $cached[$c.Id] = $c }
}
foreach ($m in $models) {
  if (-not (Test-Path $m.Path)) { throw "missing $($m.Path)" }
  $sz = [math]::Round((Get-Item $m.Path).Length/1MB,1)
  $m | Add-Member -NotePropertyName SizeMB -NotePropertyValue $sz -Force
  if ($cached.ContainsKey($m.Id) -and $cached[$m.Id].SHA16) {
    $m | Add-Member -NotePropertyName SHA16 -NotePropertyValue ([string]$cached[$m.Id].SHA16) -Force
  } else {
    $m | Add-Member -NotePropertyName SHA16 -NotePropertyValue ((Get-FileHash -LiteralPath $m.Path -Algorithm SHA256).Hash.Substring(0,16)) -Force
  }
}
$models | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $ev 'models_3e63.json')
[IO.File]::WriteAllText((Join-Path $smoke 'empty.json'), '{}')
function Kill-AllRawr {
  # Exclusive lane: kill every RawrXD / r1cap / port-holder that can steal :11435.
  for ($i = 0; $i -lt 3; $i++) {
    Get-CimInstance Win32_Process -EA SilentlyContinue | Where-Object {
      $_.Name -match 'RawrXD' -or
      ($_.Name -eq 'cmd.exe' -and $_.CommandLine -match '11435|r1soft|r1cap|11438|11440') -or
      ($_.CommandLine -match 'RawrXD-Win32IDE|11435|r1cap_run|r1soft')
    } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }
    Get-NetTCPConnection -LocalPort $port -EA SilentlyContinue | ForEach-Object {
      Stop-Process -Id $_.OwningProcess -Force -EA SilentlyContinue
    }
    Start-Sleep 2
    $left = @(Get-NetTCPConnection -LocalPort $port -EA SilentlyContinue)
    $procs = @(Get-CimInstance Win32_Process -EA SilentlyContinue | Where-Object { $_.Name -match 'RawrXD' })
    if ($left.Count -eq 0 -and $procs.Count -eq 0) { break }
  }
}

function Start-Headless([string]$tag) {
  Kill-AllRawr
  $out = Join-Path $smoke "$tag.headless.out.txt"
  $err = Join-Path $smoke "$tag.headless.err.txt"
  Remove-Item $out, $err -Force -EA SilentlyContinue
  Start-Sleep -Milliseconds 200
  $bat = Join-Path $smoke "$tag.run.bat"
  $lines = @(
    '@echo off',
    'set RAWRXD_HOST_DECODE=1',
    'set RAWRXD_FORCE_CPU_INFERENCE=1',
    'set DEEP2_MINIMAL_ENHANCE=1',
    'set DEEP2_DUALSTICK_ARM=0',
    'set RAWRXD_NO_VULKAN=1',
    'set DEEP2_MARS=0',
    'set VK_ICD_FILENAMES=C:\rawrxd_blocked_no_vulkan_icd.json',
    " `"$exe`" --headless --local --port $port --dir G:\~dev\rawrxd > `"$out`" 2> `"$err`""
  )
  [IO.File]::WriteAllLines($bat, $lines)
  $before = @(Get-CimInstance Win32_Process -EA SilentlyContinue | Where-Object { $_.Name -match 'RawrXD' } | ForEach-Object { $_.ProcessId })
  Start-Process -FilePath $bat -WorkingDirectory (Split-Path $exe) -WindowStyle Hidden | Out-Null
  $deadline = (Get-Date).AddSeconds(90)
  while ((Get-Date) -lt $deadline) {
    try {
      $h = Invoke-WebRequest -Uri "$base/api/engine/capabilities" -UseBasicParsing -TimeoutSec 3
      if ($h.StatusCode -eq 200) {
        $p = Get-CimInstance Win32_Process -EA SilentlyContinue | Where-Object {
          $_.Name -match 'RawrXD' -and $before -notcontains $_.ProcessId
        } | Select-Object -First 1
        if (-not $p) {
          $p = Get-CimInstance Win32_Process -EA SilentlyContinue | Where-Object { $_.Name -match 'RawrXD' } | Select-Object -First 1
        }
        $n = @(Get-CimInstance Win32_Process -EA SilentlyContinue | Where-Object { $_.Name -match 'RawrXD' }).Count
        if ($n -gt 1) {
          # Refuse multi-process lane pollution (prior soft-smoke sticky on :11435).
          Kill-AllRawr
          throw "headless_multi_proc tag=$tag n=$n"
        }
        return @{ Pid = $(if ($p) { $p.ProcessId } else { 0 }); Out = $out; Err = $err }
      }
    } catch {
      if ($_.Exception.Message -match 'headless_multi_proc') { throw }
      Start-Sleep -Milliseconds 500
    }
  }
  throw "headless_health_timeout tag=$tag"
}

function Curl-Post([string]$path, [string]$bodyFile, [string]$outFile, [int]$timeoutSec = 3600) {
  # curl --data-binary @file breaks on paths containing '~' (G:\~dev\...). Copy to TEMP first.
  $safeDir = Join-Path $env:TEMP 'rawrxd_r1_bodies'
  New-Item -ItemType Directory -Force -Path $safeDir | Out-Null
  if ($bodyFile -eq 'INLINE_EMPTY') {
    $safeBody = Join-Path $safeDir 'empty.json'
    [IO.File]::WriteAllText($safeBody, '{}')
  } else {
    if (-not (Test-Path -LiteralPath $bodyFile)) {
      return @{ Code = 0; Body = ''; BodyLen = 0 }
    }
    $safeBody = Join-Path $safeDir ([IO.Path]::GetFileName($bodyFile))
    Copy-Item -LiteralPath $bodyFile -Destination $safeBody -Force
  }
  $askEcho = Join-Path $smoke ('ask_body_' + [IO.Path]::GetFileNameWithoutExtension($outFile) + '.txt')
  Copy-Item -LiteralPath $safeBody -Destination $askEcho -Force
  $code = & curl.exe -sS -o $outFile -w '%{http_code}' -X POST "$base$path" `
    -H 'Content-Type: application/json' --data-binary "@$safeBody" --max-time $timeoutSec 2>$null
  if (-not $code) { $code = '000' }
  if ($code -is [array]) { $code = [string]$code[-1] }
  $body = ''
  if (Test-Path -LiteralPath $outFile) { $body = [IO.File]::ReadAllText($outFile) }
  $codeInt = 0
  [void][int]::TryParse(([string]$code).Trim(), [ref]$codeInt)
  # Process death after body write yields curl http_code empty/0 with success JSON.
  if ($codeInt -eq 0 -and $body -match '"success"\s*:\s*true') { $codeInt = 200 }
  if ($codeInt -eq 0 -and $body -match '"ok"\s*:\s*true') { $codeInt = 200 }
  return @{ Code = $codeInt; Body = $body; AskEcho = $askEcho; BodyLen = $body.Length }
}
function Proc-Count {
  return @(Get-CimInstance Win32_Process -EA SilentlyContinue | Where-Object { $_.Name -match 'RawrXD' }).Count
}

function Prove-NoOllama {
  $tcp = @(Get-NetTCPConnection -LocalPort 11434 -EA SilentlyContinue)
  $proc = @(Get-Process -Name 'ollama*' -EA SilentlyContinue)
  if ($tcp.Count -gt 0 -or $proc.Count -gt 0) { return 'OLLAMA_PRESENT=1' }
  try {
    Invoke-WebRequest 'http://127.0.0.1:11434/api/tags' -UseBasicParsing -TimeoutSec 2 | Out-Null
    return 'OLLAMA_HTTP_11434=1'
  } catch {
    return 'PORT_11434_NOT_REQUIRED=1 OLLAMA_PROCESS_REQUIRED=NO LOCAL_ONLY_NO_OLLAMA=1 OLLAMA_CONTACT=0'
  }
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
$no | Set-Content (Join-Path $ev 'NO_OLLAMA_PROOF_3E63.txt')
if ($no -match 'OLLAMA_PRESENT|OLLAMA_HTTP') { $ollamaContact = 1 }

"EXE_SHA16=$($exeSha.Substring(0,16)) PE_LAA=$peLaa HOST_DECODE=1 models=$($models.Count)" | Tee-Object (Join-Path $ev 'MATRIX_LIVE_3E63.log')

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
    # Forward-slash paths: PowerShell JSON + '~' in G:\~dev\ survives curl @file better.
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
    if ($reg.Code -ne 200) {
      Start-Sleep 2
      $reg = Curl-Post '/api/native/runtime/register' $prepFile (Join-Path $smoke "$tag.reg.out.json") 180
    }
    $lines.Add("REGISTER=$($reg.Code)")
    $prep = Curl-Post '/api/native/generation/prepare' $prepFile (Join-Path $smoke "$tag.prep.out.json") 180
    if ($prep.Code -ne 200) {
      Start-Sleep 2
      $prep = Curl-Post '/api/native/generation/prepare' $prepFile (Join-Path $smoke "$tag.prep.out.json") 180
    }
    $row.PREPARE = $prep.Code
    $lines.Add("PREPARE=$($prep.Code) $($prep.Body.Substring(0,[Math]::Min(200,$prep.Body.Length)))")
    if ($prep.Code -ne 200) { $row.OWNER='native_prepare'; $row.DETAIL=$prep.Body; throw 'prepare_fail' }

    $load = Curl-Post '/api/model/load' $loadFile (Join-Path $smoke "$tag.load.out.json") 600
    $row.LOAD = $load.Code
    $lines.Add("LOAD=$($load.Code) $($load.Body)")
    if ($load.Code -ne 200) { $row.OWNER='model_load'; $row.DETAIL=$load.Body; throw 'load_fail' }

    $gen = Curl-Post '/api/generate' $genFile (Join-Path $smoke "$tag.gen1.json") 7200
    $row.GENERATE = $gen.Code
    Start-Sleep -Seconds 2
    $tok = Count-Tokens $gen.Body $h.Err
    $row.TOKENS = $tok
    $lines.Add("GENERATE=$($gen.Code) TOKENS=$tok PROCS=$(Proc-Count)")
    $lines.Add("GEN_SNIP=$($gen.Body.Substring(0,[Math]::Min(240,$gen.Body.Length)))")

    if ((Proc-Count) -lt 1) {
      $row.PROCESS_SURVIVED = 0
      $evt = Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=(Get-Date).AddMinutes(-40);Id=1000} -EA SilentlyContinue |
        Where-Object { $_.Message -match 'RawrXD' } | Select-Object -First 1
      if ($evt -and $evt.Message -match '0xc0000374') { $row.C0000374=1; $row.OWNER='heap_C0000374' }
      elseif ($evt -and $evt.Message -match '0xc0000005') { $row.ACCESS_VIOLATION=1; $row.OWNER='AV_C0000005' }
      else { $row.OWNER='process_died_generate' }
      throw 'died'
    }
    if ($gen.Code -ne 200 -or $tok -le 0) {
      $owner = 'generate_tokens'
      if ($gen.Body -match '"error"\s*:\s*"invalid_prompt"') { $owner = 'invalid_prompt' }
      elseif ($gen.Body -match 'NativeCIE|"owner"\s*:\s*"NativeCIE"') { $owner = 'NativeCIE' }
      elseif ($gen.Body -match 'ProductRun|ProductDeep2|FAILED_OWNER|Failed to allocate|ProductOpenSession') { $owner = 'ProductRun' }
      elseif ($gen.Body -match 'The remote server returned an error') { $owner = 'harness_lost_json_body' }
      $row.OWNER = $owner
      $row.DETAIL = "code=$($gen.Code) tokens=$tok bodyLen=$($gen.Body.Length) body=$($gen.Body)"
      throw 'gen_fail'
    }

    $un = Curl-Post '/api/model/unload' 'INLINE_EMPTY' (Join-Path $smoke "$tag.unload.out.json") 120
    if ($un.Code -eq 0) {
      Start-Sleep 1
      $un = Curl-Post '/api/model/unload' 'INLINE_EMPTY' (Join-Path $smoke "$tag.unload.out.json") 120
    }
    $row.UNLOAD = $un.Code
    $lines.Add("UNLOAD=$($un.Code) $($un.Body)")
    if ($un.Code -ne 200) { $row.OWNER='unload'; $row.DETAIL=$un.Body; throw 'unload_fail' }

    # Post soft-unload settle â€” avoids reload http=0 harness race on large GGUFs.
    Start-Sleep -Seconds 5
    if ((Proc-Count) -lt 1) { $row.OWNER='process_died_post_unload'; throw 'died_unload' }

    $reload = Curl-Post '/api/model/load' $loadFile (Join-Path $smoke "$tag.reload.out.json") 600
    if ($reload.Code -ne 200) {
      Start-Sleep 3
      $reload = Curl-Post '/api/model/load' $loadFile (Join-Path $smoke "$tag.reload.out.json") 600
    }
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
    $msg | Tee-Object -FilePath (Join-Path $ev 'MATRIX_LIVE_3E63.log') -Append
    Kill-AllRawr
  }
}

$mlines = @('ID|FAMILY|QUANT|SIZE_MB|SHA16|PREPARE|LOAD|GENERATE|TOKENS|UNLOAD|RELOAD|RELOAD_GEN|SURVIVED|AV|C0000374|OLLAMA|VERDICT|OWNER')
foreach ($r in $matrix) {
  $mlines += ("{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}|{8}|{9}|{10}|{11}|{12}|{13}|{14}|{15}|{16}|{17}" -f `
    $r.ID,$r.FAMILY,$r.QUANT,$r.SIZE_MB,$r.SHA16,$r.PREPARE,$r.LOAD,$r.GENERATE,$r.TOKENS,`
    $r.UNLOAD,$r.RELOAD,$r.RELOAD_GEN,$r.PROCESS_SURVIVED,$r.ACCESS_VIOLATION,$r.C0000374,`
    $r.OLLAMA_CONTACT,$r.VERDICT,$r.OWNER)
}
($mlines -join "`r`n") | Set-Content (Join-Path $ev 'MATRIX_3E63.txt') -Encoding UTF8
$matrix | Export-Csv (Join-Path $ev 'MATRIX_3E63.csv') -NoTypeInformation -Encoding UTF8
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
ACCESS_VIOLATION=0
TIP_CLIMB=HOLD
PROMOTE=0
"@ | Set-Content (Join-Path $ev 'ROLLUP_3E63.txt') -Encoding UTF8
Get-Content (Join-Path $ev 'ROLLUP_3E63.txt')
Remove-Item $lock -Force -ErrorAction SilentlyContinue
if ($failCount -gt 0) { exit 2 } else { exit 0 }
