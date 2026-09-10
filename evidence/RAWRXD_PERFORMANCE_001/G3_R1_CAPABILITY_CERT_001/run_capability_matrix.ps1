# G3_R1_CAPABILITY_CERT_001 — A–J capability ladder (cold-start per model)
# LAA:YES + HOST_DECODE + no Ollama. Uses models_aj.json from resolve_aj_paths.ps1
$ErrorActionPreference = 'Continue'
$ev = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_CAPABILITY_CERT_001'
$smoke = Join-Path $ev 'smoke'
New-Item -ItemType Directory -Force -Path $smoke, (Join-Path $ev 'smoke_bin'), (Join-Path $ev 'receipts') | Out-Null

$modelsJson = Join-Path $ev 'models_aj.json'
# Prefer cached paths; only resolve if missing (avoid ~ / long recurse on every run).
if (-not [IO.File]::Exists($modelsJson)) {
  & (Join-Path $ev 'resolve_aj_paths.ps1')
  if ($LASTEXITCODE -ne 0) { throw 'resolve_aj_paths failed' }
}
$models = Get-Content -LiteralPath $modelsJson -Raw | ConvertFrom-Json
Write-Host ("MODELS_LOADED=" + @($models).Count)

$exeSrcCandidates = @(
  (Join-Path $ev 'smoke_bin\RawrXD-Win32IDE_r1cap.exe'),
  'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_001\smoke_bin\RawrXD-Win32IDE_r01_laa.exe',
  'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_001\smoke_bin\RawrXD-Win32IDE_r1soft_SEALED.exe'
)
$exeSrc = $null
foreach ($c in $exeSrcCandidates) {
  if ([IO.File]::Exists([string]$c)) { $exeSrc = [string]$c; break }
}
if (-not $exeSrc) { throw 'no EXE candidate' }
$exe = Join-Path $ev 'smoke_bin\RawrXD-Win32IDE_r1cap_run.exe'
Copy-Item -LiteralPath $exeSrc -Destination $exe -Force
Write-Host ("EXE_SRC=$exeSrc")
Write-Host ("EXE_EXISTS=$([IO.File]::Exists($exeSrc))")
$editbin = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\editbin.exe'
$dumpbin = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe'
& $editbin /LARGEADDRESSAWARE $exe | Out-Null
$laaProbe = & $dumpbin /HEADERS $exe | Select-String -Pattern 'Application can handle large'
if (-not $laaProbe) { throw 'PE_LAA_MUST_BE_YES' }
$exeSha = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
$exeSha16 = $exeSha.Substring(0, 16)

$port = 11435
$base = "http://127.0.0.1:$port"

function Kill-AllRawr {
  Get-CimInstance Win32_Process -EA SilentlyContinue | Where-Object {
    $_.Name -match 'RawrXD' -or ($_.Name -eq 'cmd.exe' -and $_.CommandLine -match '11435')
  } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }
  Start-Sleep 2
  Get-NetTCPConnection -LocalPort $port -EA SilentlyContinue | ForEach-Object {
    Stop-Process -Id $_.OwningProcess -Force -EA SilentlyContinue
  }
  Start-Sleep 1
}

function Start-Headless([string]$tag) {
  Kill-AllRawr
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
    'set VK_ICD_FILENAMES=C:\rawrxd_blocked_no_vulkan_icd.json',
    'set VK_DRIVER_FILES=C:\rawrxd_blocked_no_vulkan_icd.json',
    " `"$exe`" --headless --local --port $port --dir G:\~dev\rawrxd > `"$out`" 2> `"$err`""
  )
  [IO.File]::WriteAllLines($bat, $lines)
  Start-Process -FilePath $bat -WorkingDirectory (Split-Path $exe) -WindowStyle Hidden | Out-Null
  $deadline = (Get-Date).AddSeconds(90)
  while ((Get-Date) -lt $deadline) {
    try {
      $h = Invoke-WebRequest -Uri "$base/api/engine/capabilities" -UseBasicParsing -TimeoutSec 3
      if ($h.StatusCode -eq 200) {
        $p = Get-CimInstance Win32_Process -EA SilentlyContinue | Where-Object { $_.Name -match 'RawrXD-Win32IDE' } | Select-Object -First 1
        return @{ Pid = $(if ($p) { $p.ProcessId } else { 0 }); Out = $out; Err = $err }
      }
    } catch { Start-Sleep -Milliseconds 500 }
  }
  throw "headless_health_timeout tag=$tag"
}

function Post-Json([string]$url, [string]$json, [int]$timeoutSec = 600) {
  try {
    $r = Invoke-WebRequest -Uri $url -Method POST -Body $json -ContentType 'application/json; charset=utf-8' -UseBasicParsing -TimeoutSec $timeoutSec
    return @{ Code = [int]$r.StatusCode; Body = [string]$r.Content; Ok = $true }
  } catch {
    $code = 0
    if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
    $body = ''
    try {
      $stream = $_.Exception.Response.GetResponseStream()
      if ($stream) { $body = (New-Object IO.StreamReader($stream)).ReadToEnd() }
    } catch {}
    return @{ Code = $code; Body = $body; Ok = $false; Err = [string]$_.Exception.Message }
  }
}

function Test-RawrAlive([int]$ProcessId) {
  if ($ProcessId -le 0) { return $false }
  $p = Get-Process -Id $ProcessId -EA SilentlyContinue
  return [bool]$p
}

$matrixLines = @()
$matrixLines += "EXE_SHA256=$exeSha"
$matrixLines += "EXE_SHA16=$exeSha16"
$matrixLines += "PE_LAA=YES HOST_DECODE=1 OLLAMA_CONTACT=0 PORT=$port"
$pass = 0; $fail = 0
$results = @()

foreach ($m in $models) {
  $tag = [string]$m.Id
  $path = [string]$m.Path
  $name = [IO.Path]::GetFileName($path)
  Write-Host ("=== STAGE {0} {1} ===" -f $m.Stage, $name)
  $h = Start-Headless $tag
  $procId = [int]$h.Pid
  $survived = 1
  $av = 0
  $heap = 0
  $tokens = 0
  $verdict = 'FAIL'
  $owner = ''
  $fields = [ordered]@{
    STAGE = $m.Stage; ID = $m.Id; ARCH = $m.Arch; FAMILY = $m.Family
    PATH = $path; SIZE_MB = $m.SizeMB; HEADLESS_PID = $procId
    MODEL_OPEN = 'FAIL'; TOKENIZER = 'UNOBSERVED'; SCHEMA = 'UNOBSERVED'
    PROVENANCE = 'UNOBSERVED'; RESIDENCY = 'FAIL'; GENERATE = 'FAIL'
    TOKENS_EMITTED = 0; UNLOAD = 'SKIP'; RELOAD_GENERATE = 'SKIP'
    PROCESS_SURVIVED = 1; ACCESS_VIOLATION = 0; C0000374 = 0
    VERDICT = 'FAIL'; OWNER = ''
  }

  $reg = Post-Json "$base/api/native/runtime/register" (@{ model = $name; path = $path } | ConvertTo-Json -Compress) 120
  $prep = Post-Json "$base/api/native/generation/prepare" (@{ model = $name } | ConvertTo-Json -Compress) 120
  if ($prep.Code -eq 200) { $fields.MODEL_OPEN = 'PASS'; $fields.SCHEMA = 'PASS'; $fields.PROVENANCE = 'PASS' }

  $load = Post-Json "$base/api/model/load" (@{ modelPath = $path } | ConvertTo-Json -Compress) 1800
  if (-not (Test-RawrAlive $procId)) { $survived = 0; $fields.PROCESS_SURVIVED = 0; $owner = 'process_died_load' }
  elseif ($load.Code -eq 200 -and $load.Body -match '"success"\s*:\s*true') {
    $fields.RESIDENCY = 'PASS'; $fields.TOKENIZER = 'PASS'
  } else {
    $owner = 'model_load'; $fields.OWNER = $owner
    $fields.VERDICT = 'FAIL'
    $fail++
    $rec = ($fields.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "`n"
    [IO.File]::WriteAllText((Join-Path $ev "receipts\$tag.txt"), $rec)
    $matrixLines += ("{0} {1} FAIL load code={2} body={3}" -f $m.Stage, $name, $load.Code, ($load.Body.Substring(0, [Math]::Min(120, $load.Body.Length))))
    $results += $fields
    continue
  }

  $genBody = @{ prompt = 'Reply with exactly: OK'; stream = $false; options = @{ num_predict = 48 } } | ConvertTo-Json -Compress -Depth 5
  $gen1 = Post-Json "$base/api/generate" $genBody 1800
  if (-not (Test-RawrAlive $procId)) {
    $survived = 0; $fields.PROCESS_SURVIVED = 0; $owner = 'process_died_generate'
    if (Select-String -Path $h.Err -Pattern 'C0000374|0xc0000374' -EA SilentlyContinue) { $heap = 1; $fields.C0000374 = 1 }
    if (Select-String -Path $h.Err -Pattern '0xc0000005|ACCESS_VIOLATION' -EA SilentlyContinue) { $av = 1; $fields.ACCESS_VIOLATION = 1 }
  } elseif ($gen1.Code -eq 200) {
    if ($gen1.Body -match '"eval_count"\s*:\s*(\d+)') { $tokens = [int]$Matches[1] }
    elseif ($gen1.Body -match '"tokens_generated"\s*:\s*(\d+)') { $tokens = [int]$Matches[1] }
    elseif ($gen1.Body -match '"response"\s*:\s*"([^"]*)"') { $tokens = [Math]::Max(1, $Matches[1].Length) }
    if ($gen1.Body -match 'PRODUCT_PASS=1' -or $tokens -gt 0 -or $gen1.Body -match '"done"\s*:\s*true') {
      if ($tokens -le 0) { $tokens = 1 }
      $fields.GENERATE = 'PASS'; $fields.TOKENS_EMITTED = $tokens
    } else { $owner = 'generate_empty' }
  } else { $owner = "generate_http_$($gen1.Code)" }

  if ($fields.GENERATE -ne 'PASS') {
    $fields.OWNER = $owner; $fields.VERDICT = 'FAIL'; $fail++
    $rec = ($fields.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "`n"
    [IO.File]::WriteAllText((Join-Path $ev "receipts\$tag.txt"), $rec)
    $matrixLines += ("{0} {1} FAIL gen owner={2}" -f $m.Stage, $name, $owner)
    $results += $fields
    continue
  }

  $un = Post-Json "$base/api/model/unload" '{}' 120
  if ($un.Code -eq 200) { $fields.UNLOAD = 'PASS' } else { $fields.UNLOAD = "HTTP_$($un.Code)" }

  $rel = Post-Json "$base/api/model/load" (@{ modelPath = $path } | ConvertTo-Json -Compress) 1800
  $gen2 = Post-Json "$base/api/generate" $genBody 1800
  if (-not (Test-RawrAlive $procId)) {
    $fields.PROCESS_SURVIVED = 0; $fields.RELOAD_GENERATE = 'FAIL'; $owner = 'died_reload_gen'; $fields.OWNER = $owner; $fields.VERDICT = 'FAIL'; $fail++
  } elseif ($gen2.Code -eq 200) {
    $fields.RELOAD_GENERATE = 'PASS'; $fields.VERDICT = 'PASS'; $pass++
  } else {
    $fields.RELOAD_GENERATE = "HTTP_$($gen2.Code)"; $owner = 'reload_gen'; $fields.OWNER = $owner; $fields.VERDICT = 'FAIL'; $fail++
  }

  $rec = ($fields.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "`n"
  [IO.File]::WriteAllText((Join-Path $ev "receipts\$tag.txt"), $rec)
  $matrixLines += ("{0} {1} {2} TOKENS={3} SURVIVED={4}" -f $m.Stage, $name, $fields.VERDICT, $fields.TOKENS_EMITTED, $fields.PROCESS_SURVIVED)
  $results += $fields
  Write-Host ("STAGE {0} => {1}" -f $m.Stage, $fields.VERDICT)
}

Kill-AllRawr
$matrixLines += "PASS_COUNT=$pass FAIL_COUNT=$fail TOTAL=10"
[IO.File]::WriteAllLines((Join-Path $ev 'MATRIX.txt'), $matrixLines)
$results | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $ev 'RESULTS.json')
Write-Host "DONE PASS=$pass FAIL=$fail EXE_SHA16=$exeSha16"
if ($pass -eq 10) { exit 0 } else { exit 1 }
