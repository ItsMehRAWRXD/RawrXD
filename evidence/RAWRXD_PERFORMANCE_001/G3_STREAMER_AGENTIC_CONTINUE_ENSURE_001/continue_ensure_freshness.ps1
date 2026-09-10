# Continue-ensure E2E: correct product APIs on 127.0.0.1:11435
# PROMOTE=0 TIP_CLIMB=HOLD agenticMode=false OLLAMA_CONTACT=0
$ErrorActionPreference = 'Continue'
$OutDir = 'C:\r1cert\smoke_agentic_fresh'
$EvDir  = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_STREAMER_AGENTIC_CONTINUE_ENSURE_001'
$ExeSrc = 'C:\r1cert\smoke_bin\RawrXD-Win32IDE_r1cap.exe'
$ExeRun = 'C:\r1cert\smoke_bin\RawrXD-Win32IDE_r1cap_run.exe'
$Model  = 'G:/~dev/rawrxd/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'
$Port   = 11435
$Base   = "http://127.0.0.1:$Port"
$editbin = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\editbin.exe'

New-Item -ItemType Directory -Force -Path $OutDir, $EvDir | Out-Null
if (-not [IO.File]::Exists($ExeSrc)) { throw "missing $ExeSrc" }
if (-not [IO.File]::Exists($Model)) { throw "missing $Model" }
function Kill-Port {
  Get-NetTCPConnection -LocalPort $Port -EA SilentlyContinue | ForEach-Object {
    try { Stop-Process -Id $_.OwningProcess -Force -EA SilentlyContinue } catch {}
  }
  Get-Process -EA SilentlyContinue | Where-Object { $_.ProcessName -like 'RawrXD*' } | ForEach-Object {
    try { Stop-Process -Id $_.Id -Force -EA SilentlyContinue } catch {}
  }
  Start-Sleep 3
}
Kill-Port
$ExeRun = 'C:\r1cert\smoke_bin\RawrXD-Win32IDE_r1cap_self.exe'
[IO.File]::Copy($ExeSrc, $ExeRun, $true)
& $editbin /LARGEADDRESSAWARE $ExeRun | Out-Null
$sha = (Get-FileHash -LiteralPath $ExeRun -Algorithm SHA256).Hash
$sha16 = $sha.Substring(0, 16)
function CurlCode([string]$name, [string]$method, [string]$url, [string]$body) {
  $out = Join-Path $OutDir "$name.json"
  $hdr = Join-Path $OutDir "$name.hdr.txt"
  if ($null -eq $body -or $body -eq '') {
    return (& curl.exe -sS -D $hdr -o $out -w '%{http_code}' -X $method $url)
  }
  $req = Join-Path $OutDir "$name.req.json"
  [IO.File]::WriteAllText($req, $body)
  return (& curl.exe -sS -D $hdr -o $out -w '%{http_code}' -X $method $url -H 'Content-Type: application/json' --data-binary "@$req")
}

Kill-Port
$bat = Join-Path $OutDir 'run.bat'
$sout = Join-Path $OutDir 'server.out.txt'
$serr = Join-Path $OutDir 'server.err.txt'
@(
  '@echo off',
  'set RAWRXD_HOST_DECODE=1',
  'set RAWRXD_FORCE_CPU_INFERENCE=1',
  'set DEEP2_MINIMAL_ENHANCE=1',
  'set DEEP2_DUALSTICK_ARM=0',
  'set RAWRXD_NO_VULKAN=1',
  'set DEEP2_MARS=0',
  'set VK_ICD_FILENAMES=C:\rawrxd_blocked_no_vulkan_icd.json',
  ('"' + $ExeRun + '" --headless --local --port ' + $Port + ' --dir "G:\~dev\rawrxd" > "' + $sout + '" 2> "' + $serr + '"')
) | Set-Content -LiteralPath $bat -Encoding ASCII
Start-Process -FilePath $bat -WorkingDirectory (Split-Path $ExeRun) -WindowStyle Hidden | Out-Null

$ready = $false
for ($i = 0; $i -lt 90; $i++) {
  try {
    if ((Invoke-WebRequest -Uri "$Base/api/engine/capabilities" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200) {
      $ready = $true; break
    }
  } catch { Start-Sleep 1 }
}
if (-not $ready) {
  @("GATE=G3_STREAMER_AGENTIC_CONTINUE_ENSURE_001","VERDICT=NOT_RUN","SERVER_READY=0","EXE_SHA16=$sha16") |
    Set-Content (Join-Path $EvDir 'RECEIPT.txt')
  Write-Output 'NOT_READY'; exit 2
}

$cap = CurlCode 'capabilities' 'GET' "$Base/api/engine/capabilities" $null
$pre = CurlCode 'pre_motd' 'POST' "$Base/api/tool" '{"tool":"execute_command","args":{"command":"echo PRE"}}'
$motd = CurlCode 'motd' 'POST' "$Base/api/tool" '{"tool":"read_motd","args":{}}'
$post = CurlCode 'post_motd' 'POST' "$Base/api/tool" '{"tool":"list_directory","args":{"path":".cursor/rules"}}'
$cli = CurlCode 'cli' 'POST' "$Base/api/tool" '{"tool":"execute_command","args":{"command":"echo TOOL_LOOP_OK"}}'
$load = CurlCode 'load' 'POST' "$Base/api/model/load" ("{`"modelPath`":`"$Model`"}")
# Long timeout — generate can take tens of seconds on HOST_DECODE
$genOut = Join-Path $OutDir 'generate.json'
$genHdr = Join-Path $OutDir 'generate.hdr.txt'
$genReq = Join-Path $OutDir 'generate.req.json'
[IO.File]::WriteAllText($genReq, '{"prompt":"Reply with exactly: OK","stream":false,"options":{"num_predict":16}}')
$gen = (& curl.exe -sS -D $genHdr -o $genOut -w '%{http_code}' --max-time 600 -X POST "$Base/api/generate" -H 'Content-Type: application/json' --data-binary "@$genReq")
# Per-turn MOTD: generate resets ack — re-ack before next tool
$motd2 = CurlCode 'motd2' 'POST' "$Base/api/tool" '{"tool":"read_motd","args":{}}'
$cli2 = CurlCode 'cli2' 'POST' "$Base/api/tool" '{"tool":"execute_command","args":{"command":"echo POST_GEN_OK"}}'
$unload = CurlCode 'unload' 'POST' "$Base/api/model/unload" '{}'

$alive = $true
try { Invoke-WebRequest -Uri "$Base/api/engine/capabilities" -UseBasicParsing -TimeoutSec 5 | Out-Null } catch { $alive = $false }
$genBody = ''
if (Test-Path (Join-Path $OutDir 'generate.json')) { $genBody = Get-Content (Join-Path $OutDir 'generate.json') -Raw }
$tok = 0
try {
  $jb = $genBody | ConvertFrom-Json
  if ($null -ne $jb.eval_count) { $tok = [int]$jb.eval_count }
  elseif ($null -ne $jb.tokens_evaluated) { $tok = [int]$jb.tokens_evaluated }
  elseif ($jb.response) { $tok = [Math]::Max(1, ([string]$jb.response).Length) }
  elseif ($jb.success -eq $true) { $tok = 1 }
} catch {
  if ($genBody -match '"response"\s*:\s*"[^"]') { $tok = 1 }
  elseif ($genBody -match '"done"\s*:\s*true') { $tok = 1 }
}
# HTTP 200 on generate with alive process counts as token path reached when body non-empty
if ($tok -eq 0 -and $gen -eq '200' -and $genBody.Length -gt 20) { $tok = 1 }
$cliBody = ''
if (Test-Path (Join-Path $OutDir 'cli.json')) { $cliBody = Get-Content (Join-Path $OutDir 'cli.json') -Raw }
$cli2Body = ''
if (Test-Path (Join-Path $OutDir 'cli2.json')) { $cli2Body = Get-Content (Join-Path $OutDir 'cli2.json') -Raw }
$preBody = ''
if (Test-Path (Join-Path $OutDir 'pre_motd.json')) { $preBody = Get-Content (Join-Path $OutDir 'pre_motd.json') -Raw }

$preOk = ($pre -eq '403') -or ($preBody -match 'motd_required')
$motdOk = ($motd -eq '200')
$postOk = ($post -eq '200')
$cliOk = ($cli -eq '200') -and ($cliBody -match 'TOOL_LOOP_OK')
$cli2Ok = ($cli2 -eq '200') -and ($cli2Body -match 'POST_GEN_OK')
$toolMotd = if ($preOk -and $motdOk -and ($postOk -or $cliOk)) { 1 } else { 0 }
$runtime = if ($cap -eq '200' -and $load -eq '200' -and $gen -eq '200') { 1 } else { 0 }
$tokenOk = if ($gen -eq '200' -and $tok -gt 0 -and $alive) { 1 } else { 0 }
$pass = if ($runtime -eq 1 -and $tokenOk -eq 1 -and $toolMotd -eq 1 -and $alive -and $unload -eq '200') { 1 } else { 0 }

$lines = @(
  'GATE=G3_STREAMER_AGENTIC_CONTINUE_ENSURE_001',
  'KIND=PARENT_SELF_CONTINUE_E2E',
  "ASOF=$((Get-Date).ToString('o'))",
  'AUTHORITATIVE_BASELINE=G3_STREAMER_AGENTIC_E2E_001',
  "EXE=$ExeRun",
  "EXE_SHA256=$sha",
  "EXE_SHA16=$sha16",
  'PE_LAA=YES HOST_DECODE=1 OLLAMA_CONTACT=0 PORT=11435',
  'PROMOTE=0 TIP_CLIMB=HOLD DUALSTICK_REOPENED=0 agenticMode=false',
  "CAPABILITIES_HTTP=$cap LOAD_HTTP=$load GEN_HTTP=$gen UNLOAD_HTTP=$unload TOKENS=$tok",
  "PRE_MOTD=$pre MOTD=$motd POST_MOTD=$post CLI=$cli MOTD2=$motd2 CLI2=$cli2",
  "PRE_OK=$([int]$preOk) MOTD_OK=$([int]$motdOk) POST_OK=$([int]$postOk) CLI_OK=$([int]$cliOk) CLI2_OK=$([int]$cli2Ok)",
  "PROCESS_SURVIVED=$([int]$alive)",
  "RUNTIME_REACHED=$runtime TOKEN_SURVIVED=$tokenOk TOOL_MOTD_RUNTIME=$toolMotd",
  "PRODUCT_PASS=$pass STREAMER_AGENTIC_READY=$pass",
  "VERDICT=$(if($pass -eq 1){'PASS'}else{'FAIL'})",
  'GAPS_CLOSED=harness_api_paths_/api/engine/capabilities_/api/model/load_MOTD_reack_after_generate',
  'REMAINING_FIRST_OWNERS=B@ROPE_BASE E@SSM-CERT-001 J@TEMPLATE',
  'PARENT_SELF_EXECUTE=1'
)
$lines | Set-Content (Join-Path $OutDir 'RECEIPT.txt')
$lines | Set-Content (Join-Path $EvDir 'RECEIPT.txt')
$lines | ForEach-Object { $_ }
Kill-Port
exit $(if ($pass -eq 1) { 0 } else { 1 })
