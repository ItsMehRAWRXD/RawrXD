# ce9: MOTD .mdc ladder on build-fd Win32IDE (no smoke_bin). PROMOTE=0 TIP_CLIMB=HOLD
$ErrorActionPreference = 'Continue'
$EvDir = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_STREAMER_AGENTIC_CONTINUE_ENSURE_001'
$OutDir = Join-Path $EvDir 'ce9_out'
$Exe = 'G:\~dev\rawrxd\build-fd\bin\RawrXD-Win32IDE.exe'
$Port = 11443
$Base = "http://127.0.0.1:$Port"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Kill-Port {
  Get-NetTCPConnection -LocalPort $Port -EA SilentlyContinue | ForEach-Object {
    try { Stop-Process -Id $_.OwningProcess -Force -EA SilentlyContinue } catch {}
  }
}
Kill-Port
Start-Sleep 1

$sha = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash
$sha16 = $sha.Substring(0, 16)
$sout = Join-Path $OutDir 'server.out.txt'
$serr = Join-Path $OutDir 'server.err.txt'
$env:RAWRXD_HOST_DECODE = '1'
$env:RAWRXD_FORCE_CPU_INFERENCE = '1'
$env:DEEP2_MINIMAL_ENHANCE = '1'
$env:DEEP2_DUALSTICK_ARM = '0'
$env:RAWRXD_NO_VULKAN = '1'
$env:DEEP2_MARS = '0'
$env:VK_ICD_FILENAMES = 'C:\rawrxd_blocked_no_vulkan_icd.json'
$p = Start-Process -FilePath $Exe -ArgumentList @('--headless','--local',"--port",$Port,'--dir','G:\~dev\rawrxd') `
  -WorkingDirectory (Split-Path $Exe) -RedirectStandardOutput $sout -RedirectStandardError $serr -PassThru -WindowStyle Hidden

$ready = $false
for ($i = 0; $i -lt 60; $i++) {
  try {
    if ((Invoke-WebRequest -Uri "$Base/api/engine/capabilities" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200) {
      $ready = $true; break
    }
  } catch { Start-Sleep 1 }
}

function CurlCode([string]$name, [string]$method, [string]$url, [string]$body) {
  $out = Join-Path $OutDir "$name.json"
  if ($null -eq $body -or $body -eq '') {
    return (& curl.exe -sS -o $out -w '%{http_code}' -X $method $url)
  }
  $req = Join-Path $OutDir "$name.req.json"
  [IO.File]::WriteAllText($req, $body)
  return (& curl.exe -sS -o $out -w '%{http_code}' -X $method $url -H 'Content-Type: application/json' --data-binary "@$req")
}

if (-not $ready) {
  @(
    'GATE=G3_STREAMER_AGENTIC_CONTINUE_ENSURE_001',
    'PROBE=ce9_mdc_ladder',
    'VERDICT=NOT_RUN',
    'SERVER_READY=0',
    "EXE_SHA16=$sha16"
  ) | Set-Content (Join-Path $EvDir 'ce9_LIVE_PROBE.txt')
  try { Stop-Process -Id $p.Id -Force -EA SilentlyContinue } catch {}
  Write-Output 'NOT_READY'; exit 2
}

$pre = CurlCode 'pre' 'POST' "$Base/api/tool" '{"tool":"execute_command","args":{"command":"echo PRE"}}'
$motd = CurlCode 'motd' 'POST' "$Base/api/tool" '{"tool":"read_motd","args":{}}'
# Reset ack via generate is heavy; use list then re-test mdc by killing ack via second session:
# Explicit .mdc leaf read after forcing re-block: POST generate is optional.
# Instead: restart tool session isn't available — call mdc after pre would still be acked.
# Probe: kill process and re-test mdc-only path on fresh server for MDC leaf.
$post = CurlCode 'post' 'POST' "$Base/api/tool" '{"tool":"list_directory","args":{"path":".cursor/rules"}}'
$mdc = CurlCode 'motd_mdc' 'POST' "$Base/api/tool" '{"tool":"read_file","args":{"path":".cursor/rules/PassiveRoleNotRoleplay.mdc"}}'
$cli = CurlCode 'cli' 'POST' "$Base/api/tool" '{"tool":"execute_command","args":{"command":"echo TOOL_LOOP_OK"}}'

# Fresh MOTD_ACK=0: hit /api/generate with tiny request OR restart. Prefer restart for MDC-first.
try { Stop-Process -Id $p.Id -Force -EA SilentlyContinue } catch {}
Kill-Port
Start-Sleep 2
$p2 = Start-Process -FilePath $Exe -ArgumentList @('--headless','--local',"--port",$Port,'--dir','G:\~dev\rawrxd') `
  -WorkingDirectory (Split-Path $Exe) -RedirectStandardOutput (Join-Path $OutDir 'server2.out.txt') `
  -RedirectStandardError (Join-Path $OutDir 'server2.err.txt') -PassThru -WindowStyle Hidden
$ready2 = $false
for ($i = 0; $i -lt 60; $i++) {
  try {
    if ((Invoke-WebRequest -Uri "$Base/api/engine/capabilities" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200) {
      $ready2 = $true; break
    }
  } catch { Start-Sleep 1 }
}
$pre2 = '0'; $mdcFirst = '0'; $post2 = '0'
if ($ready2) {
  $pre2 = CurlCode 'pre2' 'POST' "$Base/api/tool" '{"tool":"execute_command","args":{"command":"echo PRE2"}}'
  $mdcFirst = CurlCode 'mdc_first' 'POST' "$Base/api/tool" '{"tool":"read_file","args":{"path":".cursor/rules/PassiveRoleNotRoleplay.mdc"}}'
  $post2 = CurlCode 'post2' 'POST' "$Base/api/tool" '{"tool":"list_directory","args":{"path":".cursor/rules"}}'
}
$alive = $false
try { $alive = -not $p2.HasExited } catch {}
try { Stop-Process -Id $p2.Id -Force -EA SilentlyContinue } catch {}
Kill-Port

$mdcOk = ($mdc -eq '200') -or ($mdcFirst -eq '200')
$ladderOk = ($pre -eq '403') -and ($motd -eq '200') -and ($post -eq '200') -and ($cli -eq '200')
$mdcLadderOk = ($pre2 -eq '403') -and ($mdcFirst -eq '200') -and ($post2 -eq '200')

@(
  'GATE=G3_STREAMER_AGENTIC_CONTINUE_ENSURE_001',
  'PROBE=ce9_mdc_ladder',
  "ASOF=$((Get-Date).ToString('o'))",
  "EXE=$Exe",
  "EXE_SHA256=$sha",
  "EXE_SHA16=$sha16",
  "PORT=$Port",
  'PROMOTE=0 TIP_CLIMB=HOLD',
  "SERVER_READY=$([int]$ready)",
  "TOOL_PRE=$pre TOOL_MOTD=$motd TOOL_POST=$post TOOL_CLI=$cli TOOL_MOTD_MDC_WHILE_ACKED=$mdc",
  "TOOL_PRE2=$pre2 TOOL_MOTD_MDC_FIRST=$mdcFirst TOOL_POST2=$post2",
  "MDC_LEAF_OK=$([int]$mdcOk) MDC_FIRST_LADDER_OK=$([int]$mdcLadderOk) CLASSIC_LADDER_OK=$([int]$ladderOk)",
  "PROCESS_SURVIVED=$([int]$alive)",
  "SOURCE_WIRED=1 RUNTIME_REACHED=$([int]$ready) TOKEN_SURVIVED=NOT_RUN PERFORMANCE_PASS=0",
  "VERDICT=$(if ($mdcLadderOk -and $ladderOk) { 'PASS_MDC_GAP_CLOSED' } else { 'FAIL_OR_PARTIAL' })"
) | Set-Content (Join-Path $EvDir 'ce9_LIVE_PROBE.txt')
Get-Content (Join-Path $EvDir 'ce9_LIVE_PROBE.txt')
Write-Output "DONE pre=$pre motd=$motd mdcFirst=$mdcFirst post2=$post2"
