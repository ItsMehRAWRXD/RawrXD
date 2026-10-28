# SWARM_16_SMALL_HI_AUDIT_001 — Ollama /api/generate smoke (tip EXE absorb locked)
# PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 FAIL_CLOSED — no invented PASS
$ErrorActionPreference = "Continue"
$Base = "http://127.0.0.1:11434"
$OutDir = "g:\~dev\rawrxd\evidence\SWARM_16_SMALL_HI_AUDIT_001"
$AuditPath = "g:\~dev\rawrxd\src\win32app\Win32IDE_ToolActionStatus.cpp"
$ResultsCsv = Join-Path $OutDir "RESULTS.csv"
$LogPath = Join-Path $OutDir "RUNLOG.txt"

# Preferred unique local tags (skip cloud). Digest-dedupe applied after /api/tags.
$Prefer = @(
  "n4-tiny-oracle:latest",
  "qwen2.5-coder:1.5b-base",
  "embeddinggemma-2:740m",
  "llama3.2:3b",
  "qwen35-40b-heretic-q8:latest",
  "nemotron-3-nano:4b",
  "gemma3:4b",
  "llama3.1:8b",
  "granite3.3:8b",
  "qwen3:8b",
  "kiminoto/T0.0.1:latest",
  "pdurugyan/qwen3.5-9b-deepseek-v4-flash-Q4_K_M-v_2:latest",
  "deepseek-coder-v2:16b",
  "starcoder2:15b",
  "gpt-oss:20b",
  "flint:latest"
)
$Fillers = @("nemotron-3.5-bolt:latest")

function Write-Log([string]$m) {
  $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"), $m
  Add-Content -Path $LogPath -Value $line
  Write-Output $line
}

function Invoke-Generate([string]$model, [string]$prompt, [int]$numPredict, [int]$timeoutSec) {
  $bodyObj = @{
    model = $model
    prompt = $prompt
    stream = $false
    options = @{ num_predict = $numPredict; temperature = 0.1 }
  }
  $json = $bodyObj | ConvertTo-Json -Compress -Depth 5
  try {
    $resp = Invoke-RestMethod -Uri "$Base/api/generate" -Method Post -Body $json `
      -ContentType "application/json" -TimeoutSec $timeoutSec
    $text = [string]$resp.response
    if ([string]::IsNullOrWhiteSpace($text)) {
      return @{ ok = $false; err = "EMPTY_RESPONSE"; text = "" }
    }
    $len = [Math]::Min(400, $text.Length)
    return @{ ok = $true; err = ""; text = $text.Substring(0, $len) }
  } catch {
    return @{ ok = $false; err = $_.Exception.Message; text = "" }
  }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
"" | Set-Content $LogPath
Write-Log "START SWARM_16_SMALL_HI_AUDIT_001"
Write-Log "PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0"

try {
  $tags = Invoke-RestMethod -Uri "$Base/api/tags" -TimeoutSec 10
} catch {
  Write-Log "FAIL_CLOSED: Ollama /api/tags unreachable: $($_.Exception.Message)"
  "N=0`nTAGS_REACHABLE=0`nHI_PASS=0`nAUDIT_PASS=0`nORCH_PASS=0`nPROMOTE=0" |
    Set-Content (Join-Path $OutDir "SUMMARY.txt")
  exit 2
}

$byName = @{}
foreach ($m in $tags.models) {
  $name = [string]$m.name
  $dig = ([string]$m.digest)
  if ($dig.Length -gt 12) { $dig = $dig.Substring(0, 12) }
  $cloud = ($name -match ":cloud$" -or [string]$m.remote_host)
  if ($cloud) { continue }
  $byName[$name] = @{ name = $name; digest = $dig; size = [int64]$m.size }
}

$selected = New-Object System.Collections.Generic.List[object]
$seenDig = @{}
function Try-Add([string]$name) {
  if (-not $byName.ContainsKey($name)) { return $false }
  $info = $byName[$name]
  $d = $info.digest
  if ($seenDig.ContainsKey($d)) { return $false }
  $seenDig[$d] = $true
  $selected.Add($info) | Out-Null
  return $true
}

foreach ($p in $Prefer) {
  if ($selected.Count -ge 16) { break }
  [void](Try-Add $p)
}
foreach ($p in $Fillers) {
  if ($selected.Count -ge 16) { break }
  [void](Try-Add $p)
}
if ($selected.Count -lt 16) {
  $rest = $byName.Values | Sort-Object size
  foreach ($info in $rest) {
    if ($selected.Count -ge 16) { break }
    if ($seenDig.ContainsKey($info.digest)) { continue }
    $seenDig[$info.digest] = $true
    $selected.Add($info) | Out-Null
  }
}

$N = $selected.Count
Write-Log "N=$N unique local non-cloud after digest dedupe"
$selected | ForEach-Object {
  Write-Log ("MODEL {0} digest={1} size={2}" -f $_.name, $_.digest, $_.size)
}
($selected | ForEach-Object { "{0}`t{1}`t{2}" -f $_.name, $_.digest, $_.size }) |
  Set-Content (Join-Path $OutDir "MODELS.tsv")

if ($N -eq 0) {
  Write-Log "FAIL_CLOSED: N=0"
  "N=0`nTAGS_REACHABLE=1`nHI_PASS=0`nAUDIT_PASS=0`nORCH_PASS=0`nPROMOTE=0" |
    Set-Content (Join-Path $OutDir "SUMMARY.txt")
  exit 3
}

if (-not (Test-Path $AuditPath)) {
  Write-Log "FAIL_CLOSED: audit file missing $AuditPath"
  exit 4
}
$auditSrc = Get-Content -Raw -Path $AuditPath
if ($auditSrc.Length -gt 3500) { $auditSrc = $auditSrc.Substring(0, 3500) }
$auditPrompt = @"
Audit this C++ file for synthetic success / FinishedAction risks. Reply in <=3 sentences.
FILE=$AuditPath
----
$auditSrc
"@

"model,gate,status,err,snippet" | Set-Content $ResultsCsv
$hiPass = 0; $hiFail = 0; $auditPass = 0; $auditFail = 0
$i = 0
foreach ($info in $selected) {
  $i++
  $model = $info.name
  $timeout = 120
  if ($info.size -gt 8GB) { $timeout = 300 }
  if ($info.size -gt 15GB) { $timeout = 480 }
  Write-Log "[$i/$N] HI $model timeout=${timeout}s"
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $r = Invoke-Generate $model "hi" 24 $timeout
  $sw.Stop()
  $st = if ($r.ok) { "PASS" } else { "FAIL" }
  if ($r.ok) { $hiPass++ } else { $hiFail++ }
  $snip = ($r.text -replace '[,\r\n]+', ' ')
  $err = ($r.err -replace '[,\r\n]+', ' ')
  $sLen = [Math]::Min(120, $snip.Length)
  Add-Content $ResultsCsv ("{0},HI,{1},{2},{3}" -f $model, $st, $err, $snip.Substring(0, $sLen))
  Write-Log ("  HI {0} elapsed_ms={1} err={2}" -f $st, $sw.ElapsedMilliseconds, $r.err)

  Write-Log "[$i/$N] AUDIT $model"
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $r2 = Invoke-Generate $model $auditPrompt 64 $timeout
  $sw.Stop()
  $st2 = if ($r2.ok) { "PASS" } else { "FAIL" }
  if ($r2.ok) { $auditPass++ } else { $auditFail++ }
  $snip2 = ($r2.text -replace '[,\r\n]+', ' ')
  $err2 = ($r2.err -replace '[,\r\n]+', ' ')
  $sLen2 = [Math]::Min(120, $snip2.Length)
  Add-Content $ResultsCsv ("{0},AUDIT,{1},{2},{3}" -f $model, $st2, $err2, $snip2.Substring(0, $sLen2))
  Write-Log ("  AUDIT {0} elapsed_ms={1} err={2}" -f $st2, $sw.ElapsedMilliseconds, $r2.err)
}

$orch = if ($hiPass -eq $N) { "PASS" } else { "FAIL" }
$auditGate = if ($auditPass -eq $N) { "PASS" } else { "FAIL" }
$summary = @"
N=$N
TAGS_REACHABLE=1
HI_PASS=$hiPass
HI_FAIL=$hiFail
AUDIT_PASS=$auditPass
AUDIT_FAIL=$auditFail
ORCH_1_TO_N=$orch
FILE_AUDIT_GATE=$auditGate
AUDIT_FILE=$AuditPath
HARNESS=evidence/SWARM_16_SMALL_HI_AUDIT_001/harness_ollama_swarm16.ps1
RUNTIME_REACHED=1
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
"@
$summary | Set-Content (Join-Path $OutDir "SUMMARY.txt")
Write-Log ($summary -replace "`r?`n", " | ")
Write-Log "DONE"
exit 0
