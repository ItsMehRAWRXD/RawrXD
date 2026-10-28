# SWARM_16_THINKING_CLASSIFY_001 — thinking-aware response classification (v3)
# PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 FAIL_CLOSED — no invented PASS
# Additive to SWARM_16_SMALL_HI_AUDIT_001/002 (seals untouched).
# PASS requires usable_final_answer=1 (non-empty response=). Thinking-only != PASS.
param(
  [string[]]$Models = @("qwen3:8b"),
  [switch]$ThinkTrue,
  [int]$NumPredict = 48,
  [int]$TimeoutSec = 180
)
$ErrorActionPreference = "Continue"
$Base = "http://127.0.0.1:11434"
$OutDir = "g:\~dev\rawrxd\evidence\SWARM_16_THINKING_CLASSIFY_001"
$ResultsCsv = Join-Path $OutDir "RESULTS.csv"
$ClassCsv = Join-Path $OutDir "CLASSIFY.csv"
$LogPath = Join-Path $OutDir "RUNLOG.txt"
$ProbeJsonDir = Join-Path $OutDir "probes"

function Write-Log([string]$m) {
  $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"), $m
  Add-Content -Path $LogPath -Value $line
  Write-Output $line
}

function Estimate-Tokens([string]$text) {
  if ([string]::IsNullOrEmpty($text)) { return 0 }
  return [int][Math]::Max(1, [Math]::Ceiling($text.Length / 4.0))
}

function Classify-Generate([string]$model, [string]$prompt, [int]$numPredict, [int]$timeoutSec, [bool]$think) {
  $bodyObj = @{
    model = $model
    prompt = $prompt
    stream = $false
    think = $think
    options = @{ num_predict = $numPredict; temperature = 0.1 }
  }
  $json = $bodyObj | ConvertTo-Json -Compress -Depth 5
  $out = @{
    ok = $false
    err = ""
    response = ""
    thinking = ""
    done_reason = ""
    eval_count = 0
    thinking_tokens = 0
    response_tokens = 0
    usable_final_answer = 0
    classify = "UNKNOWN"
    raw = $null
  }
  try {
    $resp = Invoke-RestMethod -Uri "$Base/api/generate" -Method Post -Body $json `
      -ContentType "application/json" -TimeoutSec $timeoutSec
    $out.raw = $resp
    $text = [string]$resp.response
    $th = [string]$resp.thinking
    if ($null -eq $text) { $text = "" }
    if ($null -eq $th) { $th = "" }
    $out.response = $text
    $out.thinking = $th
    $out.done_reason = [string]$resp.done_reason
    if ([string]::IsNullOrWhiteSpace($out.done_reason)) {
      if ($resp.done -eq $true) { $out.done_reason = "stop" } else { $out.done_reason = "unknown" }
    }
    $eval = 0
    if ($null -ne $resp.eval_count) { $eval = [int]$resp.eval_count }
    $out.eval_count = $eval

    $respTok = 0
    $thinkTok = 0
    if (-not [string]::IsNullOrWhiteSpace($text)) {
      $respTok = Estimate-Tokens $text.Trim()
    }
    if (-not [string]::IsNullOrWhiteSpace($th)) {
      $thinkTok = Estimate-Tokens $th.Trim()
    }
    if ($respTok -eq 0 -and $thinkTok -gt 0 -and $eval -gt 0) {
      $thinkTok = $eval
    } elseif ($thinkTok -eq 0 -and $respTok -gt 0 -and $eval -gt 0) {
      $respTok = $eval
    } elseif ($respTok -gt 0 -and $thinkTok -gt 0 -and $eval -gt 0) {
      $tc = $th.Trim().Length
      $rc = $text.Trim().Length
      $sum = [Math]::Max(1, $tc + $rc)
      $thinkTok = [int][Math]::Round($eval * ($tc / $sum))
      $respTok = [int][Math]::Max(0, $eval - $thinkTok)
    }
    $out.thinking_tokens = $thinkTok
    $out.response_tokens = $respTok

    $usable = (-not [string]::IsNullOrWhiteSpace($text))
    $out.usable_final_answer = if ($usable) { 1 } else { 0 }

    if ($usable) {
      $out.ok = $true
      $out.classify = "FINAL_ANSWER"
      $out.err = ""
    } elseif (-not [string]::IsNullOrWhiteSpace($th)) {
      $out.ok = $false
      $out.classify = "THINKING_ONLY"
      if ($out.done_reason -eq "length") {
        $out.err = "EMPTY_RESPONSE_THINKING_ONLY_LENGTH"
      } else {
        $out.err = "EMPTY_RESPONSE_THINKING_ONLY"
      }
    } else {
      $out.ok = $false
      $out.classify = "EMPTY"
      $out.err = "EMPTY_RESPONSE"
    }
  } catch {
    $out.ok = $false
    $out.err = $_.Exception.Message
    $out.classify = "HTTP_OR_TRANSPORT"
    $msg = $_.Exception.Message
    if ($msg -match '\(400\)') { $out.classify = "HTTP_400" }
  }
  return $out
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-Item -ItemType Directory -Force -Path $ProbeJsonDir | Out-Null
"" | Set-Content $LogPath
Write-Log "START SWARM_16_THINKING_CLASSIFY_001"
Write-Log "PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0"
Write-Log "HARNESS=harness_ollama_thinking_classify_v3.ps1"
Write-Log "CONTRACT: PASS <=> usable_final_answer=1; thinking-only != PASS"

if ($env:SWARM16_CLASSIFY_MODELS) {
  $Models = @($env:SWARM16_CLASSIFY_MODELS -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

try {
  $null = Invoke-RestMethod -Uri "$Base/api/tags" -TimeoutSec 10
} catch {
  Write-Log "FAIL_CLOSED: Ollama /api/tags unreachable: $($_.Exception.Message)"
  "N=0`nTAGS_REACHABLE=0`nCLASSIFY_PASS=0`nPROMOTE=0" |
    Set-Content (Join-Path $OutDir "SUMMARY.txt")
  exit 2
}

$hdr = "model,gate,status,err,thinking_tokens,response_tokens,done_reason,usable_final_answer,classify,snippet"
$hdr | Set-Content $ResultsCsv
$hdr | Set-Content $ClassCsv

$pass = 0; $fail = 0; $thinkingOnly = 0
$i = 0
$N = $Models.Count
$thinkFlag = [bool]$ThinkTrue
Write-Log ("MODELS={0} think={1} num_predict={2}" -f ($Models -join ','), $thinkFlag, $NumPredict)

foreach ($model in $Models) {
  $i++
  Write-Log "[$i/$N] HI classify $model"
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $r = Classify-Generate $model "hi" $NumPredict $TimeoutSec $thinkFlag
  $sw.Stop()

  $safeName = ($model -replace '[\\/:*?"<>|]', '_')
  $probePath = Join-Path $ProbeJsonDir ("probe_{0}_hi.json" -f $safeName)
  if ($null -ne $r.raw) {
    ($r.raw | ConvertTo-Json -Depth 8) | Set-Content $probePath
  } else {
    (@{ error = $r.err; classify = $r.classify } | ConvertTo-Json) | Set-Content $probePath
  }

  $st = if ($r.ok -and $r.usable_final_answer -eq 1) { "PASS" } else { "FAIL" }
  if ($st -eq "PASS") { $pass++ } else { $fail++ }
  if ($r.classify -eq "THINKING_ONLY") { $thinkingOnly++ }

  $snip = (($r.response + " |T| " + $r.thinking) -replace '[,\r\n]+', ' ')
  if ($snip.Length -gt 160) { $snip = $snip.Substring(0, 160) }
  $err = ($r.err -replace '[,\r\n]+', ' ')
  $row = "{0},HI,{1},{2},{3},{4},{5},{6},{7},{8}" -f `
    $model, $st, $err, $r.thinking_tokens, $r.response_tokens, `
    $r.done_reason, $r.usable_final_answer, $r.classify, $snip
  Add-Content $ResultsCsv $row
  Add-Content $ClassCsv $row
  Write-Log ("  {0} classify={1} usable={2} think_tok={3} resp_tok={4} done_reason={5} err={6} ms={7}" -f `
    $st, $r.classify, $r.usable_final_answer, $r.thinking_tokens, $r.response_tokens, `
    $r.done_reason, $r.err, $sw.ElapsedMilliseconds)
}

$summary = @"
N=$N
TAGS_REACHABLE=1
CLASSIFY_PASS=$pass
CLASSIFY_FAIL=$fail
THINKING_ONLY=$thinkingOnly
HARNESS=evidence/SWARM_16_THINKING_CLASSIFY_001/harness_ollama_thinking_classify_v3.ps1
CONTRACT=usable_final_answer_required
FIELDS=thinking_tokens,response_tokens,done_reason,usable_final_answer
PRESERVE_001=1
PRESERVE_002=1
RUNTIME_REACHED=1
TIP_EXE_RUNTIME=NOT_RUN
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
"@
$summary | Set-Content (Join-Path $OutDir "SUMMARY.txt")
Write-Log ($summary -replace "`r?`n", " | ")
Write-Log "DONE"
exit 0
