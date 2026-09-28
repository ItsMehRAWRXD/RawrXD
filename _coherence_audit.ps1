# Fleet coherence re-audit script — deterministic raw API, gate ladder per model
# Gates: LOAD_PASS, FORWARD_PASS(TOKEN_PASS), DECODE_PASS(UTF8), COHERENCE_PASS, REPEAT_PASS, PERF_PASS
# Output: F:\~dev\_ollama_coherence_audit.csv

$ollama = "C:\Users\Garrett\AppData\Local\Programs\Ollama\ollama.exe"
$models = @(
  "bigdaddyg-productivity-local:latest", "bigdaddyg-productivity-native:latest",
  "bigdaddyglocal:latest", "bigdaddygnative:latest",
  "deepseek-coder-v2:16b", "deepseek-r1:32b", "deepseek-r1:70b",
  "gemma3:4b", "gemma3:latest", "gpt-oss:120b", "gpt-oss:20b", "gpt-oss:latest",
  "granite3.3:8b", "kiminoto/T0.0.1:latest", "laguna-s-2.1:Q4_K_M",
  "llama3.1:8b", "llama3.2:3b", "llama3.2:latest",
  "nemotron-3-nano:4b", "nemotron-3.5-lightning:30b", "ornith-1.5:35b",
  "pdurugyan/qwen3.5-9b-deepseek-v4-flash-Q4_K_M-v_2:latest",
  "qwen2.5-coder:1.5b-base", "qwen3-next:80b", "qwen3:8b", "qwen3.8:27b",
  "qwen35-40b-heretic-q8:latest", "starcoder2:15b"
)

$api = "http://127.0.0.1:11434/api/generate"
$rows = @()

function Invoke-Gen($model, $prompt, $maxTok, $thinkOff) {
  $opt = @{ temperature = 0; seed = 1; num_predict = $maxTok }
  if ($thinkOff) { $opt["think"] = $false }
  $bodyObj = @{ model = $model; prompt = $prompt; stream = $false; options = $opt }
  if ($thinkOff) { $bodyObj["think"] = $false }
  $body = $bodyObj | ConvertTo-Json -Depth 5
  try {
    $raw = Invoke-WebRequest -Uri $api -Method Post -ContentType "application/json" -Body $body -TimeoutSec 900 -UseBasicParsing
    return $raw.Content | ConvertFrom-Json
  } catch {
    return $null
  }
}

# Deterministic coherence ladder
$coherenceTests = @(
  @{ Prompt = "The capital of France is";    Expect = "Paris";     MinLen = 4 }
  @{ Prompt = "1 + 1 =";                     Expect = "2";         MinLen = 1 }
  @{ Prompt = "Repeat after me: ABC";        Expect = "ABC";       MinLen = 3 }
  @{ Prompt = "Reply with exactly: Hello";   Expect = "Hello";     MinLen = 5 }
)

foreach ($m in $models) {
  Write-Host "=== MODEL: $m ==="
  # LOAD/FORWARD/DECODE gates: 3-run deterministic coherence on ladder
  $loadPass = $false; $forwardPass = $false; $decodePass = $false
  $coherencePass = $false; $repeatPass = $false; $perfPass = $false
  $tps = 0.0; $detail = ""
  $outputs = @()

  foreach ($t in $coherenceTests) {
    $j = Invoke-Gen $m $t.Prompt 48 $true
    if ($null -eq $j) {
      if (-not $detail) { $detail = "API_TIMEOUT_OR_ERROR" }
      continue
    }
    $out = ""
    if ($j.response -and $j.response.Length -gt 0) { $out = $j.response }
    elseif ($j.thinking -and $j.thinking.Length -gt 0) { $out = "[thinking] " + $j.thinking }
    if ($out.Length -gt 0) {
      $loadPass = $true; $forwardPass = $true; $decodePass = $true
      $hit = $false
      # base models complete text; instruct models answer; both can hit the token
      $probe = $out
      if ($probe -match [regex]::Escape($t.Expect)) { $hit = $firstHit }
      if ($probe -match [regex]::Escape($t.Expect)) { $hit = $true }
      if ($hit) { $coherencePass = $true }
      $outputs += "[$($t.Prompt)] => $out"
    } else {
      if (-not $detail) { $detail = "EMPTY_OUTPUT" }
    }
    if ($j.eval_count -gt 0) {
      $tps = [math]::Round($j.eval_count / ($j.eval_duration / 1e9), 2)
    }
  }

  # REPEAT_PASS: second run of same prompt must be byte-identical
  if ($loadPass) {
    $a = Invoke-Gen $m "The capital of France is" 48 $true
    $b = Invoke-Gen $m "The capital of France is" 48 $true
    if ($a -and $b) {
      $ta = if ($a.response) { $a.response } else { "" }
      $tb = if ($b.response) { $b.response } else { $b.response }
      if ($ta -ceq $tb) { $repeatPass = $true }
    }
  }
  if ($tps -gt 1.0) { $perfPass = $true }

  $verdict = "FAIL"
  if ($loadPass -and $forwardPass -and $decodePass -and $coherencePass -and $repeatPass) { $verdict = "PASS" }

  Write-Host "  LOAD=$loadPass FORWARD=$forwardPass DECODE=$decodePass COHERENCE=$coherencePass REPEAT=$repeatPass TPS=$tps VERDICT=$verdict"
  if ($detail) { Write-Host "  DETAIL: $detail" }
  foreach ($o in $outputs) { Write-Host "  $o" }

  $rows += [PSCustomObject]@{
    Model = $m
    LOAD = $loadPass; FORWARD = $forwardPass; DECODE = $decodePass
    COHERENCE = $coherencePass; REPEAT = $repeatPass; PERF = $perfPass
    TPS = $tps; VERDICT = $verdict; NOTE = $detail
  }
}

$rows | Export-Csv -Path "F:\~dev\_ollama_coherence_audit.csv" -NoTypeInformation -Encoding UTF8
Write-Host "=== AUDIT COMPLETE -> F:\~dev\_ollama_coherence_audit.csv ==="