$ErrorActionPreference = 'Stop'
$outDir = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_candidate_D56FE6DD_928A90F0_001'
$sessPath = Join-Path $outDir 'bin\.rawrxd\ledger\agent_session.json'
$raw = Get-Content -Raw -LiteralPath $sessPath
$raw.Length | Out-File (Join-Path $outDir '_sess_meta.txt')
# dump top-level keys via regex-ish
($raw.Substring(0, [Math]::Min(800, $raw.Length))) | Out-File (Join-Path $outDir '_sess_head.txt') -Encoding utf8

# Prefer raw string search for the fail transcript embedded anywhere
$markers = @(
  'RESPONSE_RECV',
  'response_bytes=',
  'OLLAMA_AGENT_VERDICT',
  'request failed',
  'Invalid command',
  'write rolled back',
  'host wall deadline',
  '[ollama step'
)
foreach ($m in $markers) {
  $c = ([regex]::Matches($raw, [regex]::Escape($m))).Count
  "$m count=$c" | Out-File (Join-Path $outDir '_sess_meta.txt') -Append
}

# Extract a window around first RESPONSE_RECV
$idx = $raw.IndexOf('RESPONSE_RECV')
if ($idx -ge 0) {
  $start = [Math]::Max(0, $idx - 200)
  $len = [Math]::Min(4000, $raw.Length - $start)
  $raw.Substring($start, $len) | Out-File (Join-Path $outDir '_sess_around_recv.txt') -Encoding utf8
}

# Extract around VERDICT
$idx2 = $raw.IndexOf('OLLAMA_AGENT_VERDICT')
if ($idx2 -ge 0) {
  $start2 = [Math]::Max(0, $idx2 - 500)
  $len2 = [Math]::Min(2500, $raw.Length - $start2)
  $raw.Substring($start2, $len2) | Out-File (Join-Path $outDir '_sess_around_verdict.txt') -Encoding utf8
}

# Also search IDE logs and chat_runtime for full fail text
$searchRoots = @(
  (Join-Path $outDir 'bin\logs'),
  (Join-Path $outDir 'issue49_gui_ollama_qwen3_020'),
  (Join-Path $outDir 'issue49_gui_ollama_qwen3_021')
)
$hits = New-Object System.Collections.Generic.List[string]
foreach ($root in $searchRoots) {
  if (-not (Test-Path $root)) { continue }
  Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
    try {
      $t = Get-Content -Raw -LiteralPath $_.FullName -ErrorAction Stop
    } catch { return }
    if ($t -match 'response_bytes=|OLLAMA_AGENT_AFTER|write rolled back|request failed HTTP') {
      $hits.Add($_.FullName)
      $outHit = Join-Path $outDir ('_hit_' + $_.Name + '.snip.txt')
      $i = $t.IndexOf('response_bytes=')
      if ($i -lt 0) { $i = $t.IndexOf('RESPONSE_RECV') }
      if ($i -lt 0) { $i = $t.IndexOf('OLLAMA_AGENT_VERDICT') }
      if ($i -ge 0) {
        $s = [Math]::Max(0, $i - 100)
        $l = [Math]::Min(5000, $t.Length - $s)
        $t.Substring($s, $l) | Out-File $outHit -Encoding utf8
      }
    }
  }
}
"HIT_FILES=$($hits.Count)" | Out-File (Join-Path $outDir '_sess_meta.txt') -Append
$hits | Out-File (Join-Path $outDir '_sess_meta.txt') -Append
Write-Output 'OK2'