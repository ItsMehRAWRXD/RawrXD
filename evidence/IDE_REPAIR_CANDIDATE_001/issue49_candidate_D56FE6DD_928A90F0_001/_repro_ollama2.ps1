$ErrorActionPreference = 'Stop'
$meta = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_candidate_D56FE6DD_928A90F0_001\_ollama_repro_meta.txt'
$out = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_candidate_D56FE6DD_928A90F0_001\_ollama_repro_raw.json'
$payloadPath = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_candidate_D56FE6DD_928A90F0_001\_ollama_repro_payload.json'
$payloadObj = @{
  model = 'qwen3:8b'
  stream = $false
  think = $false
  options = @{ temperature = 0.2; num_predict = 64; num_ctx = 4096 }
  messages = @(
    @{ role = 'system'; content = 'Reply with exactly one line: TOOL read bug.cpp' }
    @{ role = 'user'; content = 'Start now. First tokens must be TOOL read bug.cpp' }
  )
}
($payloadObj | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $payloadPath -Encoding utf8
# Prefer curl.exe to avoid PS5 Invoke-WebRequest NullReference quirks.
$curl = Get-Command curl.exe -ErrorAction SilentlyContinue
if (-not $curl) { throw 'curl.exe missing' }
$args = @(
  '-sS', '-m', '600',
  '-H', 'Content-Type: application/json',
  '-H', 'Accept: application/json',
  '-d', ('@' + $payloadPath),
  'http://127.0.0.1:11434/api/chat'
)
$raw = & curl.exe @args
if ($LASTEXITCODE -ne 0) { "CURL_EXIT=$LASTEXITCODE" | Set-Content $meta; throw "curl failed $LASTEXITCODE" }
[System.IO.File]::WriteAllText($out, $raw, [System.Text.UTF8Encoding]::new($false))
$j = $raw | ConvertFrom-Json
$content = [string]$j.message.content
$thinking = ''
if ($j.message.PSObject.Properties.Name -contains 'thinking') { $thinking = [string]$j.message.thinking }
$hasTools = ($j.message.PSObject.Properties.Name -contains 'tool_calls') -and ($null -ne $j.message.tool_calls)
@(
  "HTTP=200_ASSUMED_CURL_OK"
  "BODY_BYTES=$($raw.Length)"
  "content_len=$($content.Length)"
  "thinking_len=$($thinking.Length)"
  "tool_calls=$hasTools"
  "CONTENT<<<$content>>>"
  "THINKING_HEAD<<<$($thinking.Substring(0, [Math]::Min(200, $thinking.Length)))>>>"
) | Set-Content -LiteralPath $meta -Encoding utf8
Write-Output 'REPRO2_OK'