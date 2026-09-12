param([string]$Log = ".\daily_streamer_live.log")
$ErrorActionPreference = 'Stop'
if (!(Test-Path $Log)) { throw "Missing log: $Log" }
$text = Get-Content $Log -Raw
$out = if (Test-Path ".\daily_streamer_stdout.log") {
  Get-Content ".\daily_streamer_stdout.log" -Raw
} else { $text }
$all = $text + "`n" + $out
$need = @(
  'BACKEND=DEEP2_ENGINE',
  'MOCK_BACKEND=0',
  'MODEL_OPEN_REAL=1',
  'STREAM_CALLBACK_REAL=1',
  'PROMPT_TOKENIZE_REAL=1',
  'PREFILL_REAL=1',
  'GENERATION_1+2_SAME_PROCESS=PASS',
  'DEVICE_LOST=0'
)
foreach ($p in $need) {
  if ($all -notmatch [regex]::Escape($p)) {
    Write-Host "DAILY_VERIFY=HOLD missing=$p"
    exit 21
  }
}
if ($all -notmatch 'STREAM_CALLBACK_TOKENS=[1-9]') {
  Write-Host "DAILY_VERIFY=HOLD STREAM_CALLBACK_TOKENS<=0"
  exit 22
}
if ($all -match 'DAILY_STREAMER_LIVE_INFERENCE=HOLD') {
  Write-Host "DAILY_VERIFY=HOLD inference=HOLD"
  exit 23
}
if ($all -notmatch 'DAILY_STREAMER_LIVE_INFERENCE=PASS') {
  Write-Host "DAILY_VERIFY=HOLD missing LIVE_INFERENCE=PASS"
  exit 24
}
Write-Host "DAILY_VERIFY=PASS"
Write-Host "PROMOTE=0"
exit 0
