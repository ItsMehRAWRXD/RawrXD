$ErrorActionPreference = 'Stop'
$src = 'F:\rawrxd\evidence\CC79_RUNTIME_001\artifacts\issue49_product_final_tip002.ps1'
$dst = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\harness\issue49_ORIG.ps1'
Write-Host "SRC_EXISTS=$([IO.File]::Exists($src)) LEN=$((Get-Item -LiteralPath $src).Length)"
[IO.File]::Copy($src, $dst, $true)
Write-Host "DST=$dst LEN=$((Get-Item -LiteralPath $dst).Length)"
# Also dump line count and the chat section for patch targeting
$lines = [IO.File]::ReadAllLines($dst)
Write-Host "LINES=$($lines.Length)"
for ($i = 0; $i -lt $lines.Length; $i++) {
  if ($lines[$i] -match 'CHAT_INPUT|SetText|1202|4106|4100|AGENTIC|spawn|AgentWait') {
    Write-Host ("{0,4}: {1}" -f ($i+1), $lines[$i])
  }
}
