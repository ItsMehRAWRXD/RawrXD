$ErrorActionPreference = 'Continue'
$err = 'F:\rawrxd-native-agent-001\evidence\k2_oracle_single_turn.err'
$out = 'F:\rawrxd-native-agent-001\evidence\k2_oracle_single_turn.out'
Write-Output '=== ERR TAIL ==='
if (Test-Path $err) {
  Get-Content -LiteralPath $err -Tail 40
}
Write-Output '=== OUT TAIL ==='
if (Test-Path $out) {
  $fi = Get-Item $out
  Write-Output ("OUT_BYTES=" + $fi.Length)
  Get-Content -LiteralPath $out -Tail 20
}
Write-Output '=== PROCS ==='
Get-Process -Name 'llama*','llama-completion' -ErrorAction SilentlyContinue |
  ForEach-Object { Write-Output ("id=" + $_.Id + " name=" + $_.ProcessName + " ws=" + [math]::Round($_.WorkingSet64/1MB) + "MB") }
