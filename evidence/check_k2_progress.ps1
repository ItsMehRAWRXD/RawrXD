$ErrorActionPreference = 'Continue'
$meta = 'F:\rawrxd-native-agent-001\evidence\k2_oracle_meta.txt'
$err  = 'F:\rawrxd-native-agent-001\evidence\k2_oracle_single_turn.err'
if (Test-Path $meta) { Get-Content $meta }
if (Test-Path $err) {
  $fi = Get-Item $err
  Write-Output ("ERR_BYTES=" + $fi.Length)
  $hits = Select-String -Path $err -Pattern 'offloaded|load_mode|fit params|CRITICAL|OOM|slot decode token' |
    Select-Object -Last 20
  foreach ($h in $hits) {
    $line = $h.Line
    if ($line.Length -gt 180) { $line = $line.Substring(0,180) }
    Write-Output $line
  }
  $tok = @(Select-String -Path $err -Pattern 'slot decode token, id=' )
  Write-Output ("DECODE_TOKEN_EVENTS=" + $tok.Count)
}
Get-Process -Name 'llama*' -ErrorAction SilentlyContinue |
  ForEach-Object { Write-Output ("PROC id=" + $_.Id + " name=" + $_.ProcessName) }
