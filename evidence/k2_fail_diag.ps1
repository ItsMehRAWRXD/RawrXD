$ErrorActionPreference = 'Continue'
$err = 'F:\rawrxd-native-agent-001\evidence\k2_oracle_single_turn.err'
$e1 = (Get-Item -LiteralPath $err).Length
Start-Sleep -Seconds 6
$e2 = (Get-Item -LiteralPath $err).Length
Write-Output ("DELTA=" + ($e2 - $e1) + " BYTES=" + $e2)
Get-Process -Name 'llama*' -ErrorAction SilentlyContinue | ForEach-Object {
  Write-Output ("PROC " + $_.Id + " " + $_.ProcessName + " WSGB=" + [math]::Round($_.WorkingSet64 / 1GB, 2))
}
Select-String -Path $err -Pattern 'error|Error|ERROR|fail|OOM|killed|abort|slot decode|predicted_n|prompt eval' |
  Select-Object -Last 20 |
  ForEach-Object {
    $line = $_.Line
    if ($line.Length -gt 200) { $line = $line.Substring(0, 200) }
    Write-Output $line
  }
