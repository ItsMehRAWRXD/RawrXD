$ErrorActionPreference = 'Continue'
Get-Process -Name 'llama*','llama-completion' -ErrorAction SilentlyContinue | ForEach-Object {
  Write-Output ("KILL " + $_.Id + " " + $_.ProcessName)
  Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 2
$left = @(Get-Process -Name 'llama*','llama-completion' -ErrorAction SilentlyContinue)
if ($left.Count -eq 0) { Write-Output 'ORPHANS_CLEARED' }
else { foreach ($p in $left) { Write-Output ("STILL " + $p.Id + " " + $p.ProcessName) } }
