# Kill ONLY stalled inventory / recursive dir / dumpbin wrappers — not all cmd/cl/link.
$ErrorActionPreference = 'Continue'
$Ev = 'F:\rawrxd\evidence\RAWRXD_SOVEREIGN_LINKER_CERT_001'
$log = Join-Path $Ev 'host_io_recovery.log'
$patterns = @(
  'inventory_native_objs',
  'inventory_explicit',
  'classify_inventory',
  'dir /s /b.*CMakeFiles',
  'dir /s /b.*\*deep2\*',
  'dumpbin_inv',
  'Get-CimInstance Win32_Process.*inventory_native',
  'taskkill /F /IM powershell.exe'
)
$killed = @()
$kept = @()
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
  $cl = $_.CommandLine
  if (-not $cl) { return }
  $hit = $false
  foreach ($p in $patterns) {
    if ($cl -match $p) { $hit = $true; break }
  }
  if (-not $hit) { return }
  # Never kill cmake/ninja/link/cl from main builds unless they are clearly our inventory dumpbin child
  if ($cl -match 'cmake\.exe|ninja\.exe' -and $cl -notmatch 'inventory|dumpbin_inv') {
    $kept += [pscustomobject]@{ pid=$_.ProcessId; why='protected_build'; cmd=($cl.Substring(0,[Math]::Min(160,$cl.Length))) }
    return
  }
  try {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop
    $killed += [pscustomobject]@{ pid=$_.ProcessId; cmd=($cl.Substring(0,[Math]::Min(200,$cl.Length))) }
  } catch {
    $kept += [pscustomobject]@{ pid=$_.ProcessId; why=("kill_failed:"+$_); cmd=($cl.Substring(0,[Math]::Min(160,$cl.Length))) }
  }
}
$report = [ordered]@{
  schema='RAWRXD_HOST_IO_RECOVERY_001'
  generated_utc=(Get-Date).ToUniversalTime().ToString('o')
  killed=$killed
  kept=$kept
  HOST_IO_RECOVERY=$(if ($killed.Count -ge 0) {'ATTEMPTED'} else {'NONE'})
}
($report | ConvertTo-Json -Depth 5) | Set-Content (Join-Path $Ev 'host_io_recovery.json') -Encoding UTF8
$report | ConvertTo-Json -Depth 5 | Set-Content $log -Encoding UTF8
Write-Host ("RECOVERY killed={0} kept={1}" -f $killed.Count, $kept.Count)
