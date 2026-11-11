$ErrorActionPreference = 'Continue'
$out = 'F:\rawrxd\evidence\RAWRXD_GIT_RECOVERY_001\process_probe_cim.txt'
$lines = @()
$lines += "=== git CIM probe $(Get-Date -Format o)"
Get-CimInstance Win32_Process -Filter "Name = 'git.exe'" | ForEach-Object {
  $lines += "PID=$($_.ProcessId)"
  $lines += "PPID=$($_.ParentProcessId)"
  $lines += "CMD=$($_.CommandLine)"
  $lines += "CREATE=$($_.CreationDate)"
  $lines += "---"
}
$lines | Set-Content -LiteralPath $out -Encoding UTF8
Get-Content -LiteralPath $out
