$ErrorActionPreference = 'Continue'
$paths = @(
  'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_ext_host_oneshot\RawrXD-Win32IDE-Native.exe',
  'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_ext_host_oneshot\RawrXD-Win32IDE-Native-Ext.exe',
  'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_ext_host_004\RawrXD-Win32IDE-Native-Ext.exe',
  'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_ext_host_004\RawrXD-Win32IDE-Native.exe',
  'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_chat_ctrl_enter_001\RawrXD-Win32IDE-Native-Ext.exe',
  'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe',
  'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_t10_recovery_001\RawrXD-Win32IDE-Native.exe'
)
$out = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\HASH_SNAPSHOT.txt'
$lines = @("ASOF=$(Get-Date -Format o)")
foreach ($p in $paths) {
  if (Test-Path $p) {
    $h = (Get-FileHash $p -Algorithm SHA256).Hash
    $len = (Get-Item $p).Length
    $lines += "$h  $len  $p"
  } else {
    $lines += "MISSING  $p"
  }
}
$lines | Set-Content $out -Encoding ASCII
Write-Output "WROTE $out"
$lines | ForEach-Object { Write-Output $_ }
