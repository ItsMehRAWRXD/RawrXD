$ErrorActionPreference = 'Continue'
$id = 'PCI\VEN_1002&DEV_747E&SUBSYS_53241849&REV_C8\6&2E27FDA8&0&0000000B'
Write-Output ('TARGET=' + $id)
$dev = Get-PnpDevice -InstanceId $id -ErrorAction SilentlyContinue
if (-not $dev) { Write-Output 'DEVICE_NOT_FOUND'; exit 2 }
Write-Output ('BEFORE Status=' + $dev.Status + ' Problem=' + $dev.Problem)
try {
  Disable-PnpDevice -InstanceId $id -Confirm:$false -ErrorAction Stop
  Write-Output 'DISABLE_OK'
} catch {
  Write-Output ('DISABLE_FAIL=' + $_.Exception.Message)
  exit 3
}
Start-Sleep -Seconds 3
try {
  Enable-PnpDevice -InstanceId $id -Confirm:$false -ErrorAction Stop
  Write-Output 'ENABLE_OK'
} catch {
  Write-Output ('ENABLE_FAIL=' + $_.Exception.Message)
  exit 4
}
Start-Sleep -Seconds 2
$dev2 = Get-PnpDevice -InstanceId $id -ErrorAction SilentlyContinue
Write-Output ('AFTER Status=' + $dev2.Status + ' Problem=' + $dev2.Problem)
if ($dev2.Status -eq 'OK') {
  Write-Output 'RECOVERED=1'
  exit 0
}
Write-Output 'RECOVERED=0 NEED_COLD_BOOT=1'
exit 5
