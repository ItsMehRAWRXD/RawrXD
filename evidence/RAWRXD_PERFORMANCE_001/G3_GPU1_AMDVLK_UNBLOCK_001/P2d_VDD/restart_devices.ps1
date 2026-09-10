$id="PCI\VEN_1002&DEV_747E&SUBSYS_53241849&REV_C8\6&2E27FDA8&0&0000000B"
$vdd="ROOT\DISPLAY\0000"
Disable-PnpDevice -InstanceId $vdd -Confirm:$false -EA SilentlyContinue
Start-Sleep 1
Enable-PnpDevice -InstanceId $vdd -Confirm:$false -EA SilentlyContinue
Start-Sleep 2
pnputil /restart-device $id
pnputil /restart-device $vdd
$log="G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_GPU1_AMDVLK_UNBLOCK_001\P2d_VDD\restart_7800.txt"
"DONE $(Get-Date -Format o)" | Set-Content $log
Get-PnpDevice -InstanceId $vdd,$id | Format-Table Status,FriendlyName | Out-String | Add-Content $log