$vdd = "ROOT\DISPLAY\0000"
Disable-PnpDevice -InstanceId $vdd -Confirm:$false -ErrorAction SilentlyContinue
Start-Sleep 2
Enable-PnpDevice -InstanceId $vdd -Confirm:$false -ErrorAction SilentlyContinue
Start-Sleep 2
pnputil /restart-device "$vdd" 2>&1 | Out-String | Set-Content "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_GPU1_AMDVLK_UNBLOCK_001\POST_REBOOT_7800_PRIMARY\vdd_rebind.txt"
"DONE $(Get-Date -Format o)" | Add-Content "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_GPU1_AMDVLK_UNBLOCK_001\POST_REBOOT_7800_PRIMARY\vdd_rebind.txt"
