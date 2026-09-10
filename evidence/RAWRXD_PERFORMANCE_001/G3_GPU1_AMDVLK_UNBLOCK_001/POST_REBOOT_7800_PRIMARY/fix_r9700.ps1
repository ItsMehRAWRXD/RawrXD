$log = "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_GPU1_AMDVLK_UNBLOCK_001\POST_REBOOT_7800_PRIMARY\fix_r9700.txt"
$r = New-Object System.Collections.Generic.List[string]
$id9700 = "PCI\VEN_1002&DEV_7551&SUBSYS_E4991DA2&REV_C0\6&8916A45&0&00000009"
$vdd = "ROOT\DISPLAY\0000"
try {
  Disable-PnpDevice -InstanceId $vdd -Confirm:$false -EA Stop
  $r.Add("VDD_DISABLE=OK")
} catch { $r.Add("VDD_DISABLE=$_") }
Start-Sleep 2
try {
  Enable-PnpDevice -InstanceId $id9700 -Confirm:$false -EA Stop
  $r.Add("R9700_ENABLE=OK")
} catch { $r.Add("R9700_ENABLE=$_") }
# disable/enable cycle on R9700
try {
  Disable-PnpDevice -InstanceId $id9700 -Confirm:$false -EA Stop
  Start-Sleep 3
  Enable-PnpDevice -InstanceId $id9700 -Confirm:$false -EA Stop
  $r.Add("R9700_CYCLE=OK")
} catch { $r.Add("R9700_CYCLE=$_") }
Start-Sleep 2
try {
  Enable-PnpDevice -InstanceId $vdd -Confirm:$false -EA Stop
  $r.Add("VDD_ENABLE=OK")
} catch { $r.Add("VDD_ENABLE=$_") }
Start-Sleep 2
pnputil /restart-device "$id9700" 2>&1 | ForEach-Object { $r.Add("$_") }
pnputil /restart-device "$vdd" 2>&1 | ForEach-Object { $r.Add("$_") }
Get-PnpDevice -InstanceId $id9700,$vdd | ForEach-Object { $r.Add("STATUS $($_.FriendlyName)=$($_.Status) Problem=$($_.Problem)") }
$r | Set-Content $log
