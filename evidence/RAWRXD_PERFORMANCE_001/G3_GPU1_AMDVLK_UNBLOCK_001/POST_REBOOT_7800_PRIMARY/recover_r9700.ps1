$log = "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_GPU1_AMDVLK_UNBLOCK_001\POST_REBOOT_7800_PRIMARY\recover_r9700.txt"
$r = New-Object System.Collections.Generic.List[string]
$id9700 = "PCI\VEN_1002&DEV_7551&SUBSYS_E4991DA2&REV_C0\6&8916A45&0&00000009"
$vdd = "ROOT\DISPLAY\0000"

# 1) Take VDD offline completely
Disable-PnpDevice -InstanceId $vdd -Confirm:$false -EA SilentlyContinue
$r.Add("VDD_DISABLED")
Start-Sleep 3

# 2) Remove and rescan R9700 (keeps driver packages)
& pnputil /remove-device "$id9700" 2>&1 | ForEach-Object { $r.Add("$_") }
Start-Sleep 2
& pnputil /scan-devices 2>&1 | ForEach-Object { $r.Add("$_") }
Start-Sleep 8

$dev = Get-PnpDevice -InstanceId $id9700 -EA SilentlyContinue
if (-not $dev) {
  $dev = Get-PnpDevice | Where-Object { $_.InstanceId -match 'DEV_7551' } | Select-Object -First 1
}
if ($dev) {
  $r.Add("R9700_AFTER_SCAN Status=$($dev.Status) Problem=$($dev.Problem) Id=$($dev.InstanceId)")
  if ($dev.Status -ne 'OK') {
    Enable-PnpDevice -InstanceId $dev.InstanceId -Confirm:$false -EA SilentlyContinue
    Start-Sleep 3
    & pnputil /restart-device "$($dev.InstanceId)" 2>&1 | ForEach-Object { $r.Add("$_") }
    $dev2 = Get-PnpDevice -InstanceId $dev.InstanceId
    $r.Add("R9700_AFTER_RESTART Status=$($dev2.Status) Problem=$($dev2.Problem)")
  }
} else {
  $r.Add("R9700_MISSING_AFTER_SCAN")
}

# Leave VDD disabled for now — physical 7800 display is enough for 7800 Vulkan
$r.Add("VDD_LEFT_DISABLED=1 (7800 has physical DISPLAY1)")
Get-PnpDevice -Class Display | ForEach-Object { $r.Add("DISPLAY $($_.Status) $($_.FriendlyName)") }
$r | Set-Content $log
