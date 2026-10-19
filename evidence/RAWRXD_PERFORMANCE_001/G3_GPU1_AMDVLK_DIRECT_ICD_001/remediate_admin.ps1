$gate = "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_GPU1_AMDVLK_DIRECT_ICD_001"
$log = New-Object System.Collections.Generic.List[string]
function L([string]$s) { $script:log.Add($s); Write-Host $s }

$k7800 = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002"
try {
  Set-ItemProperty -Path $k7800 -Name "EnableUlps" -Value 0 -Type DWord -Force
  Set-ItemProperty -Path $k7800 -Name "PP_GPUPowerDownEnabled" -Value 0 -Type DWord -Force
  $a = Get-ItemProperty $k7800
  L "ULPS_AFTER EnableUlps=$($a.EnableUlps) PP_GPUPowerDownEnabled=$($a.PP_GPUPowerDownEnabled)"
  L "REG_WRITE=PASS"
} catch { L "REG_WRITE=FAIL $_" }

$id7800 = "PCI\VEN_1002&DEV_747E&SUBSYS_53241849&REV_C8\6&2E27FDA8&0&0000000B"
try {
  Disable-PnpDevice -InstanceId $id7800 -Confirm:$false -ErrorAction Stop
  Start-Sleep -Seconds 3
  Enable-PnpDevice -InstanceId $id7800 -Confirm:$false -ErrorAction Stop
  Start-Sleep -Seconds 4
  $st = Get-PnpDevice -InstanceId $id7800
  L "PNP_CYCLE=PASS Status=$($st.Status)"
} catch { L "PNP_CYCLE=FAIL $_" }

$wmi = Get-CimInstance Win32_VideoController | Where-Object { $_.PNPDeviceID -match '747E' }
L "WMI_AVAILABILITY_AFTER=$($wmi.Availability) Status=$($wmi.Status)"

# Also clear iGPU VulkanDriverName conflict? Soft: rename by setting empty is dangerous.
# Instead log iGPU VulkanDriverName
$kIgpu = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001"
$ig = Get-ItemProperty $kIgpu
L "IGPU_VulkanDriverName=$($ig.VulkanDriverName)"

[IO.File]::WriteAllText("$gate\REMEDIATE_ULPS_PNP_ADMIN.txt", ($log -join "`r`n"))