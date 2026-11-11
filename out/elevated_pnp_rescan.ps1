$ErrorActionPreference = "Continue"
$log = "F:\rawrxd\evidence\GPU_CODE10_PNP_RESCAN_001.txt"
$inst = "PCI\VEN_1002&DEV_747E&SUBSYS_53241849&REV_C8\6&2E27FDA8&0&0000000B"
function Prob($id) {
  try { (Get-PnpDeviceProperty -InstanceId $id -KeyName DEVPKEY_Device_ProblemCode -EA Stop).Data } catch { -1 }
}
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("GPU_CODE10_PNP_RESCAN_001")
$lines.Add("ELEVATED=1")
$before = Get-PnpDevice -InstanceId $inst -EA SilentlyContinue
$lines.Add("BEFORE_STATUS=$($before.Status)")
$lines.Add("BEFORE_PROBLEM=$(Prob $inst)")
try { Disable-PnpDevice -InstanceId $inst -Confirm:$false -EA Stop; $lines.Add("DISABLE=OK") } catch { $lines.Add("DISABLE=FAIL $($_.Exception.Message)") }
Start-Sleep -Seconds 3
try { Enable-PnpDevice -InstanceId $inst -Confirm:$false -EA Stop; $lines.Add("ENABLE=OK") } catch { $lines.Add("ENABLE=FAIL $($_.Exception.Message)") }
Start-Sleep -Seconds 3
$after = Get-PnpDevice -InstanceId $inst -EA SilentlyContinue
$lines.Add("AFTER_STATUS=$($after.Status)")
$lines.Add("AFTER_PROBLEM=$(Prob $inst)")
$lines.Add("PROMOTE=0")
[System.IO.File]::WriteAllLines($log, $lines.ToArray())
