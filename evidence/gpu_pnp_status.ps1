$ErrorActionPreference = 'Continue'
Write-Output '=== PnP Radeon / Display / Compute ==='
Get-PnpDevice -Class Display,System -ErrorAction SilentlyContinue |
  Where-Object {
    $_.FriendlyName -match 'Radeon|AMD|NVIDIA|Vulkan|Display' -or
    $_.InstanceId -match 'VEN_1002|VEN_10DE'
  } |
  ForEach-Object {
    Write-Output ("Status=" + $_.Status + " Problem=" + $_.Problem + " Class=" + $_.Class + " Name=" + $_.FriendlyName + " Id=" + $_.InstanceId)
  }
Write-Output '=== Error-status PCI devices (sample) ==='
Get-PnpDevice -Status Error -ErrorAction SilentlyContinue |
  Where-Object { $_.InstanceId -match 'PCI|VEN_1002|VEN_10DE' -or $_.FriendlyName -match 'Radeon|AMD|NVIDIA' } |
  ForEach-Object {
    Write-Output ("ERR Status=" + $_.Status + " Problem=" + $_.Problem + " Name=" + $_.FriendlyName + " Id=" + $_.InstanceId)
  }
Write-Output '=== Config Manager Error Codes (Problem=10 or 31) ==='
Get-PnpDevice -ErrorAction SilentlyContinue |
  Where-Object { $_.Problem -eq 10 -or $_.Problem -eq 31 -or $_.ConfigManagerErrorCode -eq 10 -or $_.ConfigManagerErrorCode -eq 31 } |
  ForEach-Object {
    Write-Output ("CMERR Problem=" + $_.Problem + " CM=" + $_.ConfigManagerErrorCode + " Status=" + $_.Status + " Name=" + $_.FriendlyName)
  }
