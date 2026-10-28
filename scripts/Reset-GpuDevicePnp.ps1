# Auto-elevating PnP Disable/Enable for RX 7800 XT (DEV_747E) on Code 10 / 31.
param(
  [string]$TargetInstanceId = "PCI\VEN_1002&DEV_747E",
  [string]$LogPath = "",
  [switch]$ElevatedChild
)

$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $PSScriptRoot
if (-not $LogPath) {
  $LogPath = Join-Path $Root "build\pnp_automation_history.log"
}
$dir = Split-Path -Parent $LogPath
if ($dir -and -not (Test-Path $dir)) {
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

function Write-Log([string]$msg) {
  $line = ("[{0}] {1}" -f (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss"), $msg)
  Add-Content -LiteralPath $LogPath -Value $line -Encoding ascii -ErrorAction SilentlyContinue
  Write-Host $line
}

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
$IsAdmin = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
  if ($ElevatedChild) {
    Write-Error "Elevation failed or was declined."
    exit 5
  }
  Write-Log ("ELEVATE_REQUEST Target={0}" -f $TargetInstanceId)
  $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -TargetInstanceId `"$TargetInstanceId`" -LogPath `"$LogPath`" -ElevatedChild"
  try {
    $p = Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $arg -Wait -PassThru
    exit $p.ExitCode
  } catch {
    Write-Log ("ELEVATE_FAIL {0}" -f $_.Exception.Message)
    exit 5
  }
}

Write-Log ("SCAN_BEGIN Target={0}" -f $TargetInstanceId)
$Gpu = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
  $_.InstanceId -like ("*{0}*" -f $TargetInstanceId)
} | Select-Object -First 1

$DeviceId = $null
$Status = $null
$Code = -1
if ($Gpu) {
  $DeviceId = $Gpu.InstanceId
  $Status = $Gpu.Status
  try {
    $Code = [int](Get-PnpDeviceProperty -InstanceId $DeviceId -KeyName "DEVPKEY_Device_ProblemCode" -ErrorAction Stop).Data
  } catch {
    $cim = Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue |
      Where-Object { $_.DeviceID -eq $DeviceId } | Select-Object -First 1
    if ($cim) { $Code = [int]$cim.ConfigManagerErrorCode }
  }
} else {
  $cim = Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue |
    Where-Object { $_.DeviceID -like ("*{0}*" -f $TargetInstanceId) } | Select-Object -First 1
  if ($cim) {
    $DeviceId = $cim.DeviceID
    $Status = $cim.Status
    $Code = [int]$cim.ConfigManagerErrorCode
  }
}

if (-not $DeviceId) {
  Write-Log "CANCEL missing_device"
  exit 0
}

Write-Log ("STATE Status={0} Problem={1} InstanceId={2}" -f $Status, $Code, $DeviceId)
if ($Code -ne 10 -and $Code -ne 31) {
  Write-Log ("BYPASS Problem={0}" -f $Code)
  exit 0
}

Write-Log ("CYCLE_BEGIN Problem={0}" -f $Code)
try {
  Disable-PnpDevice -InstanceId $DeviceId -Confirm:$false -ErrorAction Stop
  Write-Log "DISABLE=OK"
  Start-Sleep -Seconds 2
  Enable-PnpDevice -InstanceId $DeviceId -Confirm:$false -ErrorAction Stop
  Write-Log "ENABLE=OK"
  Start-Sleep -Seconds 2
} catch {
  Write-Log ("CYCLE_FAIL {0}" -f $_.Exception.Message)
  exit 1
}

$afterCode = -1
$afterStatus = "?"
try {
  $afterStatus = (Get-PnpDevice -InstanceId $DeviceId -ErrorAction Stop).Status
  $afterCode = [int](Get-PnpDeviceProperty -InstanceId $DeviceId -KeyName "DEVPKEY_Device_ProblemCode" -ErrorAction Stop).Data
} catch {
  $post = Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue |
    Where-Object { $_.DeviceID -eq $DeviceId } | Select-Object -First 1
  if ($post) {
    $afterStatus = $post.Status
    $afterCode = [int]$post.ConfigManagerErrorCode
  }
}

Write-Log ("AFTER Status={0} Problem={1}" -f $afterStatus, $afterCode)
if ($afterCode -eq 0) {
  Write-Log "SUCCESS"
  exit 0
}
Write-Log ("FAIL_STILL_BAD Problem={0}" -f $afterCode)
exit 1
