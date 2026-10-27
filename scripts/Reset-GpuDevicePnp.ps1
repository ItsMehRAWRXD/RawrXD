<#
.SYNOPSIS
  Elevated PnP disable/enable for RX 7800 XT (DEV_747E) on Code 10 / 31.
.DESCRIPTION
  Auto-relaunches elevated if needed. Only cycles when ConfigManagerErrorCode
  is 10 (CM_PROB_FAILED_START) or 31 (driver/gen failure). Opt-in from Deep2
  via DEEP2_GPU_PNP_BOUNCE=1. Exit: 0 ok/bypass, 1 bounce fail, 5 access denied.
#>
[CmdletBinding()]
param(
  [string]$InstanceMatch = 'PCI\VEN_1002&DEV_747E',
  [string]$LogPath = '',
  [switch]$NoElevate,
  [switch]$ForceProbe
)

$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($LogPath)) {
  $LogPath = Join-Path $Root 'evidence\DEEP2_GPU_CODE10_POWER_001\pnp_automation_history.log'
}
$dir = Split-Path -Parent $LogPath
if (-not (Test-Path -LiteralPath $dir)) {
  New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

function Write-PnpLog([string]$msg) {
  $line = '[' + (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss') + '] ' + $msg
  Add-Content -LiteralPath $LogPath -Value $line -Encoding ascii
  Write-Host $line
}

function Test-IsAdmin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
  if ($NoElevate) {
    Write-PnpLog 'FATAL not elevated and -NoElevate set'
    exit 5
  }
  Write-PnpLog 'Not elevated — relaunching with RunAs'
  $arg = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '"'
  if ($ForceProbe) { $arg += ' -ForceProbe' }
  $arg += ' -InstanceMatch "' + $InstanceMatch + '"'
  $arg += ' -LogPath "' + $LogPath + '"'
  try {
    $p = Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $arg -Wait -PassThru
    exit $p.ExitCode
  } catch {
    Write-PnpLog ('FATAL elevation failed: ' + $_.Exception.Message)
    exit 5
  }
}

Write-PnpLog ('Scanning for ' + $InstanceMatch)
$devs = @(Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
  $_.InstanceId -like ($InstanceMatch + '*')
})
if ($devs.Count -eq 0) {
  Write-PnpLog 'CANCEL device not on bus'
  exit 0
}

$rc = 0
foreach ($d in $devs) {
  $cm = 0
  try {
    $cim = Get-CimInstance Win32_PnPEntity -Filter ("DeviceID='" + ($d.InstanceId -replace '\\','\\') + "'") -ErrorAction SilentlyContinue
    if ($cim) { $cm = [int]$cim.ConfigManagerErrorCode }
  } catch { }
  if ($cm -eq 0 -and $d.Problem) {
    if ($d.Problem -match 'FAILED_START|10') { $cm = 10 }
    elseif ($d.Problem -match '31|FAILED') { $cm = 31 }
  }
  Write-PnpLog ('Device Status=' + $d.Status + ' Problem=' + $d.Problem + ' CM=' + $cm + ' Id=' + $d.InstanceId)

  $need = ($cm -eq 10 -or $cm -eq 31 -or $d.Status -eq 'Error')
  if (-not $need -and -not $ForceProbe) {
    Write-PnpLog 'Nominal — bounce bypassed'
    continue
  }
  if (-not $need -and $ForceProbe) {
    Write-PnpLog 'ForceProbe but healthy — bypass'
    continue
  }

  Write-PnpLog ('Recoverable state CM=' + $cm + ' — Disable/Enable')
  try {
    Disable-PnpDevice -InstanceId $d.InstanceId -Confirm:$false -ErrorAction Stop
    Start-Sleep -Seconds 3
    Enable-PnpDevice -InstanceId $d.InstanceId -Confirm:$false -ErrorAction Stop
    Start-Sleep -Seconds 3
  } catch {
    Write-PnpLog ('FATAL PnP cycle: ' + $_.Exception.Message)
    $rc = 1
    continue
  }

  $after = Get-PnpDevice -InstanceId $d.InstanceId -ErrorAction SilentlyContinue
  Write-PnpLog ('AFTER Status=' + $after.Status + ' Problem=' + $after.Problem)
  if ($after.Status -ne 'OK') {
    Write-PnpLog 'FAIL still Error — cold boot may be required'
    $rc = 1
  } else {
    Write-PnpLog 'SUCCESS device OK'
  }
}
exit $rc
