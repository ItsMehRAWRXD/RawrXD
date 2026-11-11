<#
.SYNOPSIS
  Register elevated Task Scheduler job: PnP bounce on Display/WDDM failure events.
.DESCRIPTION
  Prefer this over DDU. Runs Reset-GpuDevicePnp.ps1 when Kernel-PnP / Display
  driver errors are logged. Requires admin once to register.
#>
[CmdletBinding()]
param(
  [string]$TaskName = 'RawrXD-GpuPnpBounce-7800XT'
)

$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot 'Reset-GpuDevicePnp.ps1'
if (-not (Test-Path -LiteralPath $script)) { throw "missing $script" }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error 'Register-GpuPnpWatchdog requires elevation'
  exit 5
}

$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
  -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $script + '"')

# Display driver timeout / recovered + Kernel-PnP device config failures
$triggers = @(
  (New-ScheduledTaskTrigger -AtStartup),
  (New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration ([TimeSpan]::MaxValue))
)

$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest -LogonType ServiceAccount
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers `
  -Principal $principal -Settings $settings -Force | Out-Null

Write-Host "Registered task $TaskName (startup + 15m probe). DDU is NOT registered."
Write-Host 'Manual one-shot: scripts\Reset-GpuDevicePnp.ps1 (auto-elevates UAC).'
exit 0
