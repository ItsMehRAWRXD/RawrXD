# Elevated PnP clear for RX 7800 XT (Code 10 / Code 31). Writes elev_pnp_clear.log.
$ErrorActionPreference = "Continue"
$gate = Split-Path -Parent $MyInvocation.MyCommand.Path
$log = Join-Path $gate "elev_pnp_clear.log"
function W($s) { Add-Content -LiteralPath $log -Value $s; Write-Host $s }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$prin = New-Object Security.Principal.WindowsPrincipal($id)
$elev = $prin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Set-Content -LiteralPath $log -Value "START=$(Get-Date -Format o) whoami=$(whoami) ELEVATED=$([int]$elev)"

if (-not $elev) {
  W "RELAUNCH=RunAs"
  $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
  try {
    Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $arg -Wait
  } catch {
    W "RUNAS_FAIL=$($_.Exception.Message)"
    exit 3
  }
  exit 0
}

W "ENUM_BEFORE"
Get-PnpDevice -Class Display | ForEach-Object {
  W ("  {0} problem={1} status={2}" -f $_.FriendlyName, $_.Problem, $_.Status)
}

$targets = Get-PnpDevice -Class Display | Where-Object {
  $_.FriendlyName -match '7800 XT' -or
  ($_.Status -eq 'Error' -and $_.FriendlyName -match 'Radeon')
}
if (-not $targets) {
  W "NO_ERROR_RADEON_TARGET"
} else {
  foreach ($t in $targets) {
    W ("DISABLE {0} instance={1}" -f $t.FriendlyName, $t.InstanceId)
    try {
      Disable-PnpDevice -InstanceId $t.InstanceId -Confirm:$false -Verbose *>> $log
    } catch {
      W ("DISABLE_FAIL={0}" -f $_.Exception.Message)
    }
  }
  Start-Sleep -Seconds 3
  foreach ($t in $targets) {
    W ("ENABLE {0}" -f $t.FriendlyName)
    try {
      Enable-PnpDevice -InstanceId $t.InstanceId -Confirm:$false -Verbose *>> $log
    } catch {
      W ("ENABLE_FAIL={0}" -f $_.Exception.Message)
    }
  }
  Start-Sleep -Seconds 5
}

W "ENUM_AFTER"
$stillBad = 0
Get-PnpDevice -Class Display | ForEach-Object {
  W ("  {0} problem={1} status={2}" -f $_.FriendlyName, $_.Problem, $_.Status)
  if ($_.FriendlyName -match '7800 XT' -and ($_.Status -ne 'OK' -or $_.Problem -ne 'CM_PROB_NONE')) {
    $stillBad++
  }
}
W ("STILL_BAD=$stillBad")
if ($stillBad -gt 0) { W "NEXT=COLD_BOOT_REQUIRED" } else { W "NEXT=PRODUCT_HEALTHY" }
W "END=$(Get-Date -Format o)"
exit $(if ($stillBad -gt 0) { 1 } else { 0 })
