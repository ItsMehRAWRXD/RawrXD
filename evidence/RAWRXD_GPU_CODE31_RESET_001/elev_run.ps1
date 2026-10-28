$ErrorActionPreference = "Continue"
$gate = Split-Path -Parent $MyInvocation.MyCommand.Path
$log = Join-Path $gate "elev_run.log"
function W($s) { Add-Content -LiteralPath $log -Value $s }
Set-Content -LiteralPath $log -Value "START=$(Get-Date -Format o) whoami=$(whoami)"

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object Security.Principal.WindowsPrincipal($id)
$elev = $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
W "ELEVATED=$([int]$elev) IL=$((whoami /groups | Select-String 'Mandatory Label').Line)"

if (-not $elev) {
  W "RELAUNCH=RunAs"
  $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
  try {
    Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $arg -Wait
  } catch {
    W "RUNAS_FAIL=$($_.Exception.Message)"
    exit 3
  }
  if (Test-Path $log) { Get-Content $log | Select-Object -Last 30 }
  exit 0
}

# Rebuild + run smoke with admin manifest so CM_Disable_DevNode can clear Code 31.
$build = Join-Path $gate "build_and_run.ps1"
& $build *>> $log 2>&1
W "BUILD_RUN_EXIT=$LASTEXITCODE"
$smokeLog = Join-Path $gate "smoke_run.log"
if (Test-Path $smokeLog) {
  W "---- smoke_run.log ----"
  Get-Content $smokeLog | ForEach-Object { W $_ }
}
W "END=$(Get-Date -Format o)"
exit $LASTEXITCODE
