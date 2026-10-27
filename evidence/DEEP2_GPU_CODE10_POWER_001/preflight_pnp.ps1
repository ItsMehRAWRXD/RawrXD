# Preflight elevated PnP bounce before GPU tests.
$ErrorActionPreference = 'Continue'
$repo = 'F:\rawrxd-native-agent-001'
$script = Join-Path $repo 'scripts\Reset-GpuDevicePnp.ps1'
Write-Host "PREFLIGHT_PNP script=$script"
if (-not (Test-Path -LiteralPath $script)) { Write-Host 'PREFLIGHT_PNP=MISSING'; exit 2 }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script
exit $LASTEXITCODE
