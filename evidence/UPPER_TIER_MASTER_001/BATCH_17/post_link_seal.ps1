# Fail-closed post-link seal for Batch17. Does not invent PASS.
param(
  [string]$SearchRoot = 'F:\rawrxd\build_win32ide',
  [string]$OutDir = 'F:\rawrxd\evidence\UPPER_TIER_MASTER_001\BATCH_17'
)
$ErrorActionPreference = 'Stop'
$exe = Get-ChildItem -Path $SearchRoot -Recurse -Filter 'RawrXD-Win32IDE-Native.exe' -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $exe) {
  @"
EXE=ABSENT
CERTIFIED=0
PROMOTE=0
RUNTIME_SMOKE=HELD
"@ | Set-Content (Join-Path $OutDir 'EXE_SHA256.txt')
  Write-Output 'EXE_ABSENT'
  exit 2
}
$hash = (Get-FileHash -Algorithm SHA256 -Path $exe.FullName).Hash.ToLowerInvariant()
@"
EXE_PATH=$($exe.FullName)
EXE_BYTES=$($exe.Length)
SHA256=$hash
ASOF=$((Get-Date).ToUniversalTime().ToString('o'))
CERTIFIED=0
PROMOTE=0
"@ | Set-Content (Join-Path $OutDir 'EXE_SHA256.txt')
$smoke = Join-Path $OutDir 'PS_SMOKE_HARNESS\Invoke-PsExecuteClearStopSmoke.ps1'
if (Test-Path $smoke) {
  & $smoke -ExePath $exe.FullName
  Write-Output "SMOKE_EC=$LASTEXITCODE"
} else {
  Write-Output 'SMOKE_HARNESS_MISSING'
}
Write-Output "SHA256=$hash"
exit 0
