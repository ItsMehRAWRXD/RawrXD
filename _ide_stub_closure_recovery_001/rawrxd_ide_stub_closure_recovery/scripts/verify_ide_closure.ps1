[CmdletBinding()]
param(
    [string]$RepoRoot = 'F:\~dev\rawrxd',
    [string]$BuildDir = 'F:\~dev\rawrxd\win32ide_strict\build_v4',
    [string]$Config = 'Release',
    [string]$Target = 'RawrXD-Win32IDE',
    [switch]$RunRuntime,
    [string[]]$RuntimeArgs = @(),
    [string]$Receipt = ''
)
$ErrorActionPreference = 'Continue'
if (-not $Receipt) { $Receipt = Join-Path $RepoRoot 'ide_closure_receipt.txt' }
$scriptRoot = $PSScriptRoot
$auditReceipt = Join-Path $RepoRoot 'ide_stub_audit_receipt.txt'
& (Join-Path $scriptRoot 'audit_ide_stubs.ps1') -RepoRoot $RepoRoot -Receipt $auditReceipt -NoFail
$auditExit = $LASTEXITCODE
$pure = 999999
if (Test-Path $auditReceipt) {
    $m = Select-String -LiteralPath $auditReceipt -Pattern '^PURE_STUB_FILES=(\d+)$'
    if ($m) { $pure = [int]$m.Matches[0].Groups[1].Value }
}
$buildExit = -999
if ($pure -eq 0) {
    & cmake --build $BuildDir --config $Config --target $Target
    $buildExit = $LASTEXITCODE
} else {
    Write-Host "BUILD_SKIPPED=pure_stubs_remaining:$pure"
}
$runtimeExit = -999
$exe = Join-Path $BuildDir "$Config\$Target.exe"
if ($RunRuntime -and $buildExit -eq 0) {
    if (-not (Test-Path $exe)) { $exe = Join-Path $BuildDir "bin\$Config\$Target.exe" }
    if (Test-Path $exe) {
        & $exe @RuntimeArgs
        $runtimeExit = $LASTEXITCODE
    } else { $runtimeExit = -998 }
}
$pass = ($pure -eq 0 -and $buildExit -eq 0 -and ((-not $RunRuntime) -or $runtimeExit -eq 0))
$lines = @(
  'GATE=RAWRXD_IDE_STUB_CLOSURE_001',
  ('TIMESTAMP_UTC=' + (Get-Date).ToUniversalTime().ToString('o')),
  ('PURE_STUB_FILES=' + $pure),
  ('BUILD_EXIT=' + $buildExit),
  ('RUNTIME_REQUESTED=' + [int]$RunRuntime),
  ('RUNTIME_EXIT=' + $runtimeExit),
  ('VERDICT=' + $(if($pass){'PASS'}else{'FAIL'}))
)
[IO.File]::WriteAllLines($Receipt,$lines)
$lines | ForEach-Object { Write-Host $_ }
if (-not $pass) { exit 3 }
