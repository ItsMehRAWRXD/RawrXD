# Invoke-RawrOfflineCleanVmWitness.ps1
# Fail-closed CLEAN_VM witness for sealed M4 offline zip.
# Host-local install is NOT CLEAN_VM. Requires -ConfirmCleanGuest on a real guest.
# PROMOTE=0 · INVENT_CLEAN_VM=0 · no JOINT PCT invent.

[CmdletBinding()]
param(
    [string]$RepoRoot = "",
    [string]$PackageZip = "",
    [string]$TargetDir = "",
    [string]$OutDir = "",
    [switch]$ConfirmCleanGuest,
    [switch]$AddUserPath
)

$ErrorActionPreference = "Stop"
$ASOF = Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz"
if (-not $RepoRoot) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}
$m4 = Join-Path $RepoRoot "evidence\PRODUCTION_MATURITY_TOP25_001\OFFLINE_INSTALLER_M4_001"
if (-not $OutDir) { $OutDir = Join-Path $m4 "CLEAN_VM_WITNESS_001" }
if (-not $PackageZip) {
    $PackageZip = Join-Path $m4 "RawrXD-offline-windows-x64-M4-15A119-675461.zip"
}
$expPkg = "D4DF3ED526C7037A309F41062CA17C5C83E1D0FC05C5399E9252DEBFA4AB9129"
$expCli = "15A119D148572A4B3011AA9A8AFFE605F8FF40D64B7BF83673ECC10A9393C967"
$expGui = "6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431"

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

if (-not (Test-Path -LiteralPath $PackageZip)) { throw "MISSING_PACKAGE=$PackageZip" }
$pkgSha = (Get-FileHash -LiteralPath $PackageZip -Algorithm SHA256).Hash.ToUpperInvariant()
if ($pkgSha -ne $expPkg) { throw "PACKAGE_SHA_MISMATCH expected=$expPkg actual=$pkgSha" }

$sandboxExe = Test-Path "$env:WINDIR\System32\WindowsSandbox.exe"
$hvCmdlet = [bool](Get-Command Get-VM -ErrorAction SilentlyContinue)

if (-not $ConfirmCleanGuest) {
    $block = @"
CLEAN_VM_WITNESS_BLOCKED
ASOF=$ASOF
PROMOTE=0
CLEAN_VM=0
CLEAN_VM_STATUS=NOT_RUN
PACKAGE_SHA=$pkgSha
REASON=ConfirmCleanGuest_not_set
HOST_NOTE=Run this script INSIDE an isolated Hyper-V VM / Windows Sandbox / clean image with -ConfirmCleanGuest after transferring only the sealed zip. Host-local != CLEAN_VM.
WINDOWS_SANDBOX_EXE=$([int]$sandboxExe)
HYPER_V_GET_VM=$([int]$hvCmdlet)
NEXT_EXECUTABLE_GATE=HYPERVISOR_CLEAN_VM_INSTALL_ROLLBACK_WITNESS
GATE_DOC=$m4\CLEAN_VM_REMAINING_GATE.txt
INVENT_CLEAN_VM=0
"@
    Set-Content -LiteralPath (Join-Path $OutDir "BLOCKED.txt") -Value $block -Encoding UTF8
    Write-Host $block
    exit 2
}

if (-not $TargetDir) {
    $TargetDir = Join-Path $env:LOCALAPPDATA "RawrXD\offline-M4-cleanvm"
}

$extract = Join-Path $OutDir "extract"
if (Test-Path -LiteralPath $extract) { Remove-Item -LiteralPath $extract -Recurse -Force }
if (Test-Path -LiteralPath $TargetDir) { Remove-Item -LiteralPath $TargetDir -Recurse -Force }
New-Item -ItemType Directory -Path $extract -Force | Out-Null
Expand-Archive -LiteralPath $PackageZip -DestinationPath $extract -Force
$pkgRoot = (Get-ChildItem -LiteralPath $extract -Directory | Select-Object -First 1).FullName
$installPs1 = Join-Path $pkgRoot "scripts\Install-RawrOffline.ps1"
if (-not (Test-Path -LiteralPath $installPs1)) { throw "MISSING_INSTALL_SCRIPT=$installPs1" }

$installArgs = @("-NoProfile", "-File", $installPs1, "-TargetDir", $TargetDir)
if ($AddUserPath) { $installArgs += "-AddUserPath" }
$p = Start-Process -FilePath "pwsh" -ArgumentList $installArgs -Wait -PassThru -NoNewWindow `
    -RedirectStandardOutput (Join-Path $OutDir "install.out.txt") `
    -RedirectStandardError (Join-Path $OutDir "install.err.txt")
$installExit = $p.ExitCode

$cli = Join-Path $TargetDir "bin\rawr.exe"
$gui = Join-Path $TargetDir "bin\RawrXD-Win32IDE.exe"
$cliH = if (Test-Path $cli) { (Get-FileHash $cli -Algorithm SHA256).Hash.ToUpperInvariant() } else { "ABSENT" }
$guiH = if (Test-Path $gui) { (Get-FileHash $gui -Algorithm SHA256).Hash.ToUpperInvariant() } else { "ABSENT" }
$cliOk = [int]($cliH -eq $expCli)
$guiOk = [int]($guiH -eq $expGui)

$helpOk = "FAIL"
if ($cliOk -eq 1) {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $helpOut = (& $cli 2>&1 | ForEach-Object { "$_" }) -join "`n"
    $ErrorActionPreference = $prev
    if ($helpOut -match "Usage:" -or $helpOut -match "rawr\s+list") { $helpOk = "PASS" }
    Set-Content (Join-Path $OutDir "cli_help.out.txt") -Value $helpOut -Encoding UTF8
}

# Rollback
if (Test-Path -LiteralPath $TargetDir) { Remove-Item -LiteralPath $TargetDir -Recurse -Force }
$rollbackOk = [int](-not (Test-Path -LiteralPath $TargetDir))

$pass = [int](
    ($installExit -eq 0) -and ($cliOk -eq 1) -and ($guiOk -eq 1) -and
    ($helpOk -eq "PASS") -and ($rollbackOk -eq 1)
)

$seal = @"
CLEAN_VM_WITNESS_001
ASOF=$ASOF
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
CONFIRM_CLEAN_GUEST=1
PACKAGE_PATH=$PackageZip
PACKAGE_SHA=$pkgSha
INSTALL_EXIT=$installExit
CLI_SHA_MATCH=$cliOk
GUI_SHA_MATCH=$guiOk
CLI_SHA256=$cliH
GUI_SHA256=$guiH
HELP_SMOKE=$helpOk
ROLLBACK_OK=$rollbackOk
OFFLINE=1
CLOUD_MODELS=0
NETWORK_REQUIRED_FOR_INSTALL=0
CLEAN_VM=$pass
CLEAN_VM_STATUS=$(if ($pass -eq 1) { "PASS" } else { "FAIL" })
M4_PCT_RAISE=0
INVENT_JOINT_PCT=0
LAW=NOT_RUN!=PASS; guest ConfirmCleanGuest required; host-local!=CLEAN_VM
"@
Set-Content -LiteralPath (Join-Path $OutDir "SEAL.txt") -Value $seal -Encoding UTF8
Write-Host $seal
if ($pass -ne 1) { exit 1 }
exit 0
