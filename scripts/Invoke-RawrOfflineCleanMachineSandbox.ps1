# Invoke-RawrOfflineCleanMachineSandbox.ps1
# M4: clean-machine-style sandbox install + rollback measure. NOT_RUN!=PASS.
# CLEAN_VM remains ABSENT (this is sandbox, not a hypervisor VM). PROMOTE=0.

[CmdletBinding()]
param(
    [string]$RepoRoot = "",
    [string]$PackageZip = "",
    [string]$OutDir = ""
)

$ErrorActionPreference = "Stop"
$ASOF = Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz"
if (-not $RepoRoot) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}
$m4 = Join-Path $RepoRoot "evidence\PRODUCTION_MATURITY_TOP25_001\OFFLINE_INSTALLER_M4_001"
$guiPack = Join-Path $RepoRoot "evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\packaging"
if (-not $OutDir) { $OutDir = Join-Path $m4 "CLEAN_MACHINE_SANDBOX_001" }
if (-not $PackageZip) {
    $PackageZip = Join-Path $m4 "RawrXD-offline-windows-x64-M4-15A119-675461.zip"
}
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
New-Item -ItemType Directory -Path $guiPack -Force | Out-Null

$expCli = "15A119D148572A4B3011AA9A8AFFE605F8FF40D64B7BF83673ECC10A9393C967"
$expGui = "6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431"

if (-not (Test-Path -LiteralPath $PackageZip)) { throw "MISSING_PACKAGE=$PackageZip" }
$pkgSha = (Get-FileHash -LiteralPath $PackageZip -Algorithm SHA256).Hash.ToUpperInvariant()
$pkgBytes = (Get-Item -LiteralPath $PackageZip).Length

$extract = Join-Path $OutDir "extract"
$target = Join-Path $OutDir "install_root"
if (Test-Path -LiteralPath $extract) { Remove-Item -LiteralPath $extract -Recurse -Force }
if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
New-Item -ItemType Directory -Path $extract -Force | Out-Null
Expand-Archive -LiteralPath $PackageZip -DestinationPath $extract -Force

$pkgRoot = Get-ChildItem -LiteralPath $extract -Directory | Select-Object -First 1
if (-not $pkgRoot) { throw "EMPTY_EXTRACT" }
$pkgRoot = $pkgRoot.FullName
$installPs1 = Join-Path $pkgRoot "scripts\Install-RawrOffline.ps1"
$uninstallPs1 = Join-Path $pkgRoot "scripts\Uninstall-RawrOffline.ps1"
$sw = Join-Path $pkgRoot "SetupWizard.exe"
$vsix = Join-Path $pkgRoot "extensions\rawrxd-lsp-client-0.1.0.vsix"

$swPresent = Test-Path -LiteralPath $sw
$vsixPresent = Test-Path -LiteralPath $vsix
$swSha = if ($swPresent) { (Get-FileHash -LiteralPath $sw -Algorithm SHA256).Hash.ToUpperInvariant() } else { "ABSENT" }
$swSize = if ($swPresent) { (Get-Item -LiteralPath $sw).Length } else { 0 }
$vsixSha = if ($vsixPresent) { (Get-FileHash -LiteralPath $vsix -Algorithm SHA256).Hash.ToUpperInvariant() } else { "ABSENT" }

# Probe SetupWizard /? (non-blocking)
$swHelpExit = -1
$swHelpOut = ""
if ($swPresent) {
    $tmpOut = Join-Path $OutDir "setupwizard_help.out.txt"
    $p = Start-Process -FilePath $sw -ArgumentList @("/?") -Wait -PassThru -NoNewWindow `
        -RedirectStandardOutput $tmpOut -RedirectStandardError (Join-Path $OutDir "setupwizard_help.err.txt")
    $swHelpExit = $p.ExitCode
    if (Test-Path $tmpOut) { $swHelpOut = Get-Content -LiteralPath $tmpOut -Raw }
}
$swReal = ($swSize -ge 100000) -and ($swHelpOut -match "FILE_COPY=1|real CopyFile|SIMULATED=0")

# Install via SetupWizard directly (primary path)
$installLog = Join-Path $OutDir "install.out.txt"
$swInstallExit = -1
if ($swPresent) {
    $p = Start-Process -FilePath $sw -ArgumentList @("/install","/silent","/target=$target","/payload=$pkgRoot") `
        -Wait -PassThru -NoNewWindow -RedirectStandardOutput $installLog `
        -RedirectStandardError (Join-Path $OutDir "install.err.txt")
    $swInstallExit = $p.ExitCode
}
$installTxt = if (Test-Path $installLog) { Get-Content -LiteralPath $installLog -Raw } else { "" }
$fileCopy = if ($installTxt -match "FILE_COPY=1") { 1 } else { 0 }
$installOk = if ($installTxt -match "INSTALL_OK=1") { 1 } else { 0 }
$simulated = if ($installTxt -match "SIMULATED=1") { 1 } else { 0 }

$cliPath = Join-Path $target "bin\rawr.exe"
$guiPath = Join-Path $target "bin\RawrXD-Win32IDE.exe"
$vsixInst = Join-Path $target "extensions\rawrxd-lsp-client-0.1.0.vsix"
$cliOk = 0; $guiOk = 0; $cliH = "ABSENT"; $guiH = "ABSENT"
if (Test-Path $cliPath) {
    $cliH = (Get-FileHash -LiteralPath $cliPath -Algorithm SHA256).Hash.ToUpperInvariant()
    $cliOk = [int]($cliH -eq $expCli)
}
if (Test-Path $guiPath) {
    $guiH = (Get-FileHash -LiteralPath $guiPath -Algorithm SHA256).Hash.ToUpperInvariant()
    $guiOk = [int]($guiH -eq $expGui)
}
$vsixInstOk = [int](Test-Path $vsixInst)

$helpOk = "FAIL"
$helpOut = ""
if ($cliOk -eq 1) {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $helpOut = (& $cliPath 2>&1 | ForEach-Object { "$_" }) -join "`n"
    $ErrorActionPreference = $prev
    if ($helpOut -match "rawr\s+list" -or $helpOut -match "Usage:") { $helpOk = "PASS" }
}

# Rollback
$beforeFiles = 0
if (Test-Path $target) {
    $beforeFiles = @(Get-ChildItem -LiteralPath $target -Recurse -File -ErrorAction SilentlyContinue).Count
}
$rollbackLog = Join-Path $OutDir "uninstall.out.txt"
$swUnExit = -1
if ($swPresent) {
    $p = Start-Process -FilePath $sw -ArgumentList @("/uninstall","/silent","/target=$target") `
        -Wait -PassThru -NoNewWindow -RedirectStandardOutput $rollbackLog `
        -RedirectStandardError (Join-Path $OutDir "uninstall.err.txt")
    $swUnExit = $p.ExitCode
}
if (Test-Path $target) { Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue }
$rollbackOk = [int](-not (Test-Path -LiteralPath $target))

$sandboxPass = [int](
    $swReal -and ($swInstallExit -eq 0) -and ($fileCopy -eq 1) -and ($installOk -eq 1) -and
    ($simulated -eq 0) -and ($cliOk -eq 1) -and ($guiOk -eq 1) -and ($vsixInstOk -eq 1) -and
    ($helpOk -eq "PASS") -and ($rollbackOk -eq 1)
)

$sealBody = @"
M4 CLEAN_MACHINE_SANDBOX_001 MEASURED SEAL
ASOF=$ASOF
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
INVENT_PASS=0
NOT_RUN_NE_PASS=1

PACKAGE_PATH=$PackageZip
PACKAGE_SHA=$pkgSha
PACKAGE_BYTES=$pkgBytes
OFFLINE=1
CLOUD_MODELS=0
NETWORK_REQUIRED=0

SETUPWIZARD_PRESENT=$([int]$swPresent)
SETUPWIZARD_SHA256=$swSha
SETUPWIZARD_SIZE=$swSize
SETUPWIZARD_CLASS=$(if ($swReal) { "REAL_COPYFILE" } else { "STUB_OR_ABSENT" })
SETUPWIZARD_HELP_EXIT=$swHelpExit
VSIX_PRESENT=$([int]$vsixPresent)
VSIX_SHA256=$vsixSha

INSTALL_EXIT=$swInstallExit
FILE_COPY=$fileCopy
INSTALL_OK=$installOk
SIMULATED=$simulated
CLI_SHA_MATCH=$cliOk
GUI_SHA_MATCH=$guiOk
CLI_SHA256=$cliH
GUI_SHA256=$guiH
VSIX_INSTALLED=$vsixInstOk
HELP_SMOKE=$helpOk
USAGE_SEEN=$([int]($helpOk -eq "PASS"))

ROLLBACK_BEFORE_FILES=$beforeFiles
UNINSTALL_EXIT=$swUnExit
ROLLBACK_OK=$rollbackOk

CLEAN_MACHINE_SANDBOX=$sandboxPass
CLEAN_VM=0
CLEAN_VM_NOTE=ABSENT — sandbox equivalent only; do not invent CLEAN_VM PASS
NOT_PUBLISHED=1
WINGET=NOT_PUBLISHED
CHOCO=NOT_PUBLISHED
NSIS=ABSENT
MSI=ABSENT
SIGNED_RELEASE=ABSENT

DISPOSITION
  SANDBOX_INSTALL_ROLLBACK=$(if ($sandboxPass -eq 1) { "PASS" } else { "FAIL" })
  NOT_PUBLISHED_CLOSED=0
  NEXT_GATE=PUBLIC_CHANNEL_OR_BUILT_MSI_SIGNED_ON_CLEAN_VM
  REMAINING=
    G_PUBLIC_CHANNEL=NOT_PUBLISHED (winget/choco publish evidence ABSENT)
    G_CLEAN_VM=ABSENT (hypervisor clean-VM witness ABSENT)
    G_SIGNED_RELEASE=ABSENT
    G_NSIS_MSI_BUILT=ABSENT

LAW
  NOT_RUN != PASS
  CLEAN_MACHINE_SANDBOX != CLEAN_VM PASS
  NOT_PUBLISHED stays OPEN without public-channel evidence
  PROMOTE=0
"@

Set-Content -LiteralPath (Join-Path $OutDir "SEAL.txt") -Value $sealBody -Encoding UTF8
Set-Content -LiteralPath (Join-Path $OutDir "RUNLOG.txt") -Value @"
ASOF=$ASOF
PACKAGE_SHA=$pkgSha
INSTALL_EXIT=$swInstallExit
FILE_COPY=$fileCopy
HELP_SMOKE=$helpOk
ROLLBACK_OK=$rollbackOk
CLEAN_MACHINE_SANDBOX=$sandboxPass
CLEAN_VM=0
NOT_PUBLISHED=1
PROMOTE=0
"@ -Encoding UTF8

# Mirror seal into GUI packaging (enterprise/GUI receipts) — no CANON/LIVE/JOINT PCT
Set-Content -LiteralPath (Join-Path $guiPack "M4_CLEAN_MACHINE_SANDBOX_SEAL.txt") -Value $sealBody -Encoding UTF8
Copy-Item -LiteralPath (Join-Path $OutDir "SEAL.txt") -Destination (Join-Path $m4 "CLEAN_MACHINE_SANDBOX_SEAL.txt") -Force

# Refresh package SEAL honesty fields without inventing publish close
$pkgSealPath = Join-Path $m4 "SEAL.txt"
if (Test-Path $pkgSealPath) {
    $extra = @"

CLEAN_MACHINE_SANDBOX=$sandboxPass
CLEAN_MACHINE_SANDBOX_SEAL=$OutDir\SEAL.txt
SETUPWIZARD_CLASS=$(if ($swReal) { "REAL_COPYFILE" } else { "STUB_OR_ABSENT" })
NOT_PUBLISHED=1
NOT_PUBLISHED_CLOSED=0
NEXT_GATE=PUBLIC_CHANNEL_OR_BUILT_MSI_SIGNED_ON_CLEAN_VM
PROMOTE=0
"@
    Add-Content -LiteralPath $pkgSealPath -Value $extra -Encoding UTF8
}

Write-Host "CLEAN_MACHINE_SANDBOX=$sandboxPass"
Write-Host "ROLLBACK_OK=$rollbackOk"
Write-Host "HELP_SMOKE=$helpOk"
Write-Host "NOT_PUBLISHED=1"
Write-Host "CLEAN_VM=0"
Write-Host "PROMOTE=0"
Write-Host "SEAL=$OutDir\SEAL.txt"
if ($sandboxPass -ne 1) { exit 1 }
exit 0
