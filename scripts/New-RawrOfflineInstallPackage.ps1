# New-RawrOfflineInstallPackage.ps1
# MILESTONE-4: single reproducible offline installer package (zip + local install).
# Pins CLI tip 15A119D1 + GUI tip 6754616E. No network. No cloud models.
# PROMOTE=0 · CLEAN_VM not claimed · winget/choco NOT_PUBLISHED.

[CmdletBinding()]
param(
    [string]$RepoRoot = "",
    [string]$OutDir = "",
    [string]$PackageName = "",
    [string]$CliTipPath = "",
    [string]$GuiTipPath = "",
    [string]$ExpectedCliSha256 = "15A119D148572A4B3011AA9A8AFFE605F8FF40D64B7BF83673ECC10A9393C967",
    [string]$ExpectedGuiSha256 = "6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431",
    [switch]$SkipZip
)

$ErrorActionPreference = "Stop"
$ASOF = Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz"

if (-not $RepoRoot) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}
if (-not $OutDir) {
    $OutDir = Join-Path $RepoRoot "evidence\PRODUCTION_MATURITY_TOP25_001\OFFLINE_INSTALLER_M4_001"
}
if (-not $PackageName) {
    $PackageName = "RawrXD-offline-windows-x64-M4-15A119-675461"
}
if (-not $CliTipPath) {
    $CliTipPath = Join-Path $RepoRoot "build_ninja\bin\rawr_gpufwd_15A119D1.exe"
}
if (-not $GuiTipPath) {
    $GuiTipPath = Join-Path $RepoRoot "bin\RawrXD-Win32IDE_tip_land_6754616E.exe"
}

$ExpectedCliSha256 = $ExpectedCliSha256.ToUpperInvariant()
$ExpectedGuiSha256 = $ExpectedGuiSha256.ToUpperInvariant()

function Assert-Tip([string]$Path, [string]$Expected, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "MISSING_$Label=$Path"
    }
    $h = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($h -ne $Expected) {
        throw "TIP_SHA_MISMATCH_$Label expected=$Expected actual=$h path=$Path"
    }
    return $h
}

Write-Host "New-RawrOfflineInstallPackage  PROMOTE=0  ASOF=$ASOF"
Write-Host "REPO=$RepoRoot"
Write-Host "OUT=$OutDir"

$cliSha = Assert-Tip $CliTipPath $ExpectedCliSha256 "CLI_15A119D1"
$guiSha = Assert-Tip $GuiTipPath $ExpectedGuiSha256 "GUI_6754616E"
Write-Host "CLI_TIP_SHA256=$cliSha"
Write-Host "GUI_TIP_SHA256=$guiSha"

$stage = Join-Path $OutDir "stage"
$pkgRoot = Join-Path $stage $PackageName
if (Test-Path -LiteralPath $stage) {
    Remove-Item -LiteralPath $stage -Recurse -Force
}
New-Item -ItemType Directory -Path (Join-Path $pkgRoot "bin") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $pkgRoot "scripts") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $pkgRoot "extensions") -Force | Out-Null
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

Copy-Item -LiteralPath $CliTipPath -Destination (Join-Path $pkgRoot "bin\rawr.exe") -Force
Copy-Item -LiteralPath $GuiTipPath -Destination (Join-Path $pkgRoot "bin\RawrXD-Win32IDE.exe") -Force

$swPath = Join-Path $RepoRoot "installer\SetupWizard.exe"
$vsixPath = Join-Path $RepoRoot "vscode-extension\rawrxd-lsp-client-0.1.0.vsix"
if (-not (Test-Path -LiteralPath $swPath)) { throw "MISSING_SETUPWIZARD=$swPath" }
if (-not (Test-Path -LiteralPath $vsixPath)) { throw "MISSING_VSIX=$vsixPath" }
$swSha = (Get-FileHash -LiteralPath $swPath -Algorithm SHA256).Hash.ToUpperInvariant()
$vsixSha = (Get-FileHash -LiteralPath $vsixPath -Algorithm SHA256).Hash.ToUpperInvariant()
$swBytes = (Get-Item -LiteralPath $swPath).Length
if ($swBytes -lt 100000) { throw "SETUPWIZARD_STILL_TINY_STUB size=$swBytes (expect real CopyFile build)" }
Copy-Item -LiteralPath $swPath -Destination (Join-Path $pkgRoot "SetupWizard.exe") -Force
Copy-Item -LiteralPath $vsixPath -Destination (Join-Path $pkgRoot "extensions\rawrxd-lsp-client-0.1.0.vsix") -Force
Write-Host "SETUPWIZARD_SHA256=$swSha size=$swBytes"
Write-Host "VSIX_SHA256=$vsixSha"

$installPs1 = @'
# Install-RawrOffline.ps1 — extract-local install; OFFLINE=1; no network; no models.
# PROMOTE=0 · CLEAN_VM not claimed.

[CmdletBinding()]
param(
    [string]$TargetDir = "",
    [switch]$AddUserPath,
    [switch]$SkipHelpSmoke
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$pkg = Split-Path -Parent $here
if (-not $TargetDir) {
    $TargetDir = Join-Path $env:LOCALAPPDATA "RawrXD\offline-M4"
}

$pins = Join-Path $pkg "PINS.txt"
if (-not (Test-Path -LiteralPath $pins)) { throw "MISSING_PINS=$pins" }

$sw = Join-Path $pkg "SetupWizard.exe"
$fileCopy = 0
if (Test-Path -LiteralPath $sw) {
    $swArgs = @("/install", "/silent", "/target=$TargetDir", "/payload=$pkg")
    $p = Start-Process -FilePath $sw -ArgumentList $swArgs -Wait -PassThru -NoNewWindow
    if ($p.ExitCode -ne 0) { throw "SETUPWIZARD_INSTALL_FAIL exit=$($p.ExitCode)" }
    $fileCopy = 1
} else {
    $srcBin = Join-Path $pkg "bin"
    if (-not (Test-Path -LiteralPath $srcBin)) { throw "MISSING_BIN=$srcBin" }
    New-Item -ItemType Directory -Path (Join-Path $TargetDir "bin") -Force | Out-Null
    Get-ChildItem -LiteralPath $srcBin -File | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $TargetDir "bin\$($_.Name)") -Force
    }
    $srcExt = Join-Path $pkg "extensions"
    if (Test-Path -LiteralPath $srcExt) {
        New-Item -ItemType Directory -Path (Join-Path $TargetDir "extensions") -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $srcExt "*") -Destination (Join-Path $TargetDir "extensions") -Force
    }
    $fileCopy = 1
}
Copy-Item -LiteralPath $pins -Destination (Join-Path $TargetDir "PINS.txt") -Force
$manSrc = Join-Path $pkg "OFFLINE_MANIFEST.txt"
if (Test-Path -LiteralPath $manSrc) {
    Copy-Item -LiteralPath $manSrc -Destination (Join-Path $TargetDir "OFFLINE_MANIFEST.txt") -Force
}
Write-Host "FILE_COPY=$fileCopy"
Write-Host "SIMULATED=0"

$rawr = Join-Path $TargetDir "bin\rawr.exe"
$gui  = Join-Path $TargetDir "bin\RawrXD-Win32IDE.exe"
$cliH = (Get-FileHash -LiteralPath $rawr -Algorithm SHA256).Hash.ToUpperInvariant()
$guiH = (Get-FileHash -LiteralPath $gui  -Algorithm SHA256).Hash.ToUpperInvariant()
$expCli = "15A119D148572A4B3011AA9A8AFFE605F8FF40D64B7BF83673ECC10A9393C967"
$expGui = "6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431"
if ($cliH -ne $expCli) { throw "POST_INSTALL_CLI_SHA_MISMATCH actual=$cliH" }
if ($guiH -ne $expGui) { throw "POST_INSTALL_GUI_SHA_MISMATCH actual=$guiH" }

if ($AddUserPath) {
    $bin = Join-Path $TargetDir "bin"
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($null -eq $userPath) { $userPath = "" }
    $parts = @($userPath -split ";" | Where-Object { $_ -and $_.Trim() -ne "" })
    if (-not ($parts | Where-Object { $_.TrimEnd("\") -eq $bin.TrimEnd("\") })) {
        $parts += $bin
        [Environment]::SetEnvironmentVariable("Path", ($parts -join ";"), "User")
        Write-Host "ADDED_TO_USER_PATH=$bin"
    } else {
        Write-Host "ALREADY_ON_USER_PATH=$bin"
    }
}

$helpOk = "SKIP"
if (-not $SkipHelpSmoke) {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $helpOut = (& $rawr 2>&1 | ForEach-Object { "$_" }) -join "`n"
    $ErrorActionPreference = $prev
    $helpOk = if ($helpOut -match "rawr\s+list" -or $helpOut -match "Usage:") { "PASS" } else { "FAIL" }
}

Write-Host "INSTALL_TARGET=$TargetDir"
Write-Host "CLI_SHA256=$cliH"
Write-Host "GUI_SHA256=$guiH"
Write-Host "HELP_SMOKE=$helpOk"
Write-Host "OFFLINE=1"
Write-Host "CLOUD_MODELS=0"
Write-Host "CLEAN_VM=0"
Write-Host "CLEAN_MACHINE_SANDBOX=0"
Write-Host "PROMOTE=0"
if ($helpOk -eq "FAIL") { exit 1 }
exit 0
'@
Set-Content -LiteralPath (Join-Path $pkgRoot "scripts\Install-RawrOffline.ps1") -Value $installPs1 -Encoding UTF8

$uninstallPs1 = @'
# Uninstall-RawrOffline.ps1 — rollback local M4 offline install. PROMOTE=0
[CmdletBinding()]
param([string]$TargetDir = "")
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$pkg = Split-Path -Parent $here
if (-not $TargetDir) { $TargetDir = Join-Path $env:LOCALAPPDATA "RawrXD\offline-M4" }
$sw = Join-Path $pkg "SetupWizard.exe"
if (Test-Path -LiteralPath $sw) {
    $p = Start-Process -FilePath $sw -ArgumentList @("/uninstall","/silent","/target=$TargetDir") -Wait -PassThru -NoNewWindow
    Write-Host "SETUPWIZARD_UNINSTALL_EXIT=$($p.ExitCode)"
}
if (Test-Path -LiteralPath $TargetDir) {
    Remove-Item -LiteralPath $TargetDir -Recurse -Force
}
$gone = -not (Test-Path -LiteralPath $TargetDir)
Write-Host "ROLLBACK_OK=$([int]$gone)"
Write-Host "OFFLINE=1"
Write-Host "PROMOTE=0"
if (-not $gone) { exit 1 }
exit 0
'@
Set-Content -LiteralPath (Join-Path $pkgRoot "scripts\Uninstall-RawrOffline.ps1") -Value $uninstallPs1 -Encoding UTF8

$pinsTxt = @"
PINS — RawrXD offline package M4
ASOF=$ASOF
GIT_HEAD=ae418355d1973b50af487cd5c084a0ff81378a64
BRANCH=work/v0-first-divergence
PROMOTE=0
OFFLINE=1
CLOUD_MODELS=0
CLEAN_VM=0
NOT_PUBLISHED=1
WINGET=NOT_PUBLISHED
CHOCO=NOT_PUBLISHED
NSIS=ABSENT
MSI=ABSENT
SETUPWIZARD=REAL_COPYFILE
SETUPWIZARD_SHA256=$swSha
VSIX=extensions/rawrxd-lsp-client-0.1.0.vsix
VSIX_SHA256=$vsixSha

CLI_TIP_PREFIX=15A119D1
CLI_TIP_EXE=bin/rawr.exe
CLI_TIP_SHA256=$cliSha
CLI_TIP_SOURCE=$CliTipPath

GUI_TIP_PREFIX=6754616E
GUI_TIP_EXE=bin/RawrXD-Win32IDE.exe
GUI_TIP_SHA256=$guiSha
GUI_TIP_SOURCE=$GuiTipPath

INSTALL=scripts/Install-RawrOffline.ps1
UNINSTALL=scripts/Uninstall-RawrOffline.ps1
SETUPWIZARD_EXE=SetupWizard.exe
NETWORK_REQUIRED=0
"@
Set-Content -LiteralPath (Join-Path $pkgRoot "PINS.txt") -Value $pinsTxt -Encoding UTF8

$readme = @"
# RawrXD Offline Install Package (MILESTONE-4)

OFFLINE=1 · CLOUD_MODELS=0 · PROMOTE=0 · CLEAN_VM=0 · NOT_PUBLISHED=1
SETUPWIZARD=REAL_COPYFILE · VSIX bundled · rollback script included

## What this is
Reproducible local zip that installs tip-pinned CLI + GUI + SetupWizard + VSIX
with **no network** and **no cloud / bundled model weights**.

| Artifact | Tip / note | SHA256 |
|----------|------------|--------|
| rawr.exe | 15A119D1 | $cliSha |
| RawrXD-Win32IDE.exe | 6754616E | $guiSha |
| SetupWizard.exe | real CopyFile | $swSha |
| rawrxd-lsp-client-0.1.0.vsix | bundled | $vsixSha |

## Install (offline)
``````powershell
Expand-Archive .\RawrXD-offline-windows-x64-M4-15A119-675461.zip -DestinationPath .\rawrxd-offline
pwsh -File .\rawrxd-offline\$PackageName\scripts\Install-RawrOffline.ps1
# or: .\SetupWizard.exe /install /silent /target=`$env:LOCALAPPDATA\RawrXD\offline-M4
``````

## Rollback
``````powershell
pwsh -File .\rawrxd-offline\$PackageName\scripts\Uninstall-RawrOffline.ps1
``````

## Honesty
- CLEAN_VM install witness: **ABSENT** (CLEAN_VM=0); sandbox measure separate
- winget / Chocolatey / NSIS / MSI: **NOT_PUBLISHED / ABSENT**
- PROMOTE=0
"@
Set-Content -LiteralPath (Join-Path $pkgRoot "README.md") -Value $readme -Encoding UTF8

function Build-ContentsList([string]$Root) {
    $lines = New-Object System.Collections.Generic.List[string]
    Get-ChildItem -LiteralPath $Root -Recurse -File | Sort-Object FullName | ForEach-Object {
        $rel = $_.FullName.Substring($Root.Length).TrimStart("\")
        $h = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
        $lines.Add(("{0}`t{1}`t{2}" -f $h, $_.Length, $rel.Replace("\", "/")))
    }
    return $lines
}

# Placeholder then final list so OFFLINE_MANIFEST itself is inventoried
Set-Content -LiteralPath (Join-Path $pkgRoot "OFFLINE_MANIFEST.txt") -Value "PLACEHOLDER" -Encoding UTF8
$contentsLines = Build-ContentsList $pkgRoot
$manifest = @"
OFFLINE_MANIFEST — stage contents before zip
ASOF=$ASOF
PACKAGE_NAME=$PackageName
OFFLINE=1
CLOUD_MODELS=0
CLEAN_VM=0
PROMOTE=0
FILE_COUNT=$($contentsLines.Count)
SHA256`tBYTES`tRELPATH
$($contentsLines -join "`n")
"@
Set-Content -LiteralPath (Join-Path $pkgRoot "OFFLINE_MANIFEST.txt") -Value $manifest -Encoding UTF8
# Re-hash list with final OFFLINE_MANIFEST bytes
$contentsLines = Build-ContentsList $pkgRoot
$manifest = @"
OFFLINE_MANIFEST — stage contents before zip
ASOF=$ASOF
PACKAGE_NAME=$PackageName
OFFLINE=1
CLOUD_MODELS=0
CLEAN_VM=0
PROMOTE=0
FILE_COUNT=$($contentsLines.Count)
SHA256`tBYTES`tRELPATH
$($contentsLines -join "`n")
"@
Set-Content -LiteralPath (Join-Path $pkgRoot "OFFLINE_MANIFEST.txt") -Value $manifest -Encoding UTF8
Set-Content -LiteralPath (Join-Path $OutDir "CONTENTS_LIST.txt") -Value $manifest -Encoding UTF8

$zipPath = Join-Path $OutDir "$PackageName.zip"
if (-not $SkipZip) {
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($stage, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)
}

$packageSha = "SKIP"
$packageBytes = 0
if (Test-Path -LiteralPath $zipPath) {
    $packageSha = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToUpperInvariant()
    $packageBytes = (Get-Item -LiteralPath $zipPath).Length
}

$seal = @"
MILESTONE-4 OFFLINE_INSTALLER_M4_001 SEAL
ASOF=$ASOF
GIT_HEAD=ae418355d1973b50af487cd5c084a0ff81378a64
BRANCH=work/v0-first-divergence
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
RELEASE=HELD

PACKAGE_PATH=$zipPath
PACKAGE_SHA=$packageSha
PACKAGE_BYTES=$packageBytes
OFFLINE=1
CLOUD_MODELS=0
CLEAN_VM=0
CLEAN_VM_NOTE=ABSENT — no clean-VM install witness; do not invent PASS
NOT_PUBLISHED=1
WINGET=NOT_PUBLISHED
CHOCO=NOT_PUBLISHED
NSIS=ABSENT
MSI=ABSENT

CLI_TIP_SHA256=$cliSha
GUI_TIP_SHA256=$guiSha
SETUPWIZARD_SHA256=$swSha
SETUPWIZARD_CLASS=REAL_COPYFILE
VSIX_SHA256=$vsixSha
RECIPE=scripts/New-RawrOfflineInstallPackage.ps1
INSTALL_SCRIPT=scripts/Install-RawrOffline.ps1 (inside package)
UNINSTALL_SCRIPT=scripts/Uninstall-RawrOffline.ps1 (inside package)
CONTENTS_LIST=CONTENTS_LIST.txt
STAGE=$pkgRoot

INVENTORY_REAL_VS_ABSENT
  REAL: tip CLI/GUI · SetupWizard REAL_COPYFILE · bundled VSIX · offline zip+install/uninstall
  DRAFT_SHA_BOUND: distribution winget/choco/homebrew → v14.7.3 GitHub zip (legacy)
  ABSENT: CLEAN_VM (hypervisor) · winget/choco publish · NSIS/MSI built · bundled models

GAPS
  G_CLEAN_VM=ABSENT (sandbox ≠ clean VM)
  G_PUBLIC_CHANNEL=NOT_PUBLISHED
  G_NSIS_MSI=ABSENT
  G_SIGNED_RELEASE=ABSENT

LAW
  NOT_RUN != PASS
  DRAFT_SHA_BOUND != PUBLISHED
  CLEAN_VM=0 != CLEAN_VM PASS
  SANDBOX_MEASURE != CLEAN_VM PASS
  NOT_PUBLISHED remains until public channel evidence
  PROMOTE=0
"@
Set-Content -LiteralPath (Join-Path $OutDir "SEAL.txt") -Value $seal -Encoding UTF8
Set-Content -LiteralPath (Join-Path $OutDir "PACKAGE_SHA.txt") -Value @"
PACKAGE_SHA=$packageSha
PACKAGE_BYTES=$packageBytes
PACKAGE_PATH=$zipPath
OFFLINE=1
CLEAN_VM=0
PROMOTE=0
ASOF=$ASOF
"@ -Encoding UTF8

Write-Host "PACKAGE_PATH=$zipPath"
Write-Host "PACKAGE_SHA=$packageSha"
Write-Host "PACKAGE_BYTES=$packageBytes"
Write-Host "OFFLINE=1"
Write-Host "CLEAN_VM=0"
Write-Host "PROMOTE=0"
Write-Host "SEAL=$OutDir\SEAL.txt"
exit 0
