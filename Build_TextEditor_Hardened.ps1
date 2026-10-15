# Build_TextEditor_Hardened.ps1
# ----------------------------------------------------------------------------
# Builds RawrXD_TextEditorGUI_hardened.asm into a signed-off, security-hardened
# x64 Win32 executable.
#
#   RawrXD-Hardened.exe
#     - ASLR        (/DYNAMICBASE, .reloc present)
#     - DEP/NX      (/NXCOMPAT)
#     - CFG         (/GUARD:CF)
#     - Large-addr aware (/LARGEADDRESSAWARE)
#
# Usage:
#   .\Build_TextEditor_Hardened.ps1            # build only
#   .\Build_TextEditor_Hardened.ps1 -Run       # build + launch
#   .\Build_TextEditor_Hardened.ps1 -Clean     # remove outputs first
#
# Requires: Visual Studio 2022 (any edition) with the C++ toolset.
# The script locates ml64.exe and link.exe itself, so it works from a plain
# PowerShell prompt as well as a developer prompt.
# ----------------------------------------------------------------------------
[CmdletBinding()]
param(
    [string]$AsmFile,
    [string]$OutputDir,
    [string]$TargetName = "RawrXD-Hardened.exe",
    [switch]$Run,
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Resolve the script's own directory. $PSScriptRoot is empty when the script is
# launched via `powershell -File`, so fall back through $MyInvocation and the
# current location so the defaults always point at the real file.
$scriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptDir)) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if ([string]::IsNullOrWhiteSpace($scriptDir)) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
}
if ([string]::IsNullOrWhiteSpace($scriptDir)) { $scriptDir = (Get-Location).Path }

if (-not $PSBoundParameters.ContainsKey('AsmFile'))   { $AsmFile   = Join-Path $scriptDir 'RawrXD_TextEditorGUI_hardened.asm' }
if (-not $PSBoundParameters.ContainsKey('OutputDir')) { $OutputDir = $scriptDir }

# ----------------------------------------------------------------------------
# Locate the MSVC tool directories
# ----------------------------------------------------------------------------
function Get-InstallPath {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere) {
        $p = & $vswhere -latest -products * `
             -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
             -property installationPath 2>$null
        if ($LASTEXITCODE -eq 0 -and $p) { return $p.Trim() }
    }
    foreach ($candidate in @(
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools"
    )) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    throw "Visual Studio 2022 (C++ workload) not found. Install it or run from a developer prompt."
}

$vs = Get-InstallPath
$msvcRoot = Get-ChildItem (Join-Path $vs 'VC\Tools\MSVC') -Directory -ErrorAction Stop |
            Sort-Object Name -Descending | Select-Object -First 1
$msvc = $msvcRoot.FullName

$ml64 = Join-Path $msvc 'bin\Hostx64\x64\ml64.exe'
$link = Join-Path $msvc 'bin\Hostx64\x64\link.exe'
foreach ($t in @($ml64, $link)) {
    if (-not (Test-Path -LiteralPath $t)) { throw "Missing tool: $t" }
}

# Windows SDK: newest available
$sdkRoot = 'C:\Program Files (x86)\Windows Kits\10\Lib'
$sdkVer = Get-ChildItem $sdkRoot -Directory -ErrorAction SilentlyContinue |
          Sort-Object Name -Descending | Select-Object -First 1
if (-not $sdkVer) { throw "Windows 10/11 SDK not found under $sdkRoot" }
$sdk = $sdkVer.FullName

$env:LIB = "$msvc\lib\x64;$sdk\um\x64;$sdk\ucrt\x64"

# ----------------------------------------------------------------------------
# Paths
# ----------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $AsmFile)) { throw "Source not found: $AsmFile" }
$obj  = Join-Path $OutputDir ([System.IO.Path]::GetFileNameWithoutExtension($AsmFile) + '.obj')
$exe  = Join-Path $OutputDir $TargetName

if ($Clean) {
    Write-Host "[clean] removing $obj and $exe"
    Remove-Item $obj, $exe -ErrorAction SilentlyContinue
}

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# ----------------------------------------------------------------------------
# Assemble
# ----------------------------------------------------------------------------
Write-Host "[1/2] assembling  $AsmFile"
& $ml64 /c /nologo /W3 /Cp /Fo "$obj" $AsmFile
if ($LASTEXITCODE -ne 0) { throw "ml64 failed with exit code $LASTEXITCODE" }
Write-Host "      -> $obj ($((Get-Item $obj).Length) bytes)"

# ----------------------------------------------------------------------------
# Link with all production mitigations
# ----------------------------------------------------------------------------
Write-Host "[2/2] linking      $exe"
& $link /nologo /subsystem:windows /machine:x64 /entry:WinMain `
        $obj kernel32.lib user32.lib gdi32.lib comdlg32.lib `
        /out:"$exe" `
        /DYNAMICBASE /NXCOMPAT /LARGEADDRESSAWARE /GUARD:CF

# LNK4266 is expected for hand-written MASM (no CRT _load_config_used); the
# flags are still applied. Only a hard link failure aborts the build.
if ($LASTEXITCODE -ne 0) { throw "link failed with exit code $LASTEXITCODE" }

# ----------------------------------------------------------------------------
# Verify the security characteristics actually landed in the image
# ----------------------------------------------------------------------------
$b  = [System.IO.File]::ReadAllBytes($exe)
$lf = [BitConverter]::ToInt32($b, 0x3C)
$dc = [BitConverter]::ToUInt16($b, $lf + 24 + 70)

$reloc = $false
$secOff = $lf + 24 + [BitConverter]::ToUInt16($b, $lf + 20)
$nSec   = [BitConverter]::ToUInt16($b, $lf + 6)
for ($i = 0; $i -lt $nSec; $i++) {
    $o  = $secOff + ($i * 40)
    $nm = [System.Text.Encoding]::ASCII.GetString($b, $o, 8).TrimEnd([char]0)
    if ($nm -eq '.reloc') { $reloc = $true }
}

$checks = [ordered]@{
    'machine is AMD64'            = ([BitConverter]::ToUInt16($b, $lf + 4) -eq 0x8664)
    'subsystem is WINDOWS'        = ([BitConverter]::ToUInt16($b, $lf + 24 + 68) -eq 2)
    'ASLR (DYNAMIC_BASE)'         = [bool]($dc -band 0x0040)
    'DEP / NX (NX_COMPAT)'        = [bool]($dc -band 0x0100)
    'CFG (GUARD_CF)'              = [bool]($dc -band 0x4000)
    'high entropy VA'             = [bool]($dc -band 0x0020)
    '.reloc section present'      = $reloc
    'no writable+exec section'    = $true
}

# A writable AND executable section would neutralise DEP; check it explicitly.
$secOff = $lf + 24 + [BitConverter]::ToUInt16($b, $lf + 20)
for ($i = 0; $i -lt $nSec; $i++) {
    $o  = $secOff + ($i * 40)
    $ch = [BitConverter]::ToUInt32($b, $o + 36)
    if (($ch -band 0x20000000) -and ($ch -band 0x80000000)) {   # WRITE and EXECUTE
        $checks['no writable+exec section'] = $false
    }
}

Write-Host ''
Write-Host '=== security characteristics ==='
$failed = @()
foreach ($k in $checks.Keys) {
    $mark = if ($checks[$k]) { '[x]' } else { '[ ]' }
    Write-Host ("  {0} {1}" -f $mark, $k)
    if (-not $checks[$k]) { $failed += $k }
}

Write-Host ''
if ($failed.Count -gt 0) {
    Write-Warning ("Build produced, but these checks FAILED: " + ($failed -join ', '))
    exit 2
}

Write-Host "BUILD OK -> $exe"
Write-Host ("       -> {0} bytes, all security mitigations verified" -f (Get-Item $exe).Length)

if ($Run) {
    Write-Host ''
    Write-Host 'launching...'
    $p = Start-Process -FilePath $exe -PassThru -WorkingDirectory $PSScriptRoot
    Write-Host "pid=$($p.Id). Close the window to exit."
}
exit 0
