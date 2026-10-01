# RAWRXD_B81_CANONICAL_SWEEP_BUILD_001
#
# One command that builds the regime sweep so the LINK cannot fail for the
# three reasons it kept failing when the translation units were compiled ad hoc:
#
#   LNK2019/LNK1120 unresolved externals
#       regime_sweep.cpp gained calls to cpu::DispatchPendingAtReturn(),
#       DispatchCount(), etc. while rawrxd_cpu_math.obj predated them. Mixing a
#       freshly compiled sweep with a stale library object links only if the
#       library happens to export what the caller wants. Every TU is therefore
#       recompiled from source on every invocation -- there is no cached object
#       to go stale.
#
#   LNK2038 + LNK2005 RuntimeLibrary mismatch
#       The pre-existing objects were built /MD (dynamic CRT). Compiling one TU
#       /MT produced libcpmt + msvcprt duplicates and a RuntimeLibrary mismatch
#       against the /MD objects. The CRT is now pinned in ONE place ($Crt) and
#       applied to every TU, so a mismatch cannot arise from a per-invocation
#       flag.
#
#   LNK1104 cannot open file '<out>.exe'
#       A previous sweep binary was still running. The output name is passed in
#       explicitly and the script refuses to clobber a live binary unless
#       -Force is passed, so the failure is reported rather than guessed at.
#
# Usage:
#   pwsh -File tools/build_regime_sweep.ps1 -Out sweep.exe
#   pwsh -File tools/build_regime_sweep.ps1 -Out sweep.exe -Force
param(
    [string]$Out = 'regime_sweep.exe',
    [switch]$Force,
    [string]$Cpp = 'regime_sweep.cpp'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# ---------------------------------------------------------------- toolchain
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products * -property installationPath
if (-not $vs) { $vs = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools' }
$vc = Get-ChildItem "$vs\VC\Tools\MSVC" -Directory | Sort-Object Name -Descending | Select-Object -First 1
$vcRoot = $vc.FullName
$sdkVer = (Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\Include" -Directory |
           Sort-Object Name -Descending | Select-Object -First 1).Name
$sdk = "${env:ProgramFiles(x86)}\Windows Kits\10"

$env:Path = "$vcRoot\bin\Hostx64\x64;$sdk\bin\$sdkVer\x64;$env:Path"
$env:INCLUDE = "$vcRoot\include;$sdk\Include\$sdkVer\ucrt;$sdk\Include\$sdkVer\um;$sdk\Include\$sdkVer\shared;$sdk\Include\$sdkVer\winrt"
$env:LIB = "$vcRoot\lib\x64;$sdk\Lib\$sdkVer\ucrt\x64;$sdk\Lib\$sdkVer\um\x64"

# ---------------------------------------------------------------- flags
# The runtime library is pinned in ONE place and applied to every TU. A
# mismatch between two objects is fatal at link time (LNK2038), and it happens
# whenever one TU is compiled with a different CRT from the rest -- which is how
# libcpmt/msvcprt duplicates (LNK2005) appeared during this build's first run.
#
# $CrtCl is the cl.exe spelling. Do not replace it with the CMake property
# spelling (MultiThreadedDLL): cl does not accept that form and silently warns
# "ignoring unknown option", then treats the next argument as an input file --
# which is how "LINK 4 objects" turned into a link against a file literally
# named "cl : Command line warning ...".
$CrtCl = '/MD'   # dynamic CRT, matching the pre-existing objects

$common = @(
    '/nologo', '/std:c++20', '/O2', '/arch:AVX512', '/DNDEBUG', '/EHsc',
    $CrtCl, '/I', 'src', '/I', 'include', '/wd4996'
)

# Every TU the executable needs. Listed explicitly rather than globbed: a glob
# would silently pick up a half-written file mid-edit and link stale code.
$tus = @(
    @{ src = 'src/gguf_loader.cpp'          }
    @{ src = 'src/rawrxd_transformer.cpp'   }
    @{ src = 'src/rawrxd_cpu_math.cpp'      }
    @{ src = $Cpp                           }
)

Write-Output "=== RAWRXD_B81_CANONICAL_SWEEP_BUILD_001 ==="
Write-Output "MSVC    = $vcRoot"
Write-Output "SDK     = $sdkVer"
Write-Output "CRT     = $CrtCl"
Write-Output "Output  = $Out"

# RAWRXD_B81_OUTPUT_GUARD_001
# HARD STOP if the output path resolves to a source file.
#
# Checked BEFORE the running-binary test. This is not hypothetical: an earlier
# version of this script captured the compiler's output into a variable named
# `$out`. PowerShell variable names are CASE-INSENSITIVE, so `$out = & cl ...`
# silently overwrote the `$Out` parameter. The link then ran with
# `/Fe:<the compiler's last echo line>` -- literally "regime_sweep.cpp" -- and
# because /Fe names an output PATH, cl wrote the linked executable over the
# sweep source: 24516 bytes of C++ became 186368 bytes starting with "MZ".
#
# The file was recoverable only because a derived copy happened to exist. A
# guard that depends on a lucky backup is not a guard.
#
# Order matters: with a source path, Get-Process matches any RUNNING sweep
# (they share the stem), so the live-binary test fires first and reports
# "regime_sweep.cpp is running as PID ..." -- true, but the actual hazard is
# that the path is a source file at all.
$outExt = [IO.Path]::GetExtension($Out)
$sourceExts = @('.cpp', '.c', '.h', '.hpp', '.hxx', '.cc', '.asm', '.inc')
if ($sourceExts -contains $outExt.ToLower()) {
    Write-Output "FAIL: refusing to link to '$Out'."
    Write-Output "      That is a source extension. /Fe writes a BINARY at that path;"
    Write-Output "      a source file would be overwritten."
    exit 4
}

# ------------------------------------------------- refuse to clobber a live exe
if (Test-Path $Out) {
    $running = Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($Out)) -ErrorAction SilentlyContinue
    if ($running -and -not $Force) {
        Write-Output "FAIL: '$Out' is running as PID $($running.Id -join ',')."
        Write-Output "      Wait for it to exit, or pass -Force to write a new file anyway."
        exit 3
    }
}

# ---------------------------------------------------------------- compile
$objs = @()
$failed = $false
foreach ($tu in $tus) {
    if (-not (Test-Path $tu.src)) {
        Write-Output "MISSING SOURCE: $($tu.src)"
        $failed = $true
        continue
    }
    $obj = 'build_sweep_' + ([IO.Path]::GetFileNameWithoutExtension($tu.src)) + '.obj'
    Write-Output "CXX $($tu.src) -> $obj"
    $clOut = & cl @common '/c' $tu.src "/Fo:$obj" 2>&1
    $errs = $clOut | Select-String -Pattern ': error '
    if ($errs) {
        $errs | Select-Object -First 8 | ForEach-Object { Write-Output "  $_" }
        $failed = $true
    }
    if (Test-Path $obj) { $objs += $obj }
}

if ($failed) { Write-Output 'COMPILE_FAILED=1'; exit 1 }

# ---------------------------------------------------------------- link
Write-Output "LINK $($objs.Count) objects -> $Out"
$clOut = & cl @common $objs "/Fe:$Out" 2>&1
$errs = $clOut | Select-String -Pattern ': error |LNK\d{4}'
if ($errs) {
    $errs | Select-Object -First 10 | ForEach-Object { Write-Output "  $_" }
    Write-Output 'LINK_FAILED=1'
    exit 1
}

if (-not (Test-Path $Out)) { Write-Output 'LINK_PRODUCED_NO_BINARY=1'; exit 1 }

# Post-link sanity: the thing we were told to write must be a PE image, not text.
# If /Fe ever lands on a source path again, this catches it after the fact too.
$magic = [System.IO.File]::ReadAllBytes($Out)[0..1]
if (-not ($magic[0] -eq 0x4D -and $magic[1] -eq 0x5A)) {
    Write-Output "FAIL: '$Out' does not begin with 'MZ'; it is not a linked binary."
    exit 5
}

$fi = Get-Item $Out
Write-Output ("LINK_OK bytes={0} written={1:o} magic=MZ" -f $fi.Length, $fi.LastWriteTimeUtc)
Write-Output 'COMPILE_FAILED=0'
Write-Output 'LINK_FAILED=0'
exit 0
