<#
.SYNOPSIS
  Three-transition runtime smoke for F HexMag IDE send path (no UI).
#>
param(
    [string]$Root = "F:\~dev\rawrxd",
    [string]$OutDir = "",
    [string]$EvidenceDir = ""
)
$ErrorActionPreference = "Stop"
if (-not $OutDir) { $OutDir = Join-Path $Root "build\hexmag_runtime_route_smoke" }
if (-not $EvidenceDir) { $EvidenceDir = Join-Path $Root "evidence\HEXMAG_RUNTIME_ROUTE_SMOKE" }
New-Item -ItemType Directory -Force -Path $OutDir, $EvidenceDir | Out-Null

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$ml = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find "**/Hostx64/x64/ml64.exe" | Select-Object -First 1
$vcvars = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find "**/Auxiliary/Build/vcvars64.bat" | Select-Object -First 1
if (-not $ml -or -not $vcvars) { throw "ml64/vcvars not found" }

$obj = Join-Path $OutDir "RawrXD_HexMag_Swarm.obj"
$objTuner = Join-Path $OutDir "RawrXD_HexMag_RepeatTuner.obj"
$exe = Join-Path $OutDir "hexmag_runtime_route_smoke.exe"

Push-Location (Join-Path $Root "src\asm")
try {
    & $ml /c /nologo /Zi /Fo $obj "RawrXD_HexMag_Swarm.asm"
    if ($LASTEXITCODE -ne 0) { throw "ml64 swarm failed" }
    & $ml /c /nologo /Zi /Fo $objTuner "RawrXD_HexMag_RepeatTuner.asm"
    if ($LASTEXITCODE -ne 0) { throw "ml64 tuner failed" }
} finally { Pop-Location }

$inc = Join-Path $Root "src"
$srcs = @(
    (Join-Path $Root "tests\hexmag_runtime_route_smoke.cpp"),
    (Join-Path $Root "src\agent\hexmag_client.cpp"),
    (Join-Path $Root "src\core\hexmag_control_plane.cpp"),
    (Join-Path $Root "src\core\hexmag_oracle_binder.cpp"),
    (Join-Path $Root "src\core\hexmag_runtime_controller.cpp")
)

$bat = Join-Path $OutDir "build_smoke.bat"
@"
@echo off
call "$vcvars" >nul
cd /d "$OutDir"
cl /nologo /EHsc /O2 /std:c++20 /DRAWR_HAS_MASM /I "$inc" $($srcs -join ' ') /Fe:"$exe" /link /nologo "$obj" "$objTuner" kernel32.lib
if errorlevel 1 exit /b 1
"$exe" "$EvidenceDir"
exit /b %ERRORLEVEL%
"@ | Set-Content -Path $bat -Encoding ASCII

cmd /c "`"$bat`""
$code = $LASTEXITCODE
Write-Host "exit=$code evidence=$EvidenceDir"
if (Test-Path (Join-Path $EvidenceDir "GATE.txt")) {
    Get-Content (Join-Path $EvidenceDir "GATE.txt")
}
exit $code
