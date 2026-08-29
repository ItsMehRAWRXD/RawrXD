<#
.SYNOPSIS
  HEXMAG_RUNTIME_CONTROLLER_001 — sequencing cert (no FINAL/W0/client edits).
  Fail-closed: exit!=0 or ^FAIL: ⇒ FAIL.
#>
param(
    [string]$Root = "",
    [string]$OutDir = "",
    [string]$EvidenceDir = ""
)
$ErrorActionPreference = "Stop"
if (-not $Root) { $Root = Split-Path -Parent $PSScriptRoot }
if (-not (Test-Path (Join-Path $Root "src\asm\RawrXD_HexMag_Swarm.asm"))) {
    $Root = (Get-Location).Path
}
if (-not $OutDir) { $OutDir = Join-Path $Root "build\hexmag_runtime_ctrl" }
if (-not $EvidenceDir) { $EvidenceDir = Join-Path $Root "evidence\HEXMAG_RUNTIME_CONTROLLER_001" }
New-Item -ItemType Directory -Force -Path $OutDir, $EvidenceDir | Out-Null

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$ml = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find "**/Hostx64/x64/ml64.exe" | Select-Object -First 1
$vcvars = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find "**/Auxiliary/Build/vcvars64.bat" | Select-Object -First 1
if (-not $ml -or -not $vcvars) { throw "ml64/vcvars not found" }

$obj = Join-Path $OutDir "RawrXD_HexMag_Swarm.obj"
$objTuner = Join-Path $OutDir "RawrXD_HexMag_RepeatTuner.obj"
$exe = Join-Path $OutDir "hexmag_runtime_controller_cert.exe"
$inc = Join-Path $Root "src"

Push-Location (Join-Path $Root "src\asm")
try {
    & $ml /c /nologo /Zi /Fo $obj "RawrXD_HexMag_Swarm.asm"
    if ($LASTEXITCODE -ne 0) { throw "ml64 swarm failed" }
    & $ml /c /nologo /Zi /Fo $objTuner "RawrXD_HexMag_RepeatTuner.asm"
    if ($LASTEXITCODE -ne 0) { throw "ml64 tuner failed" }
} finally { Pop-Location }

$srcs = @(
    (Join-Path $Root "tests\hexmag_runtime_controller_cert.cpp"),
    (Join-Path $Root "src\core\hexmag_runtime_controller.cpp"),
    (Join-Path $Root "src\agent\hexmag_client.cpp"),
    (Join-Path $Root "src\core\hexmag_control_plane.cpp"),
    (Join-Path $Root "src\core\hexmag_oracle_binder.cpp")
)

$bat = Join-Path $OutDir "build_cert.bat"
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
$gate = Join-Path $EvidenceDir "GATE.txt"
$failLine = $false
if (Test-Path $gate) {
    Get-Content $gate | ForEach-Object { Write-Host $_ }
}
# Re-scan last cert stdout isn't available; rely on exit code + GATE status
if ($code -ne 0) {
    Write-Host "HEXMAG_RUNTIME_CONTROLLER_001=FAIL exit=$code" -ForegroundColor Red
    exit $code
}
if ((Test-Path $gate) -and ((Get-Content $gate -Raw) -match 'status=FAIL')) {
    Write-Host "HEXMAG_RUNTIME_CONTROLLER_001=FAIL (GATE)" -ForegroundColor Red
    exit 1
}
Write-Host "HEXMAG_RUNTIME_CONTROLLER_001=PASS" -ForegroundColor Green
exit 0
