<#
.SYNOPSIS
  HexMag MASM smoke + NEED_INPUT + Oracle binder + W0-001 (weightless prototype).
  Keep-it-simple critical path: IR → workspace → intent → synth → evidence → HexMag gates.
#>
param([string]$OutDir = "")
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $Root "src\asm\RawrXD_HexMag_Swarm.asm"))) {
    $Root = (Get-Location).Path
}
if (-not $OutDir) { $OutDir = Join-Path $Root "build\hexmag_masm" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$ml = $null; $vcvars = $null
if (Test-Path $vswhere) {
    $ml = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -find "**/Hostx64/x64/ml64.exe" 2>$null | Select-Object -First 1
    $vcvars = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -find "**/Auxiliary/Build/vcvars64.bat" 2>$null | Select-Object -First 1
}
if (-not $ml) {
    $ml = Get-ChildItem "C:\Program Files*\Microsoft Visual Studio" -Recurse -Filter ml64.exe -EA SilentlyContinue |
        Where-Object { $_.FullName -match 'Hostx64\\x64\\ml64\.exe$' } |
        Select-Object -First 1 -ExpandProperty FullName
}
if (-not $vcvars) {
    $vcvars = Get-ChildItem "C:\Program Files*\Microsoft Visual Studio" -Recurse -Filter vcvars64.bat -EA SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
}
if (-not $ml -or -not $vcvars) { Write-Error "ml64/vcvars not found" }

$obj = Join-Path $OutDir "RawrXD_HexMag_Swarm.obj"
$objTuner = Join-Path $OutDir "RawrXD_HexMag_RepeatTuner.obj"
$exeUnit = Join-Path $OutDir "hexmag_swarm_smoke.exe"
$exeE2E = Join-Path $OutDir "hexmag_e2e_smoke.exe"
$exeCert = Join-Path $OutDir "hexmag_repeat_tuner_cert.exe"
$exeNeed = Join-Path $OutDir "hexmag_need_input_cert.exe"
$exeBind = Join-Path $OutDir "hexmag_oracle_binder_cert.exe"
$exeW0 = Join-Path $OutDir "w0_001_cert.exe"
$cppUnit = Join-Path $Root "tests\hexmag_swarm_smoke.cpp"
$cppE2E = Join-Path $Root "tests\hexmag_e2e_smoke.cpp"
$cppCert = Join-Path $Root "tests\hexmag_repeat_tuner_cert.cpp"
$cppNeed = Join-Path $Root "tests\hexmag_need_input_cert.cpp"
$cppBind = Join-Path $Root "tests\hexmag_oracle_binder_cert.cpp"
$cppW0 = Join-Path $Root "tests\w0_001_cert.cpp"
$cpCpp = Join-Path $Root "src\core\hexmag_control_plane.cpp"
$obCpp = Join-Path $Root "src\core\hexmag_oracle_binder.cpp"
$w0Cpp = Join-Path $Root "src\deep2w0\W0Engine.cpp"
$inc = Join-Path $Root "src"
$incAgentic = Join-Path $Root "src\agentic"
$fixW0 = Join-Path $Root "tests\fixtures\w0_001"

Push-Location (Join-Path $Root "src\asm")
try {
    & $ml /c /nologo /Zi /Fo $obj "RawrXD_HexMag_Swarm.asm"
    if ($LASTEXITCODE -ne 0) { throw "ml64 swarm failed" }
    & $ml /c /nologo /Zi /Fo $objTuner "RawrXD_HexMag_RepeatTuner.asm"
    if ($LASTEXITCODE -ne 0) { throw "ml64 tuner failed" }
} finally { Pop-Location }

$cmd = @"
call "$vcvars" >nul
cd /d "$OutDir"

echo === 1/6 unit swarm smoke ===
cl /nologo /EHsc /O2 /DRAWR_HAS_MASM /I "$inc" "$cppUnit" /Fe:"$exeUnit" /link /nologo "$obj" "$objTuner" kernel32.lib
if errorlevel 1 exit /b 1
"$exeUnit"
if errorlevel 1 exit /b 1

echo === 2/6 E2E policy+control plane ===
cl /nologo /EHsc /O2 /std:c++20 /DRAWR_HAS_MASM /I "$inc" "$cppE2E" "$cpCpp" "$obCpp" /Fe:"$exeE2E" /link /nologo "$obj" "$objTuner" kernel32.lib
if errorlevel 1 exit /b 1
"$exeE2E"
if errorlevel 1 exit /b 1

echo === 3/6 repeat tuner cert ===
cl /nologo /EHsc /O2 /std:c++20 /DRAWR_HAS_MASM /I "$incAgentic" /I "$inc" "$cppCert" /Fe:"$exeCert" /link /nologo "$objTuner" kernel32.lib
if errorlevel 1 exit /b 1
"$exeCert"
if errorlevel 1 exit /b 1

echo === 4/6 NEED_INPUT cert ===
cl /nologo /EHsc /O2 /std:c++20 /DRAWR_HAS_MASM /I "$inc" "$cppNeed" "$cpCpp" "$obCpp" /Fe:"$exeNeed" /link /nologo "$obj" "$objTuner" kernel32.lib
if errorlevel 1 exit /b 1
"$exeNeed"
if errorlevel 1 exit /b 1

echo === 5/6 Oracle binder cert ===
cl /nologo /EHsc /O2 /std:c++20 /DRAWR_HAS_MASM /I "$inc" "$cppBind" "$cpCpp" "$obCpp" /Fe:"$exeBind" /link /nologo "$obj" "$objTuner" kernel32.lib
if errorlevel 1 exit /b 1
"$exeBind"
if errorlevel 1 exit /b 1

echo === 6/6 W0-001 weightless prototype ===
cl /nologo /EHsc /O2 /std:c++20 /I "$inc" "$cppW0" "$w0Cpp" "$obCpp" /Fe:"$exeW0" /link /nologo kernel32.lib
if errorlevel 1 exit /b 1
"$exeW0" "$fixW0"
if errorlevel 1 exit /b 1

exit /b 0
"@
$bat = Join-Path $OutDir "_e2e_cert.cmd"
Set-Content -Path $bat -Value $cmd -Encoding ASCII
cmd /c $bat
$code = $LASTEXITCODE
if ($code -eq 0) { Write-Host "`nSmoke-HexMagMasm ALL: PASS" -ForegroundColor Green }
else { Write-Host "`nSmoke-HexMagMasm ALL: FAIL ($code)" -ForegroundColor Red }
exit $code
