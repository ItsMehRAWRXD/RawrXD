<#
.SYNOPSIS
  HexMag MASM smoke + NEED_INPUT + Oracle binder + W0-001.
  Fail-closed: nonzero exit OR any stderr/stdout line matching ^FAIL: ⇒ ALL FAIL.
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
$inc = Join-Path $Root "src"
$incAgentic = Join-Path $Root "src\agentic"
$cpCpp = Join-Path $Root "src\core\hexmag_control_plane.cpp"
$obCpp = Join-Path $Root "src\core\hexmag_oracle_binder.cpp"
$w0Cpp = Join-Path $Root "src\deep2w0\W0Engine.cpp"
$fixW0 = Join-Path $Root "tests\fixtures\w0_001"

Push-Location (Join-Path $Root "src\asm")
try {
    & $ml /c /nologo /Zi /Fo $obj "RawrXD_HexMag_Swarm.asm"
    if ($LASTEXITCODE -ne 0) { throw "ml64 swarm failed" }
    & $ml /c /nologo /Zi /Fo $objTuner "RawrXD_HexMag_RepeatTuner.asm"
    if ($LASTEXITCODE -ne 0) { throw "ml64 tuner failed" }
} finally { Pop-Location }

function Invoke-CertStep {
    param(
        [string]$Name,
        [string]$CompileCmd,
        [string]$RunExe,
        [string[]]$RunArgs = @()
    )
    Write-Host "=== $Name ==="
    cmd /c "`"$vcvars`" >nul && $CompileCmd"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "COMPILE_FAIL: $Name" -ForegroundColor Red
        return $false
    }
    # Capture stdout+stderr without treating stderr writes as terminating errors
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $out = @()
    try {
        $out = & $RunExe @RunArgs 2>&1 | ForEach-Object { "$_" }
    } finally {
        $ErrorActionPreference = $prevEap
    }
    $code = $LASTEXITCODE
    $out | ForEach-Object { Write-Host $_ }
    $hasFailLine = $false
    foreach ($line in $out) {
        if ($line -match '(?m)^FAIL:') { $hasFailLine = $true; break }
    }
    if ($code -ne 0 -or $hasFailLine) {
        Write-Host "CERT_FAIL: $Name exit=$code fail_line=$hasFailLine" -ForegroundColor Red
        return $false
    }
    return $true
}

$allPass = $true

$exeUnit = Join-Path $OutDir "hexmag_swarm_smoke.exe"
$allPass = (Invoke-CertStep -Name "1/6 unit swarm" `
    -CompileCmd "cl /nologo /EHsc /O2 /DRAWR_HAS_MASM /I `"$inc`" `"$(Join-Path $Root 'tests\hexmag_swarm_smoke.cpp')`" /Fe:`"$exeUnit`" /link /nologo `"$obj`" `"$objTuner`" kernel32.lib" `
    -RunExe $exeUnit) -and $allPass

$exeE2E = Join-Path $OutDir "hexmag_e2e_smoke.exe"
$allPass = (Invoke-CertStep -Name "2/6 E2E" `
    -CompileCmd "cl /nologo /EHsc /O2 /std:c++20 /DRAWR_HAS_MASM /I `"$inc`" `"$(Join-Path $Root 'tests\hexmag_e2e_smoke.cpp')`" `"$cpCpp`" `"$obCpp`" /Fe:`"$exeE2E`" /link /nologo `"$obj`" `"$objTuner`" kernel32.lib" `
    -RunExe $exeE2E) -and $allPass

$exeCert = Join-Path $OutDir "hexmag_repeat_tuner_cert.exe"
$allPass = (Invoke-CertStep -Name "3/6 repeat tuner" `
    -CompileCmd "cl /nologo /EHsc /O2 /std:c++20 /DRAWR_HAS_MASM /I `"$incAgentic`" /I `"$inc`" `"$(Join-Path $Root 'tests\hexmag_repeat_tuner_cert.cpp')`" /Fe:`"$exeCert`" /link /nologo `"$objTuner`" kernel32.lib" `
    -RunExe $exeCert) -and $allPass

$exeNeed = Join-Path $OutDir "hexmag_need_input_cert.exe"
$allPass = (Invoke-CertStep -Name "4/6 NEED_INPUT" `
    -CompileCmd "cl /nologo /EHsc /O2 /std:c++20 /DRAWR_HAS_MASM /I `"$inc`" `"$(Join-Path $Root 'tests\hexmag_need_input_cert.cpp')`" `"$cpCpp`" `"$obCpp`" /Fe:`"$exeNeed`" /link /nologo `"$obj`" `"$objTuner`" kernel32.lib" `
    -RunExe $exeNeed) -and $allPass

$exeBind = Join-Path $OutDir "hexmag_oracle_binder_cert.exe"
$allPass = (Invoke-CertStep -Name "5/6 Oracle binder" `
    -CompileCmd "cl /nologo /EHsc /O2 /std:c++20 /DRAWR_HAS_MASM /I `"$inc`" `"$(Join-Path $Root 'tests\hexmag_oracle_binder_cert.cpp')`" `"$cpCpp`" `"$obCpp`" /Fe:`"$exeBind`" /link /nologo `"$obj`" `"$objTuner`" kernel32.lib" `
    -RunExe $exeBind) -and $allPass

$exeW0 = Join-Path $OutDir "w0_001_cert.exe"
$allPass = (Invoke-CertStep -Name "6/6 W0-001" `
    -CompileCmd "cl /nologo /EHsc /O2 /std:c++20 /I `"$inc`" `"$(Join-Path $Root 'tests\w0_001_cert.cpp')`" `"$w0Cpp`" `"$obCpp`" /Fe:`"$exeW0`" /link /nologo kernel32.lib" `
    -RunExe $exeW0 -RunArgs @($fixW0)) -and $allPass

if (-not $allPass) {
    Write-Host "`nSmoke-HexMagMasm ALL: FAIL" -ForegroundColor Red
    exit 1
}
Write-Host "`nSmoke-HexMagMasm ALL: PASS" -ForegroundColor Green
exit 0
