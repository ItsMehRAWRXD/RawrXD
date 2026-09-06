<#
.SYNOPSIS
  HexMag MASM smoke suite (7 steps).
  Fail-closed: COMPILE_FAIL / CERT_FAIL / child exit!=0 / FAIL: lines ⇒ ALL FAIL.
  Later PASS steps never clear an earlier failure.
#>
param([string]$OutDir = "")
$ErrorActionPreference = "Continue"
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
if (-not $ml -or -not $vcvars) { Write-Error "ml64/vcvars not found"; exit 1 }

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
    if ($LASTEXITCODE -ne 0) { Write-Host "COMPILE_FAIL: ml64 swarm"; exit 1 }
    & $ml /c /nologo /Zi /Fo $objTuner "RawrXD_HexMag_RepeatTuner.asm"
    if ($LASTEXITCODE -ne 0) { Write-Host "COMPILE_FAIL: ml64 tuner"; exit 1 }
} finally { Pop-Location }

$script:suiteFailed = $false

function Test-StepFailure {
    param(
        [int]$ExitCode,
        [string[]]$Output
    )
    $text = ($Output -join "`n")
    return (
        $ExitCode -ne 0 -or
        $text -match '(?m)^(FAIL:|COMPILE_FAIL:|CERT_FAIL:)'
    )
}

function Invoke-CertStep {
    param(
        [string]$Name,
        [string]$CompileCmd,
        [string]$RunExe,
        [string[]]$RunArgs = @()
    )
    Write-Host "=== $Name ==="

    $compileOut = @()
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $compileOut = cmd /c "`"$vcvars`" >nul && $CompileCmd" 2>&1 | ForEach-Object { "$_" }
    } finally {
        $ErrorActionPreference = $prevEap
    }
    $compileCode = $LASTEXITCODE
    # Always show compiler output on failure (was previously swallowed).
    if ($compileCode -ne 0) {
        $compileOut | ForEach-Object { Write-Host $_ }
        Write-Host "COMPILE_FAIL: $Name" -ForegroundColor Red
        $script:suiteFailed = $true
        return
    }

    $ErrorActionPreference = "Continue"
    $out = @()
    try {
        $out = & $RunExe @RunArgs 2>&1 | ForEach-Object { "$_" }
    } finally {
        $ErrorActionPreference = $prevEap
    }
    $code = $LASTEXITCODE
    $out | ForEach-Object { Write-Host $_ }

    if (Test-StepFailure -ExitCode $code -Output $out) {
        Write-Host "CERT_FAIL: $Name exit=$code" -ForegroundColor Red
        $script:suiteFailed = $true
        return
    }
}

$exeUnit = Join-Path $OutDir "hexmag_swarm_smoke.exe"
Invoke-CertStep -Name "1/7 unit swarm" `
    -CompileCmd "cl /nologo /EHsc /O2 /DRAWR_HAS_MASM /I `"$inc`" `"$(Join-Path $Root 'tests\hexmag_swarm_smoke.cpp')`" /Fe:`"$exeUnit`" /link /nologo `"$obj`" `"$objTuner`" kernel32.lib" `
    -RunExe $exeUnit

$rcCpp = Join-Path $Root "src\core\hexmag_runtime_controller.cpp"
$clCpp = Join-Path $Root "src\agent\hexmag_client.cpp"

$exeE2E = Join-Path $OutDir "hexmag_e2e_smoke.exe"
# E2E includes AgentRuntimeController → ide_send_path → controller + client (link seam).
Invoke-CertStep -Name "2/7 E2E" `
    -CompileCmd "cl /nologo /EHsc /O2 /std:c++20 /DRAWR_HAS_MASM /I `"$inc`" `"$(Join-Path $Root 'tests\hexmag_e2e_smoke.cpp')`" `"$cpCpp`" `"$obCpp`" `"$rcCpp`" `"$clCpp`" /Fe:`"$exeE2E`" /link /nologo `"$obj`" `"$objTuner`" kernel32.lib" `
    -RunExe $exeE2E

$exeCert = Join-Path $OutDir "hexmag_repeat_tuner_cert.exe"
Invoke-CertStep -Name "3/7 repeat tuner" `
    -CompileCmd "cl /nologo /EHsc /O2 /std:c++20 /DRAWR_HAS_MASM /I `"$incAgentic`" /I `"$inc`" `"$(Join-Path $Root 'tests\hexmag_repeat_tuner_cert.cpp')`" /Fe:`"$exeCert`" /link /nologo `"$objTuner`" kernel32.lib" `
    -RunExe $exeCert

$exeNeed = Join-Path $OutDir "hexmag_need_input_cert.exe"
Invoke-CertStep -Name "4/7 NEED_INPUT" `
    -CompileCmd "cl /nologo /EHsc /O2 /std:c++20 /DRAWR_HAS_MASM /I `"$inc`" `"$(Join-Path $Root 'tests\hexmag_need_input_cert.cpp')`" `"$cpCpp`" `"$obCpp`" /Fe:`"$exeNeed`" /link /nologo `"$obj`" `"$objTuner`" kernel32.lib" `
    -RunExe $exeNeed

$exeBind = Join-Path $OutDir "hexmag_oracle_binder_cert.exe"
Invoke-CertStep -Name "5/7 Oracle binder" `
    -CompileCmd "cl /nologo /EHsc /O2 /std:c++20 /DRAWR_HAS_MASM /I `"$inc`" `"$(Join-Path $Root 'tests\hexmag_oracle_binder_cert.cpp')`" `"$cpCpp`" `"$obCpp`" /Fe:`"$exeBind`" /link /nologo `"$obj`" `"$objTuner`" kernel32.lib" `
    -RunExe $exeBind

$exeW0 = Join-Path $OutDir "w0_001_cert.exe"
Invoke-CertStep -Name "6/7 W0-001" `
    -CompileCmd "cl /nologo /EHsc /O2 /std:c++20 /I `"$inc`" `"$(Join-Path $Root 'tests\w0_001_cert.cpp')`" `"$w0Cpp`" `"$obCpp`" /Fe:`"$exeW0`" /link /nologo kernel32.lib" `
    -RunExe $exeW0 -RunArgs @($fixW0)

$exeCtrl = Join-Path $OutDir "hexmag_runtime_controller_cert.exe"
$evCtrl = Join-Path $Root "evidence\HEXMAG_RUNTIME_CONTROLLER_001"
New-Item -ItemType Directory -Force -Path $evCtrl | Out-Null
Invoke-CertStep -Name "7/7 Runtime controller" `
    -CompileCmd "cl /nologo /EHsc /O2 /std:c++20 /DRAWR_HAS_MASM /I `"$inc`" `"$(Join-Path $Root 'tests\hexmag_runtime_controller_cert.cpp')`" `"$rcCpp`" `"$clCpp`" `"$cpCpp`" `"$obCpp`" /Fe:`"$exeCtrl`" /link /nologo `"$obj`" `"$objTuner`" kernel32.lib" `
    -RunExe $exeCtrl -RunArgs @($evCtrl)

if ($script:suiteFailed) {
    Write-Host ""
    Write-Host "Smoke-HexMagMasm ALL: FAIL"
    exit 1
}

Write-Host ""
Write-Host "Smoke-HexMagMasm ALL: PASS"
exit 0
