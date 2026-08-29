<#
.SYNOPSIS
  Assemble, link, and run the HexMag MASM control-plane smoke (no Python).
#>
param(
    [string]$OutDir = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $Root "src\asm\RawrXD_HexMag_Swarm.asm"))) {
    $Root = (Get-Location).Path
}

if (-not $OutDir) {
    $OutDir = Join-Path $Root "build\hexmag_masm"
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$ml = $null
$vcvars = $null
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
if (-not $ml -or -not $vcvars) {
    Write-Error "ml64.exe / vcvars64.bat not found. Install VS Build Tools with MSVC x64."
}

Write-Host "ml64:   $ml"
Write-Host "vcvars: $vcvars"
Write-Host "outdir: $OutDir"

$asm = Join-Path $Root "src\asm\RawrXD_HexMag_Swarm.asm"
$asmTuner = Join-Path $Root "src\asm\RawrXD_HexMag_RepeatTuner.asm"
$obj = Join-Path $OutDir "RawrXD_HexMag_Swarm.obj"
$objTuner = Join-Path $OutDir "RawrXD_HexMag_RepeatTuner.obj"
$exe = Join-Path $OutDir "hexmag_swarm_smoke.exe"
$cpp = Join-Path $Root "tests\hexmag_swarm_smoke.cpp"
$inc = Join-Path $Root "src"

Push-Location (Join-Path $Root "src\asm")
try {
    & $ml /c /nologo /Zi /Fo $obj "RawrXD_HexMag_Swarm.asm"
    if ($LASTEXITCODE -ne 0) { throw "ml64 swarm failed: $LASTEXITCODE" }
    & $ml /c /nologo /Zi /Fo $objTuner "RawrXD_HexMag_RepeatTuner.asm"
    if ($LASTEXITCODE -ne 0) { throw "ml64 tuner failed: $LASTEXITCODE" }
} finally {
    Pop-Location
}
Write-Host "OBJ: $obj ($((Get-Item $obj).Length) bytes)"
Write-Host "OBJ: $objTuner ($((Get-Item $objTuner).Length) bytes)"

$cmd = @"
call "$vcvars" >nul
cd /d "$OutDir"
cl /nologo /EHsc /O2 /DRAWR_HAS_MASM /I "$inc" "$cpp" /Fe:"$exe" /link /nologo "$obj" "$objTuner" kernel32.lib
if errorlevel 1 exit /b 1
"$exe"
exit /b %ERRORLEVEL%
"@

$bat = Join-Path $OutDir "_smoke.cmd"
Set-Content -Path $bat -Value $cmd -Encoding ASCII
cmd /c $bat
$code = $LASTEXITCODE
if ($code -eq 0) {
    Write-Host "`nSmoke-HexMagMasm: PASS" -ForegroundColor Green
} else {
    Write-Host "`nSmoke-HexMagMasm: FAIL ($code)" -ForegroundColor Red
}
exit $code
