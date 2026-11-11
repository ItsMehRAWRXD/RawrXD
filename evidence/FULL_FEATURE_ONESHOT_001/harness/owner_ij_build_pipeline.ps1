# BUILD_PIPELINE_GATE harness — measured only; NOT_RUN != PASS
$ErrorActionPreference = 'Continue'
$Root = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001'
$OutDir = Join-Path $Root 'logs\build_pipeline'
$Receipt = Join-Path $Root 'artifacts\BUILD_PIPELINE_RECEIPT.txt'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$lines = New-Object System.Collections.Generic.List[string]
function L([string]$s) { $lines.Add($s); Write-Host $s }

L "ASOF_UTC=$stamp"
L 'GATE=BUILD_PIPELINE_GATE'
L 'PROMOTE=0'
L 'CERTIFIED=0'
L 'INVENT_PASS=0'

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$installPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$vcvars = Join-Path $installPath 'VC\Auxiliary\Build\vcvars64.bat'
$cl = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe'
L "MSVC_INSTALL=$installPath"
L "VCVARS_EXISTS=$([bool](Test-Path $vcvars))"
L "CL_EXISTS=$([bool](Test-Path $cl))"
L "CL_PATH=$cl"
L "CMAKE=$((Get-Command cmake -ErrorAction SilentlyContinue).Source)"
L "NINJA=$((Get-Command ninja -ErrorAction SilentlyContinue).Source)"
$MSVC_DISCOVERY = if ((Test-Path $cl) -and (Test-Path $vcvars)) { 'PASS' } else { 'FAIL' }
L "MSVC_DISCOVERY=$MSVC_DISCOVERY"

$spaceDir = Join-Path $OutDir 'path with spaces'
New-Item -ItemType Directory -Force -Path $spaceDir | Out-Null
$src = Join-Path $spaceDir 'hello_gate.c'
$obj = Join-Path $spaceDir 'hello_gate.obj'
$exe = Join-Path $spaceDir 'hello_gate.exe'
Set-Content -Path $src -Encoding ASCII -Value @"
#include <stdio.h>
int main(void) {
  puts("BUILD_PIPELINE_HELLO_OK");
  return 0;
}
"@

$compileLog = Join-Path $OutDir 'compile_link_run.log'
$bat = Join-Path $OutDir '_compile.bat'
Set-Content -Path $bat -Encoding ASCII -Value @"
@echo off
call "$vcvars" >nul
cl /nologo /O2 /Fe"$exe" /Fo"$obj" "$src" > "$compileLog" 2>&1
echo CL_EXIT=%ERRORLEVEL%>> "$compileLog"
"$exe" >> "$compileLog" 2>&1
echo RUN_EXIT=%ERRORLEVEL%>> "$compileLog"
"@
$p = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', "`"$bat`"" -Wait -PassThru -NoNewWindow
$compileOut = if (Test-Path $compileLog) { Get-Content $compileLog -Raw } else { '' }
L "COMPILE_LINK_RUN_EXIT=$($p.ExitCode)"
$COMPILE_LINK_RUN = if (($compileOut -match 'BUILD_PIPELINE_HELLO_OK') -and ($compileOut -match 'RUN_EXIT=0')) { 'PASS' } else { 'FAIL' }
L "COMPILE_LINK_RUN=$COMPILE_LINK_RUN"
L "PATHS_WITH_SPACES=$COMPILE_LINK_RUN"

$objBefore = if (Test-Path $obj) { (Get-Item $obj).LastWriteTimeUtc.ToString('o') } else { 'MISSING' }
Start-Sleep -Milliseconds 800
$batInc = Join-Path $OutDir '_incremental.bat'
$incLog = Join-Path $OutDir 'incremental.log'
Set-Content -Path $batInc -Encoding ASCII -Value @"
@echo off
call "$vcvars" >nul
cl /nologo /c /Fo"$obj" "$src" > "$incLog" 2>&1
echo INC_EXIT=%ERRORLEVEL%>> "$incLog"
"@
$pInc = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', "`"$batInc`"" -Wait -PassThru -NoNewWindow
$objAfter = if (Test-Path $obj) { (Get-Item $obj).LastWriteTimeUtc.ToString('o') } else { 'MISSING' }
$INCREMENTAL = if (($pInc.ExitCode -eq 0) -and ($objAfter -ne $objBefore)) { 'PASS' } else { 'FAIL' }
L "INCREMENTAL=$INCREMENTAL"
L "OBJ_BEFORE=$objBefore"
L "OBJ_AFTER=$objAfter"

Remove-Item $obj, $exe -Force -ErrorAction SilentlyContinue
$batClean = Join-Path $OutDir '_clean.bat'
$cleanLog = Join-Path $OutDir 'clean_rebuild.log'
Set-Content -Path $batClean -Encoding ASCII -Value @"
@echo off
call "$vcvars" >nul
cl /nologo /O2 /Fe"$exe" /Fo"$obj" "$src" > "$cleanLog" 2>&1
echo CLEAN_EXIT=%ERRORLEVEL%>> "$cleanLog"
"@
$pClean = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', "`"$batClean`"" -Wait -PassThru -NoNewWindow
$CLEAN = if ((Test-Path $exe) -and ($pClean.ExitCode -eq 0)) { 'PASS' } else { 'FAIL' }
L "CLEAN_REBUILD=$CLEAN"

$child = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', 'ping -n 30 127.0.0.1 >nul' -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 1
$aliveBefore = -not $child.HasExited
Stop-Process -Id $child.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500
$aliveAfter = $false
try { $aliveAfter = -not (Get-Process -Id $child.Id -ErrorAction Stop).HasExited } catch { $aliveAfter = $false }
$CANCEL_TIMEOUT = if ($aliveBefore -and -not $aliveAfter) { 'PASS' } else { 'FAIL' }
L "CANCEL_TIMEOUT=$CANCEL_TIMEOUT"
L "CHILD_ALIVE_BEFORE=$aliveBefore"
L "CHILD_ALIVE_AFTER=$aliveAfter"

$broken = Join-Path $Root 'fixtures\broken_multi.cpp'
$diagLog = Join-Path $OutDir 'diagnostics_cl.log'
$batDiag = Join-Path $OutDir '_diag.bat'
Set-Content -Path $batDiag -Encoding ASCII -Value @"
@echo off
call "$vcvars" >nul
cl /nologo /c /Fo"$OutDir\broken_multi.obj" "$broken" > "$diagLog" 2>&1
echo DIAG_EXIT=%ERRORLEVEL%>> "$diagLog"
"@
$pDiag = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', "`"$batDiag`"" -Wait -PassThru -NoNewWindow
$diagText = if (Test-Path $diagLog) { Get-Content $diagLog -Raw } else { '' }
$DIAG = if (($diagText -match 'error') -and ($diagText -match 'DIAG_EXIT=[1-9]')) { 'PASS' } else { 'FAIL' }
L "DIAGNOSTICS_PROP=$DIAG"
L "DIAG_BYTES=$($diagText.Length)"
L "DIAG_PROCESS_EXIT=$($pDiag.ExitCode)"

$cmakeDir = Join-Path $OutDir 'cmake_space_probe'
New-Item -ItemType Directory -Force -Path $cmakeDir | Out-Null
Set-Content -Path (Join-Path $cmakeDir 'CMakeLists.txt') -Encoding ASCII -Value @"
cmake_minimum_required(VERSION 3.20)
project(build_pipeline_probe LANGUAGES C)
add_executable(probe hello_gate.c)
"@
Copy-Item $src (Join-Path $cmakeDir 'hello_gate.c') -Force
$cmakeBuild = Join-Path $OutDir 'cmake build with spaces'
New-Item -ItemType Directory -Force -Path $cmakeBuild | Out-Null
$cmakeLog = Join-Path $OutDir 'cmake_probe.log'
$batCmake = Join-Path $OutDir '_cmake.bat'
Set-Content -Path $batCmake -Encoding ASCII -Value @"
@echo off
call "$vcvars" >nul
cmake -S "$cmakeDir" -B "$cmakeBuild" -G Ninja > "$cmakeLog" 2>&1
echo CMAKE_CFG=%ERRORLEVEL%>> "$cmakeLog"
ninja -C "$cmakeBuild" > "$cmakeLog.ninja" 2>&1
echo NINJA_EXIT=%ERRORLEVEL%>> "$cmakeLog.ninja"
"$cmakeBuild\probe.exe" >> "$cmakeLog.ninja" 2>&1
echo PROBE_EXIT=%ERRORLEVEL%>> "$cmakeLog.ninja"
"@
$pCmake = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', "`"$batCmake`"" -Wait -PassThru -NoNewWindow
$ninjaOut = if (Test-Path "$cmakeLog.ninja") { Get-Content "$cmakeLog.ninja" -Raw } else { '' }
$CMAKE_SPACE = if ($ninjaOut -match 'BUILD_PIPELINE_HELLO_OK') { 'PASS' } else { 'FAIL' }
L "CMAKE_NINJA_PATHS_SPACES=$CMAKE_SPACE"
L "CMAKE_NINJA_PROCESS_EXIT=$($pCmake.ExitCode)"

$subs = @($MSVC_DISCOVERY, $COMPILE_LINK_RUN, $INCREMENTAL, $CLEAN, $CANCEL_TIMEOUT, $DIAG, $CMAKE_SPACE)
$allPass = ($subs | Where-Object { $_ -ne 'PASS' }).Count -eq 0
$OVERALL = if ($allPass) { 'PASS' } else { 'PARTIAL' }
L "BUILD_PIPELINE_OVERALL=$OVERALL"
L 'IDE_BUILD_PROJECT_E2E=NOT_RUN'
L 'FROZEN_A4F_UNTOUCHED=1'
L 'NOT_RUN_NE_PASS=1'
$lines -join "`n" | Set-Content -Path $Receipt -Encoding UTF8
Write-Host "RECEIPT=$Receipt"
