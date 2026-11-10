@echo off
setlocal EnableExtensions
set LOG=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\_followup_hostseed_stage_issue49.log
echo START %DATE% %TIME%> "%LOG%"

echo === KILL ===>> "%LOG%"
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >> "%LOG%" 2>&1
taskkill /F /IM RawrXD-Win32IDE-Native.exe >> "%LOG%" 2>&1
taskkill /F /IM deep2_agentic_loop.exe >> "%LOG%" 2>&1
taskkill /F /IM debuggee_fixture.exe >> "%LOG%" 2>&1
timeout /t 3 /nobreak >nul

echo === BUILD AgentCommands + Native-Ext ===>> "%LOG%"
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 >> "%LOG%" 2>&1
cd /d F:\rawrxd\build_tip_debug_rel
ninja -j1 "CMakeFiles/RawrXD-Win32IDE-Native-Ext.dir/src/win32app/Win32IDE_AgentCommands.cpp.obj" RawrXD-Win32IDE-Native-Ext >> "%LOG%" 2>&1
set NINJA_RC=%ERRORLEVEL%
echo NINJA_RC=%NINJA_RC%>> "%LOG%"
if not "%NINJA_RC%"=="0" (
  echo BUILD_FAIL>> "%LOG%"
  exit /b 1
)

set SRC=F:\rawrxd\build_tip_debug_rel\bin\RawrXD-Win32IDE-Native-Ext.exe
set TIP=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_011
set TIP_EXE=%TIP%\RawrXD-Win32IDE-Native-Ext.exe

echo === HASH SRC via certutil TEMP ===>> "%LOG%"
set TMPHASH=%TEMP%\tip011_src_sha.txt
certutil -hashfile "%SRC%" SHA256 > "%TMPHASH%"
type "%TMPHASH%" >> "%LOG%"
for /f "skip=1 tokens=1" %%H in ('certutil -hashfile "%SRC%" SHA256') do (
  set SHA=%%H
  goto :gotsha
)
:gotsha
echo SRC_SHA=%SHA%>> "%LOG%"

echo === STAGE copy ===>> "%LOG%"
copy /Y "%SRC%" "%TIP_EXE%" >> "%LOG%" 2>&1
if errorlevel 1 (
  echo COPY_FAIL>> "%LOG%"
  exit /b 2
)
copy /Y "F:\rawrxd\build_tip_debug_rel\bin\deep2_agentic_loop.exe" "%TIP%\deep2_agentic_loop.exe" >> "%LOG%" 2>&1

echo %SHA%> "%TIP%\SHA256.txt"
(
echo CANDIDATE=INTEG_011
echo EXE_SHA256=%SHA%
echo LINEAGE=host_seed_read_write_bugcpp_FORCE_LOCAL
echo PROMOTE=0
echo TIP_MOVE_AUTHORIZED=0
echo FROZEN_TIP_009_0946_UNTOUCHED=1
echo A4F_IMMUTABLE=1
) > "%TIP%\CANDIDATE.txt"

echo === PATCH ExpectSha ===>> "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$sha='%SHA%'.ToUpper(); $files=@('F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ011_remeasure.ps1','F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\run_issue49_tip011_exclusive.ps1'); foreach($f in $files){ (Get-Content -LiteralPath $f -Raw) -replace 'ExpectSha\s*=\s*\"[0-9A-Fa-f]{64}\"','ExpectSha = \"'+$sha+'\"' -replace \"\\$expect\s*=\s*'[0-9A-Fa-f]{64}'\",\"$expect = '$sha'\" | Set-Content -LiteralPath $f -NoNewline -Encoding UTF8 }" >> "%LOG%" 2>&1

echo === RESET bug.cpp fixture ===>> "%LOG%"
set BUG=F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\bug.cpp
(
echo /* Issue #49 product-final fixture: intentional compile bug for agent fix loop.
echo  * Do not pre-fix - agent ^(or measured blocker^) must own the repair.
echo  */
echo int undeclared_fn^(int a^);
echo.
echo int main^(^) {
echo   int x = undeclared_fn^(1, 2^); /* error: too many args + may need declaration fix */
echo   return x;
echo }
) > "%BUG%"

echo === ISSUE49 EXCLUSIVE ===>> "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -File "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\run_issue49_tip011_exclusive.ps1" >> "%LOG%" 2>&1
set I49_RC=%ERRORLEVEL%
echo ISSUE49_RC=%I49_RC%>> "%LOG%"

echo === FOUR PANEL ===>> "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -File "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\run_integ011_four_panel_exclusive.ps1" >> "%LOG%" 2>&1
set FP_RC=%ERRORLEVEL%
echo FOUR_PANEL_RC=%FP_RC%>> "%LOG%"

echo DONE NINJA_RC=%NINJA_RC% ISSUE49_RC=%I49_RC% FOUR_PANEL_RC=%FP_RC% SHA=%SHA%>> "%LOG%"
echo DONE
exit /b 0
