@echo off
setlocal EnableExtensions
set LOG=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\_stage_tip011_hostseed.log
echo START %DATE% %TIME%> "%LOG%"

set SRC=F:\rawrxd\build_tip_debug_rel\bin\RawrXD-Win32IDE-Native-Ext.exe
set TIP=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_011
set TIP_EXE=%TIP%\RawrXD-Win32IDE-Native-Ext.exe
set ART=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts

if not exist "%TIP%" mkdir "%TIP%"

taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >> "%LOG%" 2>&1
taskkill /F /IM deep2_agentic_loop.exe >> "%LOG%" 2>&1
timeout /t 2 /nobreak >nul

echo === STRINGS ===>> "%LOG%"
findstr /C:HOST_SEED_TOOL_CALL /C:FORCE_LOCAL_HOST_WRITE /C:HOST_SEED_FORCE_LOCAL "%SRC%" >nul
if errorlevel 1 (
  echo STRINGS_MISS>> "%LOG%"
) else (
  echo STRINGS_HIT=1>> "%LOG%"
)

set TMPHASH=%TEMP%\tip011_src_sha.txt
certutil -hashfile "%SRC%" SHA256 > "%TMPHASH%"
type "%TMPHASH%" >> "%LOG%"
for /f "skip=1 tokens=1" %%H in ('certutil -hashfile "%SRC%" SHA256') do (
  set SHA=%%H
  goto :gotsha
)
:gotsha
call :toupper SHA
echo SRC_SHA=%SHA%>> "%LOG%"

copy /Y "%SRC%" "%TIP_EXE%" >> "%LOG%" 2>&1
if errorlevel 1 (
  echo COPY_FAIL>> "%LOG%"
  exit /b 2
)
if exist "F:\rawrxd\build_tip_debug_rel\bin\deep2_agentic_loop.exe" (
  copy /Y "F:\rawrxd\build_tip_debug_rel\bin\deep2_agentic_loop.exe" "%TIP%\deep2_agentic_loop.exe" >> "%LOG%" 2>&1
)

set TMPHASH2=%TEMP%\tip011_tip_sha.txt
certutil -hashfile "%TIP_EXE%" SHA256 > "%TMPHASH2%"
type "%TMPHASH2%" >> "%LOG%"
for /f "skip=1 tokens=1" %%H in ('certutil -hashfile "%TIP_EXE%" SHA256') do (
  set TIPSHA=%%H
  goto :gottip
)
:gottip
call :toupper TIPSHA
echo TIP_SHA=%TIPSHA%>> "%LOG%"

echo %TIPSHA%> "%TIP%\SHA256.txt"
(
echo CANDIDATE=INTEG_011
echo EXE_SHA256=%TIPSHA%
echo LINEAGE=host_seed_read_write_bugcpp_FORCE_LOCAL
echo PROMOTE=0
echo TIP_MOVE_AUTHORIZED=0
echo FROZEN_TIP_009_0946_UNTOUCHED=1
echo A4F_IMMUTABLE=1
) > "%TIP%\CANDIDATE.txt"

echo === PATCH ExpectSha ===>> "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$sha='%TIPSHA%'.ToUpper(); $files=@('%ART%\issue49_integ011_remeasure.ps1','%ART%\run_issue49_tip011_exclusive.ps1'); foreach($f in $files){ if(Test-Path -LiteralPath $f){ $c=Get-Content -LiteralPath $f -Raw; $c=$c -replace 'ExpectSha\s*=\s*\"[0-9A-Fa-f]{64}\"','ExpectSha = \"'+$sha+'\"'; $c=$c -replace \"\$expect\s*=\s*'[0-9A-Fa-f]{64}'\",\"`$expect = '$sha'\"; Set-Content -LiteralPath $f -Value $c -NoNewline -Encoding UTF8; Write-Output ('PATCHED '+$f)} else { Write-Output ('MISSING '+$f)} }" >> "%LOG%" 2>&1

echo === RESET bug.cpp ===>> "%LOG%"
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
echo BUG_RESET=1>> "%LOG%"

echo STAGE_OK SHA=%TIPSHA%>> "%LOG%"
echo STAGE_OK SHA=%TIPSHA%
exit /b 0

:toupper
setlocal EnableDelayedExpansion
set "v=!%~1!"
for %%A in (a b c d e f) do call set "v=%%v:%%A=%%A%%"
rem force upper via powershell helper if needed
endlocal & set "%~1=%SHA%"
if /I "%~1"=="SHA" (
  for /f %%U in ('powershell -NoProfile -Command "'%SHA%'.ToUpper()"') do set SHA=%%U
)
if /I "%~1"=="TIPSHA" (
  for /f %%U in ('powershell -NoProfile -Command "'%TIPSHA%'.ToUpper()"') do set TIPSHA=%%U
)
goto :eof
