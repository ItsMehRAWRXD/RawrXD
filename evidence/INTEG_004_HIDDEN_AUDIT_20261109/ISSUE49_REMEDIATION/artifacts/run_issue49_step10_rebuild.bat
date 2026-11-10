@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
  echo VCVARS_FAIL
  exit /b 1
)

echo === NATIVE_EXT ===
cd /d F:\rawrxd\build_tip_ext_host_001
echo NINJA_START=%DATE% %TIME%
ninja RawrXD-Win32IDE-Native-Ext
set NINJA_EC=%ERRORLEVEL%
echo NINJA_EXIT=%NINJA_EC%
echo NINJA_END=%DATE% %TIME%
if not "%NINJA_EC%"=="0" exit /b %NINJA_EC%

echo === LOOP_BUILD ===
cd /d F:\rawrxd\tools
call build_deep2_agentic_loop.bat
set LOOP_EC=%ERRORLEVEL%
echo LOOP_EXIT=%LOOP_EC%
if not "%LOOP_EC%"=="0" (
  echo LOOP_BUILD_FAILED continuing with Native-Ext only if prior loop exists
)

echo === STAGE tip_rc_issue49_005 ===
set TIPROOT=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_rc_issue49_005
if not exist "%TIPROOT%" mkdir "%TIPROOT%"
if not exist "%TIPROOT%\issue49_logs" mkdir "%TIPROOT%\issue49_logs"
copy /Y F:\rawrxd\build_tip_ext_host_001\bin\RawrXD-Win32IDE-Native-Ext.exe "%TIPROOT%\RawrXD-Win32IDE-Native-Ext.exe"
if exist F:\rawrxd\tools\deep2_agentic_loop.exe (
  copy /Y F:\rawrxd\tools\deep2_agentic_loop.exe "%TIPROOT%\deep2_agentic_loop.exe"
) else (
  copy /Y F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_rc_issue49_004\deep2_agentic_loop.exe "%TIPROOT%\deep2_agentic_loop.exe"
)
powershell -NoProfile -Command "(Get-FileHash '%TIPROOT%\RawrXD-Win32IDE-Native-Ext.exe').Hash | Set-Content '%TIPROOT%\SHA256.txt'; Write-Host ('NATIVE_SHA=' + (Get-Content '%TIPROOT%\SHA256.txt')); if (Test-Path '%TIPROOT%\deep2_agentic_loop.exe') { Write-Host ('LOOP_SHA=' + (Get-FileHash '%TIPROOT%\deep2_agentic_loop.exe').Hash) }"
echo STAGE_DONE
exit /b 0
