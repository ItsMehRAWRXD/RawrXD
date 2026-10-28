@echo off
setlocal EnableExtensions
set EVID=%~dp0
cd /d "%EVID%"
call "%EVID%_asm_rebuild.bat"
if errorlevel 1 (
  echo ABSORB_FAIL asm
  exit /b 1
)
call "%EVID%_relink_win32ide.bat"
if errorlevel 1 (
  echo ABSORB_FAIL relink
  exit /b 1
)
echo ABSORB_PIPELINE_OK
exit /b 0
