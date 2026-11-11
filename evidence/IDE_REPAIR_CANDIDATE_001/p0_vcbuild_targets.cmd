@echo off
setlocal EnableExtensions
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
  echo VCVARS_FAIL
  exit /b 90
)
echo INCLUDE_OK
cmake --build F:\rawrxd\build_tip_debug_rel --config Release --target rawrxd_computer_use --target RawrXD-CLI-V2 --target rawrxd_computer_use_ide_verify --target RawrXD-Win32IDE-Native-Ext -j 4
exit /b %ERRORLEVEL%
