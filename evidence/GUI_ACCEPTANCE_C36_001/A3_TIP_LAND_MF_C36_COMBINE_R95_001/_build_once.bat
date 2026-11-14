@echo off
setlocal EnableDelayedExpansion
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "G:\~dev\rawrxd\build_win32ide_link001"
link.exe /nologo @"G:\~dev\rawrxd\build_win32ide_link001\CMakeFiles\RawrXD-Win32IDE_tip_land_mf_c36_combine_r95.rsp"
echo LINK_RC=!ERRORLEVEL!
exit /b !ERRORLEVEL!
