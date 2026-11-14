@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64 >nul
cd /d "G:\~dev\rawrxd\build_win32ide_link001"
ninja RawrXD-Win32IDE
echo NINJA_EXIT=%ERRORLEVEL%
