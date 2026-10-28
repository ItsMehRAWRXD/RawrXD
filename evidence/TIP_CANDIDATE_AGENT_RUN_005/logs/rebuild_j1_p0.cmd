@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 >nul
cd /d "G:\~dev\rawrxd\build_win32ide_link001"
echo START_UTC=%DATE% %TIME%
where ninja
ninja -j1 RawrXD-Win32IDE
echo NINJA_EXIT=%ERRORLEVEL%
echo END_UTC=%DATE% %TIME%
