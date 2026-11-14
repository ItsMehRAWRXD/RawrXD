@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64 >nul
cd /d G:\~dev\rawrxd\build_win32ide_link001
ninja -t commands RawrXD-Win32IDE 2>nul | findstr /I "link.exe AgentPanel /OUT"
