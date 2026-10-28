@echo off
taskkill /F /PID 48836 >nul 2>&1
taskkill /F /IM cl.exe >nul 2>&1
taskkill /F /IM link.exe >nul 2>&1
taskkill /F /IM ninja.exe >nul 2>&1
echo KILL_DONE
dir /T:W "G:\~dev\rawrxd\build_win32ide_link001\CMakeFiles\RawrXD-Win32IDE.dir\src\deep2\Deep2Engine.cpp.obj"
dir /T:W "G:\~dev\rawrxd\build_win32ide_link001\CMakeFiles\RawrXD-Win32IDE.dir\src\win32app\Win32IDE.cpp.obj"
exit /b 0
