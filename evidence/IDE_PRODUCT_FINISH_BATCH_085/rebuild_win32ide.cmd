@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
cd /d "F:\~dev\rawrxd\build_p1pra_win32ide"
set "TELEM_OBJ=CMakeFiles\RawrXD-Win32IDE.dir\src\asm\RawrXD_Telemetry_Kernel.asm.obj"
if exist "%TELEM_OBJ%" del /f /q "%TELEM_OBJ%"
ninja RawrXD-Win32IDE
exit /b %ERRORLEVEL%
