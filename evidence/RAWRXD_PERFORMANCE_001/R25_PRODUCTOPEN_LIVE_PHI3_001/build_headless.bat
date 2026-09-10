@echo off
cd /D G:\~dev\rawrxd\build-fd
del /f /q CMakeFiles\RawrXD-Win32IDE.dir\src\win32app\HeadlessIDE.cpp.obj 2>nul
p
echo HEADLESS_EXIT=%ERRORLEVEL%
