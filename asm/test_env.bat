@echo off
cd /d d:\src\asm

for /f "delims=" %%i in ('"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath') do set VSPATH=%%i

echo VS Path: %VSPATH%
echo.

call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat"

echo.
echo INCLUDE=%INCLUDE%
echo.
echo LIB=%LIB%
echo.
where cl.exe
