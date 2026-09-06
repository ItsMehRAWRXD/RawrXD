@echo off
setlocal EnableExtensions

set "VSROOT=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
set "VCVARS=%VSROOT%\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
    set "VSROOT=C:\Program Files\Microsoft Visual Studio\2022\Community"
    set "VCVARS=%VSROOT%\VC\Auxiliary\Build\vcvars64.bat"
)

call "%VCVARS%" >nul 2>nul
if errorlevel 1 exit /b 1

set "ROOT=%~dp0..\.."
for %%I in ("%ROOT%") do set "ROOT=%%~fI"
set "SRC=%ROOT%\src\asm"
set "OUT=%ROOT%\build\p1_product_runtime_authority_x64"

if not exist "%OUT%" mkdir "%OUT%"

ml64 /nologo /c /Fo"%OUT%\P1_ProductRuntimeAuthority_x64.obj" /I"%SRC%" "%SRC%\P1_ProductRuntimeAuthority_x64.asm"
if errorlevel 1 exit /b %errorlevel%

echo P1PRA_OBJ=%OUT%\P1_ProductRuntimeAuthority_x64.obj
exit /b 0
