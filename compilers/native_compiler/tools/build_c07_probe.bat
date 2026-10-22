@echo off
REM Build and run the C07 assembler probe.
setlocal enabledelayedexpansion
for %%I in ("%~dp0..") do set "ROOT=%%~fI"
set "OUT=%~1"
if "%OUT%"=="" for %%I in ("%ROOT%\..\build\rawr_stage1") do set "OUT=%%~fI"
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
set "COMMON_OBJS=%OUT%\sys.obj %OUT%\string.obj %OUT%\sha256.obj"
cl /nologo /std:c++17 /EHsc /W3 /O2 /GS- ^
   /I"%ROOT%\rawrstd\include" /I"%ROOT%\src" ^
   /Fe:"%OUT%\c07_probe.exe" ^
   "%ROOT%\tests\c07_probe.cpp" ^
   %COMMON_OBJS% "%OUT%\CoffWriter.obj" "%OUT%\X64Assembler.obj" 2>&1
if errorlevel 1 ( echo [FAIL] probe build & exit /b 1 )
"%OUT%\c07_probe.exe" "%~2" "%~3"
exit /b %errorlevel%
