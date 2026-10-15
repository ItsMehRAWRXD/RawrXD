@echo off
REM Compile-verify helper: compiles one C++ source with MSVC and reports diagnostics.
REM Usage: build_one.bat <source.cpp> <output_obj_dir> [extra cl flags]
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
    echo ERROR: vcvars64.bat failed
    exit /b 1
)
setlocal enabledelayedexpansion
set SRC=%1
set OUTDIR=%2
set EXTRA=%3

if not exist "%OUTDIR%" mkdir "%OUTDIR%"

echo === Compiling %SRC% ===
cl.exe /nologo /std:c++20 /EHsc /W4 /permissive- /c /Fo:"%OUTDIR%\\" /I"%CD%\include" %EXTRA% "%SRC%" 2>&1
set RC=%errorlevel%
echo === exit code: %RC% ===
endlocal
exit /b %RC%