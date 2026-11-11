@echo off
setlocal

echo ========================================
echo Testing Extension Host Compilation
echo ========================================

REM Find VS installation
set "VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Enterprise"
if not exist "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat" (
    set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
)

if not exist "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat" (
    echo ERROR: Could not find Visual Studio
    exit /b 1
)

echo Found VS at: %VS_PATH%

REM Setup environment
call "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat"

if errorlevel 1 (
    echo ERROR: Failed to setup environment
    exit /b 1
)

cd /d d:\rawrxd\extension_host

set "INCLUDE_FLAGS=/I. /I..\include /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared""

echo.
echo Compiling test_extension_host.cpp...
echo.

cl /c /std:c++20 /EHsc %INCLUDE_FLAGS% test_extension_host.cpp 2>&1
if errorlevel 1 (
    echo.
    echo ========================================
    echo COMPILATION FAILED
    echo ========================================
    exit /b 1
) else (
    echo.
    echo ========================================
    echo COMPILATION SUCCESSFUL
    echo ========================================
    echo All extension_host headers compile cleanly!
)

endlocal
