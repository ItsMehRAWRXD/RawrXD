@echo off
REM Build script for RawrXD_IDE_Win32 with PrometheusMoE integration
REM Uses MinGW-w64

echo ========================================
echo RawrXD IDE with PrometheusMoE Build
echo ========================================
echo.

set SRC=D:\RawrXD\src\ide\RawrXD_IDE_Win32.cpp
set OUT=D:\RawrXD\src\ide\RawrXD_IDE_MoE.exe
set CC=C:\msys64\mingw64\bin\g++.exe

if not exist "%CC%" (
    echo ERROR: MinGW g++ not found at %CC%
    echo Please install MinGW-w64 or update the path.
    exit /b 1
)

echo Compiler: %CC%
echo Source: %SRC%
echo Output: %OUT%
echo.

REM Compile with all necessary flags
"%CC%" -O2 -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0601 ^
    -I"D:\rawrxd-ci-bootstrap\src" ^
    -I"D:\RawrXD\src" ^
    "%SRC%" ^
    -o "%OUT%" ^
    -mwindows ^
    -luser32 -lgdi32 -lcomctl32 -lcomdlg32 -lshell32 -lshlwapi ^
    -ladvapi32 -lole32 -lmsftedit ^
    -static-libgcc -static-libstdc++ ^
    -Wl,--subsystem,windows 2>&1

if %ERRORLEVEL% neq 0 (
    echo.
    echo ========================================
    echo BUILD FAILED
    echo ========================================
    exit /b 1
)

echo.
echo ========================================
echo BUILD SUCCESSFUL
echo ========================================
echo.
echo Output: %OUT%
echo.
echo To run: %OUT%

exit /b 0
