@echo off
REM Build RawrXD IDE with Sovereign Validation Integration
REM ======================================================

setlocal enabledelayedexpansion

echo ========================================
echo RawrXD IDE Build with Sovereign Bridge
echo ========================================
echo.

REM Check for Visual Studio environment
where cl >nul 2>nul
if errorlevel 1 (
    echo ERROR: Visual Studio C++ compiler not found.
    echo Please run this script from a VS Developer Command Prompt.
    exit /b 1
)

REM Set source files
set SOURCES=RawrXD_IDE_Win32.cpp

REM Set output
set OUTPUT=RawrXD_IDE.exe

REM Set include paths
set INCLUDES=-I. -I..\..\rawrxd-ci-bootstrap\src\sovereign

REM Set compiler flags
set CFLAGS=/W4 /O2 /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /nologo %INCLUDES%

REM Set linker libraries
set LIBS=user32.lib gdi32.lib comctl32.lib comdlg32.lib shell32.lib shlwapi.lib advapi32.lib ole32.lib

REM Set linker flags
set LDFLAGS=/subsystem:windows /entry:wWinMainCRTStartup

echo Compiling...
echo Source: %SOURCES%
echo Output: %OUTPUT%
echo.

REM Compile and link
cl %CFLAGS% %SOURCES% /Fe%OUTPUT% /link %LDFLAGS% %LIBS%

if errorlevel 1 (
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
echo Output: %OUTPUT%
echo.
echo Features:
echo   - File operations (New, Open, Save, Save As)
echo   - Edit operations (Undo, Redo, Cut, Copy, Paste)
echo   - Build system (ml64.exe, cl.exe)
echo   - Sovereign Validation (Ctrl+Shift+V)
echo   - Evidence Bundle Viewer
echo.
echo Run with: .\%OUTPUT%
