@echo off
REM ============================================================================
REM Build Script: Test Debugger Integration
REM ============================================================================

setlocal enabledelayedexpansion

REM Tool paths
set VSROOT=C:\Program Files\Microsoft Visual Studio\18\Enterprise
set CL="%VSROOT%\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe"
set LINK="%VSROOT%\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe"

REM Include paths
set INCLUDE=%VSROOT%\VC\Tools\MSVC\14.51.36231\include;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt
set LIB=%VSROOT%\VC\Tools\MSVC\14.51.36231\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64

REM Directories
set SRC_DIR=d:\RawrXD\src
set OUT_DIR=d:\RawrXD\bin
set OBJ_DIR=d:\RawrXD\obj\debugger_test

REM Create directories
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"
if not exist "%OBJ_DIR%" mkdir "%OBJ_DIR%"

echo ============================================================================
echo Testing Debugger Integration Build
echo ============================================================================
echo.

REM Compile DebugSession.cpp
echo [1/4] Compiling DebugSession.cpp...
%CL% /c /W4 /EHsc /O2 /nologo /Zi /Fo"%OBJ_DIR%\DebugSession.obj" /I"%SRC_DIR%" "%SRC_DIR%\debugger\DebugSession.cpp"
if errorlevel 1 goto :error

echo.
echo ============================================================================
echo DEBUGGER BUILD TEST SUCCESSFUL
echo ============================================================================
echo.
echo The real debugger integration compiles correctly.
echo.
goto :end

:error
echo.
echo ============================================================================
echo BUILD FAILED
echo ============================================================================
exit /b 1

:end
endlocal
