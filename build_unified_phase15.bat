@echo off
::==============================================================================
:: build_unified_phase15.bat - Build RawrXD Unified System
:: Phase 15: Complete System Unification
::
:: This script builds the unified RawrXD.exe that replaces all previous
:: separate executables with a single coherent product.
::==============================================================================

setlocal enabledelayedexpansion

echo ============================================
echo RawrXD Unified Build System
echo Phase 15: Complete System Unification
echo ============================================
echo.

:: Configuration
set BUILD_DIR=build-unified-phase15
set SRC_DIR=src
set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set CL=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe

:: Create build directory
if not exist %BUILD_DIR% mkdir %BUILD_DIR%

:: Set up environment
call "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

echo [1/5] Building Deep2 Inference Gateway...
%CL% /c /O2 /EHsc /I%SRC_DIR% /I%SRC_DIR%\include /Fo%BUILD_DIR%\Deep2InferenceGateway.obj %SRC_DIR%\deep2\Deep2InferenceGateway.cpp
if errorlevel 1 goto :error

echo [2/5] Building RawrXD Host...
%CL% /c /O2 /EHsc /I%SRC_DIR% /I%SRC_DIR%\include /Fo%BUILD_DIR%\RawrXDHost.obj %SRC_DIR%\unified\RawrXDHost.cpp
if errorlevel 1 goto :error

echo [3/5] Building Unified Main...
%CL% /c /O2 /EHsc /I%SRC_DIR% /I%SRC_DIR%\include /Fo%BUILD_DIR%\main_unified.obj %SRC_DIR%\unified\main_unified.cpp
if errorlevel 1 goto :error

echo [4/5] Linking Unified Executable...
%LINK% /OUT:%BUILD_DIR%\RawrXD.exe /SUBSYSTEM:CONSOLE /MACHINE:X64 ^
    %BUILD_DIR%\main_unified.obj ^
    %BUILD_DIR%\RawrXDHost.obj ^
    %BUILD_DIR%\Deep2InferenceGateway.obj ^
    kernel32.lib user32.lib gdi32.lib advapi32.lib shell32.lib ^
    ole32.lib oleaut32.lib uuid.lib ws2_32.lib
if errorlevel 1 goto :error

echo [5/5] Build complete!
echo.
echo ============================================
echo RawrXD Unified Build Successful
echo ============================================
echo.
echo Output: %BUILD_DIR%\RawrXD.exe
echo.
echo Usage:
echo   RawrXD.exe              - Launch IDE
echo   RawrXD.exe --cli        - CLI mode
echo   RawrXD.exe --server     - Server mode
echo   RawrXD.exe --compile    - Compile mode
echo   RawrXD.exe --agent      - Agent mode
echo.

goto :end

:error
echo.
echo ============================================
echo BUILD FAILED
echo ============================================
exit /b 1

:end
endlocal
