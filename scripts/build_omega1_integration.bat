@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion

:: ============================================================================
:: Omega1 IDE Integration Build Script
:: Builds the v2.0 IDE integration layer for RawrXD-Win32IDE
:: ============================================================================

echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║  RawrXD OMEGA-1 IDE Integration Build                                        ║
echo ║  Version 2.0.0 - Gate 4: IDE Integration                                       ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.

:: Configuration
set SRC_DIR=D:\rawrxd\src\Win32IDE
set BUILD_DIR=D:\rawrxd\build\omega1_integration
set VCVARS="C:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat"

:: Create build directory
if not exist %BUILD_DIR% mkdir %BUILD_DIR%

:: Check for VS2022
if not exist %VCVARS% (
    echo [ERROR] Visual Studio 2022 not found at %VCVARS%
    exit /b 1
)

echo [INFO] Loading Visual Studio 2022 environment...
call %VCVARS% >nul 2>&1

:: Source files
set SOURCES=^
%SRC_DIR%\Omega1_IPC_Client.cpp ^
%SRC_DIR%\Omega1_IDE_Bridge.cpp ^
%SRC_DIR%\Omega1_Keyboard_Hook.cpp

echo [INFO] Compiling Omega1 IDE Integration...
echo [INFO] Sources: Omega1_IPC_Client, Omega1_IDE_Bridge, Omega1_Keyboard_Hook

:: Compile to static library
cl.exe /c /W4 /O2 /MD /EHsc /nologo /std:c++17 ^
    /I%SRC_DIR% ^
    /DUNICODE /D_UNICODE ^
    /DWIN32_LEAN_AND_MEAN ^
    /DNDEBUG ^
    %SOURCES% ^
    /Fo%BUILD_DIR%\

if errorlevel 1 (
    echo [ERROR] Compilation failed
    exit /b 1
)

echo [INFO] Creating static library...

:: Create static library
lib.exe /nologo /out:%BUILD_DIR%\Omega1IDE.lib ^
    %BUILD_DIR%\Omega1_IPC_Client.obj ^
    %BUILD_DIR%\Omega1_IDE_Bridge.obj ^
    %BUILD_DIR%\Omega1_Keyboard_Hook.obj

if errorlevel 1 (
    echo [ERROR] Library creation failed
    exit /b 1
)

echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║  ✅ BUILD SUCCESSFUL                                                         ║
echo ╠══════════════════════════════════════════════════════════════════════════════╣
echo ║  Output: %BUILD_DIR%\Omega1IDE.lib                                          ║
echo ║  Headers:                                                                     ║
echo ║    - Omega1_IPC_Protocol.h                                                    ║
echo ║    - Omega1_IPC_Client.h                                                      ║
echo ║    - Omega1_IDE_Bridge.h                                                      ║
echo ║    - Omega1_Keyboard_Hook.h                                                   ║
echo ║    - Omega1_Integration.h (master header)                                   ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.

:: List outputs
dir /b %BUILD_DIR%\*.lib %BUILD_DIR%\*.obj 2>nul

echo.
echo [INFO] Integration files ready at: %BUILD_DIR%
echo [INFO] Link Omega1IDE.lib with RawrXD-Win32IDE to enable OMEGA-1 integration
echo.

endlocal
