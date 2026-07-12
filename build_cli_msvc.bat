@echo off
:: Build script for Sovereign CLI using MSVC
:: Complete Phase 7C.2 Integration

setlocal EnableDelayedExpansion

echo ==============================================================================
echo Sovereign CLI Build - Phase 7C.2 Complete Integration
echo ==============================================================================
echo.

:: Configuration
set "BUILD_DIR=d:\rawrxd\build_cli"
set "SRC_DIR=d:\rawrxd\src"
set "ASM_DIR=d:\src\asm"
set "CXX=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe"
set "LINK=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe"
set "CXXFLAGS=/std:c++17 /O2 /arch:AVX2 /DNDEBUG /D_WIN32 /EHsc /MP /W3"
set "INCLUDES=/I%SRC_DIR% /I%ASM_DIR% /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt""
set "LDFLAGS=/LIBPATH:%ASM_DIR% /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64""

:: Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

:: Check compiler exists
if not exist "%CXX%" (
    echo ERROR: Compiler not found at %CXX%
    exit /b 1
)

echo Using compiler: %CXX%
echo Build directory: %BUILD_DIR%
echo.

:: Build CLI main
echo [1/1] Building SovereignCLI.exe...
"%CXX%" %CXXFLAGS% %INCLUDES% "d:\rawrxd\cli_main.cpp" /Fo"%BUILD_DIR%\cli_main.obj" /c 2>&1
if errorlevel 1 (
    echo FAILED: cli_main.cpp compilation
    exit /b 1
)
echo ^> cli_main.obj compiled
echo.

:: Link with kernel libraries
echo Linking with kernel libraries...
"%LINK%" /OUT:"%BUILD_DIR%\SovereignCLI.exe" ^
    "%BUILD_DIR%\cli_main.obj" ^
    %LDFLAGS% ^
    kernel32.lib ^
    user32.lib ^
    2>&1

if errorlevel 1 (
    echo FAILED: Linking
    exit /b 1
)

echo.
echo ==============================================================================
echo BUILD SUCCESSFUL
echo ==============================================================================
echo.
echo Output: %BUILD_DIR%\SovereignCLI.exe
echo.
echo Run with:
echo   %BUILD_DIR%\SovereignCLI.exe --help
echo   %BUILD_DIR%\SovereignCLI.exe --test
echo   %BUILD_DIR%\SovereignCLI.exe --info
echo ==============================================================================
