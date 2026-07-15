@echo off
REM ============================================================================
REM RawrXD-Script Phase 0 Build Script
REM Builds the MASM VM and C++ test harness
REM ============================================================================

setlocal enabledelayedexpansion

REM Configuration
set ML64="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set CL="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe"
set LINK="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"

set SRC_DIR=d:\rawrxd\src\masm
set OUT_DIR=d:\rawrxd\build-ninja\masm_vm

REM Create output directory
if not exist %OUT_DIR% mkdir %OUT_DIR%

echo ============================================================================
echo RawrXD-Script Phase 0 Build
echo ============================================================================
echo.

REM Step 1: Assemble the MASM VM
echo [1/3] Assembling rawrxd_script_vm.asm...
%ML64% /c /W3 /nologo /Zi /Fo %OUT_DIR%\rawrxd_script_vm.obj %SRC_DIR%\rawrxd_script_vm.asm
if errorlevel 1 (
    echo ERROR: Assembly failed!
    exit /b 1
)
echo       Success: rawrxd_script_vm.obj created

REM Step 2: Compile the C++ test harness
echo [2/3] Compiling test_vm.cpp...
%CL% /c /W4 /nologo /Zi /O2 /Fo %OUT_DIR%\test_vm.obj %SRC_DIR%\test_vm.cpp
if errorlevel 1 (
    echo ERROR: C++ compilation failed!
    exit /b 1
)
echo       Success: test_vm.obj created

REM Step 3: Link the executable
echo [3/3] Linking test_vm.exe...
%LINK% /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /NODEFAULTLIB:libucrt.lib /NODEFAULTLIB:libvcruntime.lib ^
    /OUT:%OUT_DIR%\test_vm.exe ^
    %OUT_DIR%\test_vm.obj ^
    %OUT_DIR%\rawrxd_script_vm.obj ^
    kernel32.lib ^
    ucrt.lib ^
    vcruntime.lib
if errorlevel 1 (
    echo ERROR: Linking failed!
    exit /b 1
)
echo       Success: test_vm.exe created

echo.
echo ============================================================================
echo Build Complete!
echo ============================================================================
echo Output: %OUT_DIR%\test_vm.exe
echo.
echo Run with: %OUT_DIR%\test_vm.exe

endlocal
