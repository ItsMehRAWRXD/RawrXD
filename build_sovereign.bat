@echo off
REM Build Sovereign Loader with MASM Kernels
REM Uses Visual Studio 2022 x64 Native Tools Command Prompt

echo.
echo ================================================================
echo    RawrXD Sovereign Loader - MASM Kernel Build System
echo    Pure Assembly Performance ^| Zero Qt Overhead
echo ================================================================
echo.

REM Set paths
set PROJECT_ROOT=D:\temp\RawrXD-agentic-ide-production
set KERNEL_DIR=%PROJECT_ROOT%\RawrXD-ModelLoader\kernels
set SRC_DIR=%PROJECT_ROOT%\src
set BUILD_DIR=%PROJECT_ROOT%\build-sovereign
set BIN_DIR=%BUILD_DIR%\bin

REM Create directories
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"

REM === Step 1: Assemble MASM kernels ===
echo [1/4] Assembling MASM kernels...

REM Assemble universal_quant_kernel.asm
echo   -^> Assembling universal_quant_kernel.asm...
ml64 /c /Cp /arch:AVX512 /Fo"%BUILD_DIR%\universal_quant_kernel.obj" "%KERNEL_DIR%\universal_quant_kernel.asm"
if errorlevel 1 (
    echo   X Assembly failed!
    exit /b 1
)
echo   OK

REM Assemble beaconism_dispatcher.asm
echo   -^> Assembling beaconism_dispatcher.asm...
ml64 /c /Cp /arch:AVX512 /Fo"%BUILD_DIR%\beaconism_dispatcher.obj" "%KERNEL_DIR%\beaconism_dispatcher.asm"
if errorlevel 1 (
    echo   X Assembly failed!
    exit /b 1
)
echo   OK

REM Assemble dimensional_pool.asm
echo   -^> Assembling dimensional_pool.asm...
ml64 /c /Cp /arch:AVX512 /Fo"%BUILD_DIR%\dimensional_pool.obj" "%KERNEL_DIR%\dimensional_pool.asm"
if errorlevel 1 (
    echo   X Assembly failed!
    exit /b 1
)
echo   OK

echo.
echo [2/4] Compiling C launcher...
echo   -^> Compiling sovereign_loader.c...
cl /c /O2 /Fo"%BUILD_DIR%\sovereign_loader.obj" "%SRC_DIR%\sovereign_loader.c" /nologo
if errorlevel 1 (
    echo   X Compilation failed!
    exit /b 1
)
echo   OK

echo.
echo [3/4] Linking executable...
echo   -^> Linking SovereignLoader.exe...
link /OUT:"%BIN_DIR%\SovereignLoader.exe" /SUBSYSTEM:CONSOLE ^
     "%BUILD_DIR%\sovereign_loader.obj" ^
     "%BUILD_DIR%\universal_quant_kernel.obj" ^
     "%BUILD_DIR%\beaconism_dispatcher.obj" ^
     "%BUILD_DIR%\dimensional_pool.obj" ^
     kernel32.lib user32.lib /NOLOGO
if errorlevel 1 (
    echo   X Linking failed!
    exit /b 1
)
echo   OK

echo.
echo [4/4] Verifying build...
if exist "%BIN_DIR%\SovereignLoader.exe" (
    echo   OK Executable created: %BIN_DIR%\SovereignLoader.exe
    echo   -^> Architecture: x64 ^(Pure MASM + Minimal C^)
    echo   -^> Dependencies: None ^(native Windows API only^)
) else (
    echo   X Executable not found!
    exit /b 1
)

echo.
echo ================================================================
echo   BUILD SUCCESSFUL
echo ================================================================
echo.
echo Run the sovereign loader:
echo   cd %BIN_DIR%
echo   SovereignLoader.exe
echo.
echo This executes pure MASM kernels with:
echo   * Universal 10^-8 quantization
echo   * 1:11 dimensional pooling
echo   * Beaconism protocol
echo   * 11-sided circular mirror geometry
echo.
