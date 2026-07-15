@echo off
REM ============================================================================
REM Sovereign Test Suite Build Script
REM ============================================================================
REM Auto-detects VS2022, builds all kernels, and creates test executable
REM ============================================================================

setlocal enabledelayedexpansion

echo ============================================
echo Sovereign Kernel Test Suite Build
echo ============================================
echo.

REM ============================================================================
REM Step 1: Locate Visual Studio 2022
REM ============================================================================
echo [1/6] Locating Visual Studio 2022...

for /f "tokens=*" %%i in ('"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath') do (
    set VSROOT=%%i
)

if "%VSROOT%"=="" (
    echo ERROR: Visual Studio 2022 not found.
    echo Please install VS2022 with C++ build tools.
    exit /b 1
)

echo      Found: %VSROOT%

REM Setup environment
call "%VSROOT%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

REM Find MSVC version
set VCTOOLS=%VSROOT%\VC\Tools\MSVC
for /f "tokens=*" %%i in ('dir "%VCTOOLS%" /b /ad ^| findstr /r "^[0-9]"') do (
    set MSVCVER=%%i
)

set ML64="%VCTOOLS%\%MSVCVER%\bin\Hostx64\x64\ml64.exe"
set CL="cl.exe"
set LINK="link.exe"
set LIBTOOL="lib.exe"

echo      Using MSVC: %MSVCVER%
echo.

REM ============================================================================
REM Step 2: Verify kernel objects exist
REM ============================================================================
echo [2/6] Verifying kernel objects...

set KERNELS_EXIST=1
for %%K in (Sovereign_RMSNorm Sovereign_RoPE Sovereign_ResidualAdd Sovereign_LayerNorm Sovereign_Q4K_Dequant) do (
    if not exist "%%K.obj" (
        echo      MISSING: %%K.obj
        set KERNELS_EXIST=0
    ) else (
        echo      FOUND: %%K.obj
    )
)

if %KERNELS_EXIST%==0 (
    echo.
    echo ERROR: Some kernel objects are missing.
    echo Run individual build scripts first:
    echo   build_rmsnorm.bat
    echo   build_rope.bat
    echo   build_residual.bat
    exit /b 1
)
echo.

REM ============================================================================
REM Step 3: Compile C++ dispatch layer
REM ============================================================================
echo [3/6] Compiling C++ dispatch layer...

%CL% /c /O2 /W4 /EHsc /Zi /nologo /Fo Sovereign_KernelDispatch.obj ^
    /I. ^
    Sovereign_KernelDispatch.cpp

if errorlevel 1 (
    echo ERROR: Dispatch compilation failed
    exit /b 1
)
echo      OK: Sovereign_KernelDispatch.obj
echo.

REM ============================================================================
REM Step 4: Compile test suite
REM ============================================================================
echo [4/6] Compiling test suite...

%CL% /c /O2 /W4 /EHsc /Zi /nologo /Fo test_kernel_dispatch.obj ^
    /I. ^
    test_kernel_dispatch.cpp

if errorlevel 1 (
    echo ERROR: Test compilation failed
    exit /b 1
)
echo      OK: test_kernel_dispatch.obj
echo.

REM ============================================================================
REM Step 5: Link test executable
REM ============================================================================
echo [5/6] Linking test executable...

%LINK% /OUT:test_kernel_dispatch.exe ^
    /SUBSYSTEM:CONSOLE ^
    /DEBUG ^
    /nologo ^
    test_kernel_dispatch.obj ^
    Sovereign_KernelDispatch.obj ^
    Sovereign_RMSNorm.obj ^
    Sovereign_RoPE.obj ^
    Sovereign_ResidualAdd.obj ^
    Sovereign_LayerNorm.obj ^
    Sovereign_Q4K_Dequant.obj ^
    msvcrt.lib ^
    kernel32.lib ^
    legacy_stdio_definitions.lib

if errorlevel 1 (
    echo ERROR: Linking failed
    exit /b 1
)
echo      OK: test_kernel_dispatch.exe
echo.

REM ============================================================================
REM Step 6: Compile transformer oracle (if exists)
REM ============================================================================
if exist "Sovereign_Transformer_Oracle.cpp" (
    echo [6/6] Compiling transformer oracle...
    
    %CL% /c /O2 /W4 /EHsc /Zi /nologo /Fo Sovereign_Transformer_Oracle.obj ^
        /I. ^
        Sovereign_Transformer_Oracle.cpp
    
    if errorlevel 1 (
        echo WARNING: Oracle compilation failed
    ) else (
        %LINK% /OUT:transformer_oracle.exe ^
            /SUBSYSTEM:CONSOLE ^
            /DEBUG ^
            /nologo ^
            Sovereign_Transformer_Oracle.obj ^
            Sovereign_KernelDispatch.obj ^
            Sovereign_RMSNorm.obj ^
            Sovereign_RoPE.obj ^
            Sovereign_ResidualAdd.obj ^
            Sovereign_LayerNorm.obj ^
            Sovereign_Q4K_Dequant.obj ^
            msvcrt.lib ^
            kernel32.lib ^
            legacy_stdio_definitions.lib
        
        if not errorlevel 1 (
            echo      OK: transformer_oracle.exe
        )
    )
) else (
    echo [6/6] Skipping transformer oracle (not yet generated)
)
echo.

REM ============================================================================
REM Summary
REM ============================================================================
echo ============================================
echo Build Complete!
echo ============================================
echo.
echo Executables:
echo   - test_kernel_dispatch.exe  (Kernel unit tests)
echo.
echo Run tests with:
echo   .\test_kernel_dispatch.exe
echo.
echo Expected output:
echo   [PASS] RMSNorm
echo   [PASS] RoPE
echo   [PASS] ResidualAdd
echo   [PASS] LayerNorm
echo   [PASS] Q4K Dequant
echo   [PASS] Transformer Layer Simulation
echo.

endlocal
