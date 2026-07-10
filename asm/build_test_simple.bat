@echo off
REM ============================================================================
REM build_test_simple.bat - Build Simple Kernel Test
REM ============================================================================

cd /d d:\src\asm

REM Find VS2022
for /f "delims=" %%i in ('"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath') do set VSPATH=%%i

if not defined VSPATH (
    echo [ERROR] Visual Studio 2022 not found
    exit /b 1
)

echo [INFO] VS2022 found at: %VSPATH%

REM Setup environment
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat"

REM Add Windows SDK paths
set INCLUDE=%INCLUDE%;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um
set INCLUDE=%INCLUDE%;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared

echo [INFO] Environment configured

REM ============================================================================
REM Build KernelDispatch
REM ============================================================================
echo.
echo [BUILD] Compiling Sovereign_KernelDispatch.cpp...

cl.exe /c /W3 /O2 /arch:AVX2 /nologo /EHsc /Foobj\Sovereign_KernelDispatch.obj Sovereign_KernelDispatch.cpp

if errorlevel 1 (
    echo [ERROR] KernelDispatch compilation failed
    exit /b 1
)
echo [OK] Sovereign_KernelDispatch.obj

REM ============================================================================
REM Build Test
REM ============================================================================
echo.
echo [BUILD] Compiling test_kernels_simple.cpp...

cl.exe /c /W3 /O2 /arch:AVX2 /nologo /EHsc /Foobj\test_kernels_simple.obj test_kernels_simple.cpp

if errorlevel 1 (
    echo [ERROR] Test compilation failed
    exit /b 1
)
echo [OK] test_kernels_simple.obj

REM ============================================================================
REM Link
REM ============================================================================
echo.
echo [BUILD] Linking test_kernels_simple.exe...

link.exe /SUBSYSTEM:CONSOLE /OUT:test_kernels_simple.exe obj\test_kernels_simple.obj obj\Sovereign_KernelDispatch.obj Sovereign_RMSNorm.obj Sovereign_RoPE.obj Sovereign_ResidualAdd.obj Sovereign_LayerNorm.obj Sovereign_Q4K_Dequant.obj msvcrt.lib kernel32.lib

if errorlevel 1 (
    echo [ERROR] Linking failed
    exit /b 1
)

echo.
echo ============================================
echo [SUCCESS] Build Complete
echo ============================================
echo.
echo Executable: test_kernels_simple.exe
echo.
echo Run with: test_kernels_simple.exe
echo.
