@echo off
REM ============================================================================
REM build_test_resurrected.bat - Build Phase 7A Integration Test
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
set VCVARS=%VSPATH%\VC\Auxiliary\Build\vcvars64.bat
echo [INFO] Setting up environment with %VCVARS%
call "%VCVARS%"

echo ============================================
echo Building Phase 7A Integration Test
REM ============================================================================
echo.

REM Compile test
echo [1/2] Compiling test_resurrected_kernels.cpp...
cl.exe /c /W4 /O2 /EHsc /arch:AVX2 /Fo test_resurrected_kernels.obj test_resurrected_kernels.cpp
if errorlevel 1 (
    echo [ERROR] Compilation failed
    exit /b 1
)
echo [OK] test_resurrected_kernels.obj
echo.

REM Link with legacy kernels
echo [2/2] Linking with Sovereign_Legacy_Kernels.lib...
link.exe /OUT:test_resurrected_kernels.exe test_resurrected_kernels.obj Sovereign_Legacy_Kernels.lib kernel32.lib /SUBSYSTEM:CONSOLE /NODEFAULTLIB:uuid.lib
if errorlevel 1 (
    echo [ERROR] Linking failed
    exit /b 1
)
echo [OK] test_resurrected_kernels.exe
echo.

echo ============================================
echo Build Complete
echo ============================================
echo.
echo Running validation test...
echo.
test_resurrected_kernels.exe
echo.
