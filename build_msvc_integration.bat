@echo off
:: Build script for Titan Kernel Integration using MSVC
:: This links against the actual kernel .lib files

setlocal EnableDelayedExpansion

echo ╔══════════════════════════════════════════════════════════════╗
echo ║     TITAN KERNEL INTEGRATION BUILD (MSVC)                    ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.

:: Configuration
set "BUILD_DIR=d:\rawrxd\build_msvc"
set "SRC_DIR=d:\rawrxd\src"
set "ASM_DIR=d:\src\asm"
set "CXX=cl.exe"
set "CXXFLAGS=/std:c++17 /O2 /arch:AVX2 /DNDEBUG /D_WIN32 /EHsc /MP"
set "INCLUDES=/I%SRC_DIR% /I%ASM_DIR%"
set "LDFLAGS=/link /LIBPATH:%ASM_DIR%"

:: Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

:: Setup VS2022 environment
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat" 2>nul
if errorlevel 1 (
    call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" 2>nul
)
if errorlevel 1 (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" 2>nul
)
if errorlevel 1 (
    call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" 2>nul
)
if errorlevel 1 (
    echo WARNING: Could not find VS2022 vcvars64.bat
    echo Make sure VS2022 is installed
)

echo [1/5] Building UnifiedKernelInterface.cpp...
%CXX% %CXXFLAGS% %INCLUDES% /c "%SRC_DIR%\core\execution\UnifiedKernelInterface.cpp" /Fo"%BUILD_DIR%\UnifiedKernelInterface.obj" 2>&1
if errorlevel 1 (
    echo FAILED: UnifiedKernelInterface.cpp
    exit /b 1
)
echo ✓ UnifiedKernelInterface.obj
echo.

echo [2/5] Building MemoryBridge.cpp...
%CXX% %CXXFLAGS% %INCLUDES% /c "%SRC_DIR%\core\execution\MemoryBridge.cpp" /Fo"%BUILD_DIR%\MemoryBridge.obj" 2>&1
if errorlevel 1 (
    echo FAILED: MemoryBridge.cpp
    exit /b 1
)
echo ✓ MemoryBridge.obj
echo.

echo [3/5] Building Titan_KernelIntegration.cpp...
%CXX% %CXXFLAGS% %INCLUDES% /c "%SRC_DIR%\core\execution\Titan_KernelIntegration.cpp" /Fo"%BUILD_DIR%\Titan_KernelIntegration.obj" 2>&1
if errorlevel 1 (
    echo FAILED: Titan_KernelIntegration.cpp
    exit /b 1
)
echo ✓ Titan_KernelIntegration.obj
echo.

echo [4/5] Building Sovereign_KernelDispatch_Runtime.cpp...
%CXX% %CXXFLAGS% %INCLUDES% /c "%SRC_DIR%\core\execution\Sovereign_KernelDispatch_Runtime.cpp" /Fo"%BUILD_DIR%\Sovereign_KernelDispatch.obj" 2>&1
if errorlevel 1 (
    echo FAILED: Sovereign_KernelDispatch_Runtime.cpp
    exit /b 1
)
echo ✓ Sovereign_KernelDispatch.obj
echo.

echo [5/5] Building TitanCLI.exe with kernel libraries...
%CXX% %CXXFLAGS% %INCLUDES% "%SRC_DIR%\cli\TitanCLI.cpp" ^
    "%BUILD_DIR%\UnifiedKernelInterface.obj" ^
    "%BUILD_DIR%\MemoryBridge.obj" ^
    "%BUILD_DIR%\Titan_KernelIntegration.obj" ^
    "%BUILD_DIR%\Sovereign_KernelDispatch.obj" ^
    /Fe"%BUILD_DIR%\TitanCLI.exe" ^
    %LDFLAGS% ^
    Sovereign_Legacy_Kernels.lib ^
    Sovereign_Intrinsics.lib ^
    Sovereign_RMSNorm.lib ^
    Sovereign_ResidualAdd.lib ^
    Sovereign_RoPE.lib ^
    Sovereign_LayerNorm.lib ^
    Sovereign_Q4K_Dequant.lib ^
    2>&1
if errorlevel 1 (
    echo FAILED: TitanCLI.exe linking
    echo Attempting fallback build without kernel libs...
    goto fallback
)
echo ✓ TitanCLI.exe (with kernel linking)
goto complete

:fallback
echo.
echo Attempting build without kernel libraries (runtime loading mode)...
%CXX% %CXXFLAGS% %INCLUDES% "%SRC_DIR%\cli\TitanCLI.cpp" ^
    "%BUILD_DIR%\UnifiedKernelInterface.obj" ^
    "%BUILD_DIR%\MemoryBridge.obj" ^
    "%BUILD_DIR%\Titan_KernelIntegration.obj" ^
    "%BUILD_DIR%\Sovereign_KernelDispatch.obj" ^
    /Fe"%BUILD_DIR%\TitanCLI.exe" ^
    2>&1
if errorlevel 1 (
    echo FAILED: Fallback build also failed
    exit /b 1
)
echo ✓ TitanCLI.exe (runtime loading mode)

:complete
echo.
echo ╔══════════════════════════════════════════════════════════════╗
echo ║                    BUILD COMPLETE                              ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.
echo Output files:
echo   %BUILD_DIR%\TitanCLI.exe       - CLI tool with kernel support
echo.
echo Run tests:
echo   %BUILD_DIR%\TitanCLI.exe --status
echo   %BUILD_DIR%\TitanCLI.exe --test
echo   %BUILD_DIR%\TitanCLI.exe --benchmark
echo.

endlocal
