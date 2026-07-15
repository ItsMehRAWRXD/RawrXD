@echo off
:: Build Titan Kernel Integration
:: Links Titan dispatch layer with real Sovereign kernels
::
:: Date: July 10, 2026

setlocal enabledelayedexpansion

echo ============================================================================
echo Titan Kernel Integration Build
echo ============================================================================
echo.

:: Configuration
set SRC_DIR=d:\rawrxd\src\core\execution
set ASM_DIR=d:\src\asm
set OUT_DIR=d:\rawrxd\bin
set VS_ROOT=C:\Program Files\Microsoft Visual Studio\18\Enterprise
set MSVC_VER=14.51.36231
set "VS_TOOLS=%VS_ROOT%\VC\Tools\MSVC\%MSVC_VER%\bin\Hostx64\x64"

:: Create output directory
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

:: Setup VS environment
set "INCLUDE=%VS_ROOT%\VC\Tools\MSVC\%MSVC_VER%\include;%INCLUDE%"
set "LIB=%VS_ROOT%\VC\Tools\MSVC\%MSVC_VER%\lib\x64;%LIB%"
set "PATH=%VS_TOOLS%;%PATH%"

:: Tool paths (quoted for spaces)
set "CL=%VS_TOOLS%\cl.exe"
set "LINK=%VS_TOOLS%\link.exe"

:: Include paths
set INCLUDES=/I"%ASM_DIR%" /I"%SRC_DIR%"

:: Compiler flags
set CFLAGS=/c /O2 /arch:AVX2 /W3 /nologo /EHsc /MD %INCLUDES%

:: Linker flags
set LFLAGS=/SUBSYSTEM:CONSOLE /NODEFAULTLIB:libcmt.lib /LARGEADDRESSAWARE

:: Library files to link
set LIBS="%ASM_DIR%\Sovereign_Intrinsics.lib"
set LIBS=%LIBS% "%ASM_DIR%\Sovereign_RMSNorm.lib"
set LIBS=%LIBS% "%ASM_DIR%\Sovereign_RoPE.lib"
set LIBS=%LIBS% "%ASM_DIR%\Sovereign_LayerNorm.lib"
set LIBS=%LIBS% "%ASM_DIR%\Sovereign_ResidualAdd.lib"
set LIBS=%LIBS% "%ASM_DIR%\Sovereign_Q4K_Dequant.lib"
set LIBS=%LIBS% "%ASM_DIR%\Sovereign_Legacy_Kernels.lib"
set LIBS=%LIBS% kernel32.lib user32.lib

echo [1/3] Compiling Titan_KernelIntegration.cpp...
"%CL%" %CFLAGS% /Fo"%OUT_DIR%\Titan_KernelIntegration.obj" "%SRC_DIR%\Titan_KernelIntegration.cpp" 2>&1
if errorlevel 1 (
    echo ERROR: Compilation failed!
    exit /b 1
)
echo     OK: Titan_KernelIntegration.obj

echo.
echo [2/3] Creating Titan_KernelIntegration.lib...
:: Create static library from object
"%VS_TOOLS%\lib.exe" /nologo /out:"%OUT_DIR%\Titan_KernelIntegration.lib" "%OUT_DIR%\Titan_KernelIntegration.obj"
if errorlevel 1 (
    echo ERROR: Library creation failed!
    exit /b 1
)
echo     OK: Titan_KernelIntegration.lib

echo.
echo [3/3] Building test executable...
:: Compile test
"%CL%" %CFLAGS% /Fo"%OUT_DIR%\test_titan_integration.obj" "%SRC_DIR%\..\....\test_titan_integration.cpp" 2>nul
if exist "%OUT_DIR%\test_titan_integration.obj" (
    "%LINK%" %LFLAGS% /OUT:"%OUT_DIR%\test_titan_integration.exe" ^
        "%OUT_DIR%\test_titan_integration.obj" ^
        "%OUT_DIR%\Titan_KernelIntegration.obj" ^
        %LIBS%
    if errorlevel 1 (
        echo     WARNING: Test executable link failed (may need test file)
    ) else (
        echo     OK: test_titan_integration.exe
    )
) else (
    echo     INFO: No test file found, skipping test executable
)

echo.
echo ============================================================================
echo Build Complete
echo ============================================================================
echo.
echo Output files:
dir /b "%OUT_DIR%\Titan_KernelIntegration.*" 2^>nul
echo.
echo Libraries linked:
echo   - Sovereign_Intrinsics.lib (Phase 7B)
echo   - Sovereign_RMSNorm.lib
echo   - Sovereign_RoPE.lib
echo   - Sovereign_LayerNorm.lib
echo   - Sovereign_ResidualAdd.lib
echo   - Sovereign_Q4K_Dequant.lib
echo   - Sovereign_Legacy_Kernels.lib (Phase 7A)
echo.
echo Next steps:
echo   1. Replace TitanStubs.cpp with Titan_KernelIntegration.cpp in your build
echo   2. Link against Titan_KernelIntegration.lib
echo   3. Call Titan_InitializeKernelSystem() before using kernels
echo   4. Use Titan_ExecuteComputeKernel() with real computation
echo.

endlocal
