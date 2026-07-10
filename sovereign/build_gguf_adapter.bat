@echo off
REM ============================================================================
REM Build Script for GGUF Adapter (Sovereign Fabricator)
REM ============================================================================

echo Building GGUF Adapter for Sovereign Fabricator...
echo.

REM Initialize Visual Studio environment
set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build"
if not exist "%VS_PATH%\vcvars64.bat" (
    set "VS_PATH=C:\VS2022Enterprise\VC\Auxiliary\Build"
)
if not exist "%VS_PATH%\vcvars64.bat" (
    echo ERROR: Could not find vcvars64.bat
    echo Please ensure Visual Studio 2022 is installed
    exit /b 1
)
call "%VS_PATH%\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
    echo ERROR: Failed to initialize VS environment
    exit /b 1
)

REM Set paths
set "OUT_DIR=D:\rawrxd\sovereign\build"
set "SRC_DIR=D:\rawrxd\sovereign"

REM Create output directory
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

REM Assemble the MASM source
echo [1/3] Assembling gguf_adapter_fixed.asm...
ml64.exe /c /Fo"%OUT_DIR%\gguf_adapter.obj" /W3 /Zi "%SRC_DIR%\gguf_adapter_fixed.asm"
if errorlevel 1 (
    echo ERROR: Assembly failed!
    exit /b 1
)

REM Create static library
echo [2/3] Creating static library...
lib.exe /OUT:"%OUT_DIR%\gguf_adapter.lib" /MACHINE:X64 "%OUT_DIR%\gguf_adapter.obj"
if errorlevel 1 (
    echo ERROR: Library creation failed!
    exit /b 1
)

REM Create test program
echo [3/3] Building test program...
cl.exe /nologo /O2 /W4 /EHsc /I"%SRC_DIR%" /Fe"%OUT_DIR%\test_gguf_adapter.exe" /Fo"%OUT_DIR%\test_gguf_adapter.obj" "%SRC_DIR%\test_gguf_adapter.cpp" /link "%OUT_DIR%\gguf_adapter.lib" kernel32.lib
if errorlevel 1 (
    echo WARNING: Test program build failed, but core library succeeded.
)

echo.
echo ============================================================================
echo Build SUCCESSFUL!
echo.
echo Output files:
echo   - %OUT_DIR%\gguf_adapter.lib   (Static library)
echo   - %OUT_DIR%\gguf_adapter.obj   (Object file)
echo   - %OUT_DIR%\test_gguf_adapter.exe (Test executable)
echo.
echo To test:
echo   %OUT_DIR%\test_gguf_adapter.exe D:\test_model.gguf
echo ============================================================================

exit /b 0
