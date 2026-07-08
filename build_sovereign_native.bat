@echo off
REM =============================================================================
REM build_sovereign_native.bat
REM Build Sovereign Engine with Native Toolchain (no MSVC)
REM =============================================================================

setlocal EnableDelayedExpansion

REM Configuration
set "PROJECT_ROOT=D:\rawrxd"
set "BUILD_DIR=%PROJECT_ROOT%\build-sovereign-native"
set "SRC_DIR=%PROJECT_ROOT%\src"
set "ASM_DIR=%PROJECT_ROOT%\src\asm"
set "CORE_DIR=%PROJECT_ROOT%\src\core"
set "TOOLCHAIN=%PROJECT_ROOT%\compilers\native_toolchain"

REM Native toolchain
set "NASM=%TOOLCHAIN%\rawrxd_native_assembler.exe"
set "NLINK=%TOOLCHAIN%\rawrxd_native_linker.exe"

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%BUILD_DIR%\obj" mkdir "%BUILD_DIR%\obj"

echo.
echo =============================================================================
echo Sovereign Engine - Native Toolchain Build
echo Using: rawrxd_native_assembler + rawrxd_native_linker
echo =============================================================================

REM =============================================================================
REM Phase 1: Assemble ASM Components
REM =============================================================================

echo.
echo [Phase 1] Assembling x64 ASM Components...
echo -----------------------------------------------------------------------------

set "ASM_COMPONENTS=SovereignKernels dequant_simd inference_kernels"

for %%f in (%ASM_COMPONENTS%) do (
    if exist "%ASM_DIR%\%%f.asm" (
        echo   Assembling %%f.asm...
        "%NASM%" "%ASM_DIR%\%%f.asm" "%BUILD_DIR%\obj\%%f.obj"
        if errorlevel 1 (
            echo   WARNING: Failed to assemble %%f.asm
        ) else (
            echo   OK: %%f.obj
        )
    ) else (
        echo   WARNING: %%f.asm not found, skipping
    )
)

REM =============================================================================
REM Phase 2: Link Object Files
REM =============================================================================

echo.
echo [Phase 2] Linking Sovereign Engine...
echo -----------------------------------------------------------------------------

set "OBJ_FILES="
for %%f in (%BUILD_DIR%\obj\*.obj) do (
    set "OBJ_FILES=!OBJ_FILES! "%%f""
)

if "!OBJ_FILES!"=="" (
    echo ERROR: No object files to link
    exit /b 1
)

echo   Linking: sovereign_engine.exe...
"%NLINK%" !OBJ_FILES! /out:%BUILD_DIR%\sovereign_engine.exe
if errorlevel 1 (
    echo   ERROR: Link failed
    exit /b 1
)

echo   OK: sovereign_engine.exe created

REM =============================================================================
REM Verify Build
REM =============================================================================

echo.
echo [Verify] Checking output...
echo -----------------------------------------------------------------------------

if exist "%BUILD_DIR%\sovereign_engine.exe" (
    for %%F in ("%BUILD_DIR%\sovereign_engine.exe") do (
        echo   SUCCESS: sovereign_engine.exe (%%~zF bytes)
    )
    
    echo.
    echo   Object files:
    for %%f in (%BUILD_DIR%\obj\*.obj) do (
        for %%F in ("%%f") do (
            echo     %%~nf.obj (%%~zF bytes)
        )
    )
) else (
    echo   FAILED: sovereign_engine.exe not created
    exit /b 1
)

echo.
echo =============================================================================
echo Build Complete!
echo Output: %BUILD_DIR%\sovereign_engine.exe
echo =============================================================================

endlocal
