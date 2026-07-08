@echo off
::=============================================================================
:: build_integration.bat - Build Native Toolchain Integration Components
:: Part of RawrXD Native Toolchain - RE Integration
::=============================================================================

setlocal enabledelayedexpansion

echo =============================================================================
echo   RawrXD Native Toolchain - Integration Build
echo =============================================================================
echo.

set "ROOT_DIR=%~dp0.."
set "BUILD_DIR=%ROOT_DIR%\integration_build"
set "OUT_DIR=%BUILD_DIR%\output"

:: Create output directory
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

:: Find compiler
set "CC=gcc.exe"
where gcc.exe > nul 2>&1
if errorlevel 1 (
    echo [ERROR] gcc.exe not found. Please ensure MinGW is installed and in PATH.
    exit /b 1
)

echo [INFO] Compiler: %CC%
echo [INFO] Output: %OUT_DIR%
echo.

::=============================================================================
:: Build Integration Components
::=============================================================================

echo [STEP 1/4] Building Codex-Native Bridge...
%CC% -O2 -Wall -o "%OUT_DIR%\codex_native_bridge.exe" "%ROOT_DIR%\codex_native_bridge.c"

if errorlevel 1 (
    echo [FAILED] codex_native_bridge.exe
    exit /b 1
)
echo [SUCCESS] codex_native_bridge.exe
echo.

echo [STEP 2/4] Building RawrXDCompiler Backend...
%CC% -O2 -Wall -o "%OUT_DIR%\rawrxd_compiler_backend.exe" "%ROOT_DIR%\rawrxd_compiler_backend.c"

if errorlevel 1 (
    echo [FAILED] rawrxd_compiler_backend.exe
    exit /b 1
)
echo [SUCCESS] rawrxd_compiler_backend.exe
echo.

echo [STEP 3/4] Building Binary Patch Pipeline...
%CC% -O2 -Wall -o "%OUT_DIR%\binary_patch_pipeline.exe" "%ROOT_DIR%\binary_patch_pipeline.c"

if errorlevel 1 (
    echo [FAILED] binary_patch_pipeline.exe
    exit /b 1
)
echo [SUCCESS] binary_patch_pipeline.exe
echo.

::=============================================================================
:: Verify Core Tools Exist
::=============================================================================

echo [STEP 4/4] Verifying core toolchain components...
echo.

set "CORE_TOOLS=minimal_assembler.exe minimal_linker.exe linker_with_imports.exe c_compiler_minimal.exe"
set "ALL_FOUND=1"

for %%t in (%CORE_TOOLS%) do (
    if exist "%ROOT_DIR%\%%t" (
        echo   [OK] %%t
    ) else (
        echo   [MISSING] %%t
        set "ALL_FOUND=0"
    )
)

echo.

::=============================================================================
:: Integration Test
::=============================================================================

if "%ALL_FOUND%"=="1" (
    echo [INFO] Running integration test...
    echo.
    
    :: Create test assembly
    echo ; Test assembly for integration > "%OUT_DIR%\test_integration.asm"
    echo .code >> "%OUT_DIR%\test_integration.asm"
    echo _start: >> "%OUT_DIR%\test_integration.asm"
    echo     xor rax, rax >> "%OUT_DIR%\test_integration.asm"
    echo     inc rax >> "%OUT_DIR%\test_integration.asm"
    echo     ret >> "%OUT_DIR%\test_integration.asm"
    
    :: Compile using native backend
    echo [TEST] Compiling test assembly...
    "%OUT_DIR%\rawrxd_compiler_backend.exe" "%OUT_DIR%\test_integration.asm" "%OUT_DIR%\test_integration.exe"
    
    if exist "%OUT_DIR%\test_integration.exe" (
        echo [SUCCESS] Integration test passed!
        echo   Input:  test_integration.asm
        echo   Output: test_integration.exe
    ) else (
        echo [FAILED] Integration test failed
    )
) else (
    echo [WARNING] Some core tools missing. Build them first:
    echo   - minimal_assembler.c -> minimal_assembler.exe
    echo   - linker_with_imports.c -> linker_with_imports.exe
    echo   - c_compiler_minimal.c -> c_compiler_minimal.exe
)

echo.
echo =============================================================================
echo   Build Complete
echo =============================================================================
echo.
echo Output files in: %OUT_DIR%
echo.
echo Next steps:
echo   1. Test: %OUT_DIR%\codex_native_bridge.exe /convert disasm.txt output.asm
echo   2. Compile: %OUT_DIR%\rawrxd_compiler_backend.exe code.asm output.exe
echo   3. Patch: %OUT_DIR%\binary_patch_pipeline.exe /patch in.exe out.exe
echo.

endlocal
