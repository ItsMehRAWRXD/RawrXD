@echo off
REM Sovereign Pipeline — Complete MASM-to-Executable Build
REM Usage: sovereign_pipeline.bat <input.asm> [output.exe]

setlocal EnableDelayedExpansion

REM Configuration
set "TOOLCHAIN_DIR=D:\rawrxd-ci-bootstrap\toolchain\from_scratch"
set "PHASE1_DIR=%TOOLCHAIN_DIR%\phase1_assembler"
set "PHASE2_DIR=%TOOLCHAIN_DIR%\phase2_linker"
set "BUILD_DIR=D:\rawrxd-ci-bootstrap\build\sovereign"

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

set "INPUT_FILE=%~1"
set "OUTPUT_FILE=%~2"

if "%INPUT_FILE%"=="" (
    echo Usage: %~nx0 ^<input.asm^> [output.exe]
    exit /b 1
)

if "%OUTPUT_FILE%"=="" (
    set "OUTPUT_FILE=%BUILD_DIR%\%~n1.exe"
)

set "PREPROCESSED=%BUILD_DIR%\%~n1_pre.asm"
set "OBJECT_FILE=%BUILD_DIR%\%~n1.obj"

echo.
echo ============================================
echo SOVEREIGN PIPELINE
echo ============================================
echo Input:    %INPUT_FILE%
echo Output:   %OUTPUT_FILE%
echo.

REM Step 1: Preprocess MASM syntax
echo [1/3] Preprocessing MASM directives...
"%PHASE1_DIR%\masm_preprocessor_full.exe" "%INPUT_FILE%" "%PREPROCESSED%" >nul 2>&1
if errorlevel 1 (
    echo ERROR: Preprocessing failed
    exit /b 1
)
echo         Preprocessed -^> %PREPROCESSED%

REM Step 2: Assemble with custom toolchain
echo [2/3] Assembling with RawrXD Phase 1...
"%PHASE1_DIR%\build\rawrxd_asm.exe" "%PREPROCESSED%" -o "%OBJECT_FILE%" -v
if errorlevel 1 (
    echo ERROR: Assembly failed
    exit /b 1
)
echo         Object file  -^> %OBJECT_FILE%

REM Step 3: Link with Phase 2 linker
echo [3/3] Linking with RawrXD Phase 2...
"%PHASE2_DIR%\build_dbg\rawrxd_link.exe" -o "%OUTPUT_FILE%" "%OBJECT_FILE%"
if errorlevel 1 (
    echo ERROR: Linking failed
    exit /b 1
)
echo         Executable   -^> %OUTPUT_FILE%

echo.
echo ============================================
echo SOVEREIGN BUILD COMPLETE
echo ============================================
echo.

REM Verify output exists
if exist "%OUTPUT_FILE%" (
    echo SUCCESS: %OUTPUT_FILE% created
    dir "%OUTPUT_FILE%" | findstr "exe"
) else (
    echo ERROR: Output file not created
    exit /b 1
)

exit /b 0
