@echo off
setlocal enabledelayedexpansion

echo ==============================================================================
echo Syntax Highlighter Pipeline Build
echo ==============================================================================

REM ============================================================================
REM Configuration (Matching working debug_pipeline.bat)
REM ============================================================================

set "MASM_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "WINSDK_PATH=C:\Program Files (x86)\Windows Kits\10"
set "WINSDK_VER=10.0.22621.0"

set "ML64=%MASM_PATH%\ml64.exe"
set "LINK=%MASM_PATH%\link.exe"

REM Add linker directory to PATH (required for DLL dependencies)
set "PATH=%MASM_PATH%;%PATH%"

set "SRC_DIR=d:\rawrxd\src\asm"
set "BUILD_DIR=d:\rawrxd\build-syntax-pipeline"
set "OUT_DIR=%BUILD_DIR%\bin"

REM ============================================================================
REM Setup
REM ============================================================================

echo [BUILD] Setting up build environment...

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

REM Set up include paths
set "INCLUDE_PATH=%MASM_PATH%\include"
set "INCLUDE_PATH=%INCLUDE_PATH%;%WINSDK_PATH%\Include\%WINSDK_VER%\um"
set "INCLUDE_PATH=%INCLUDE_PATH%;%WINSDK_PATH%\Include\%WINSDK_VER%\shared"
set "INCLUDE_PATH=%INCLUDE_PATH%;%SRC_DIR%"

REM Set up library paths
set "LIB_PATH=%MASM_PATH%\lib\x64"
set "LIB_PATH=%LIB_PATH%;%WINSDK_PATH%\Lib\%WINSDK_VER%\um\x64"
set "LIB_PATH=%LIB_PATH%;%WINSDK_PATH%\Lib\%WINSDK_VER%\ucrt\x64"

REM ============================================================================
REM Assemble
REM ============================================================================

echo [ASM] Assembling syntax_highlight.asm...
"%ML64%" /c /Zi /Zf /W3 /nologo /I"%INCLUDE_PATH%" /Fo"%BUILD_DIR%\syntax_highlight.obj" "%SRC_DIR%\syntax_highlight.asm"
if errorlevel 1 (
    echo [ERROR] Failed to assemble syntax_highlight.asm
    exit /b 1
)

REM ============================================================================
REM Link
REM ============================================================================

echo [LINK] Linking syntax_pipeline.dll...

"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain ^
    /LIBPATH:"%LIB_PATH%" ^
    /OUT:"%OUT_DIR%\syntax_pipeline.dll" ^
    /PDB:"%OUT_DIR%\syntax_pipeline.pdb" ^
    "%BUILD_DIR%\syntax_highlight.obj" ^
    kernel32.lib user32.lib

if errorlevel 1 (
    echo [ERROR] Linker failed with exit code %ERRORLEVEL%
    exit /b 1
)

REM ============================================================================
REM Verify
REM ============================================================================

echo [BUILD] Verifying output...

if exist "%OUT_DIR%\syntax_pipeline.dll" (
    echo [SUCCESS] Built: %OUT_DIR%\syntax_pipeline.dll
    for %%F in ("%OUT_DIR%\syntax_pipeline.dll") do echo [SIZE] %%~zF bytes
    echo.
    echo Exports:
    echo   - GetVTable (returns SYNTAX_HIGHLIGHTER_VTABLE*)
    echo.
    echo VTable Functions:
    echo   - Syntax_Init
    echo   - Syntax_Shutdown
    echo   - Syntax_ScanLine
    echo   - Syntax_ScanAll
    echo   - Syntax_InvalidateLine
    echo   - Syntax_GetTokenAt
    echo   - Syntax_GetLineTokens
    echo   - Syntax_AddKeyword
    echo   - Syntax_LoadKeywords
    echo   - Syntax_GetStats
) else (
    echo [ERROR] Output file not found
    exit /b 1
)

echo [BUILD] Syntax pipeline build complete!
echo [BUILD] Output directory: %OUT_DIR%

exit /b 0