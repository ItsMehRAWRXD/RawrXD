@echo off
REM ============================================================================
REM build_editor_pipeline.bat - Build script for MASM32 Editor Input Pipeline
REM ============================================================================
REM Builds the complete editor input handling system:
REM   - input_handler.asm (input event queue)
REM   - wndproc_input_bridge.asm (Win32 message bridge)
REM   - editor.asm (gap buffer editor)
REM   - memory.asm (heap allocation)
REM
REM Tool: ml64.exe (MASM x64)
REM Link: link.exe (MSVC linker)
REM ============================================================================

setlocal enabledelayedexpansion

REM ============================================================================
REM Configuration
REM ============================================================================

set "MASM_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "WINSDK_PATH=C:\Program Files (x86)\Windows Kits\10"
set "WINSDK_VER=10.0.22621.0"

set "ML64=%MASM_PATH%\ml64.exe"
set "LINK=%MASM_PATH%\link.exe"

set "SRC_DIR=d:\rawrxd\src\asm"
set "KERNEL_DIR=d:\rawrxd\kernels\editor"
set "BUILD_DIR=d:\rawrxd\build-editor-pipeline"
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
set "INCLUDE_PATH=%INCLUDE_PATH%;%KERNEL_DIR%"

REM Set up library paths
set "LIB_PATH=%MASM_PATH%\lib\x64"
set "LIB_PATH=%LIB_PATH%;%WINSDK_PATH%\Lib\%WINSDK_VER%\um\x64"
set "LIB_PATH=%LIB_PATH%;%WINSDK_PATH%\Lib\%WINSDK_VER%\ucrt\x64"

REM ============================================================================
REM Assemble
REM ============================================================================

echo [BUILD] Assembling input_handler.asm...
"%ML64%" /c /Zi /Zf /W3 /nologo /I"%INCLUDE_PATH%" /Fo"%BUILD_DIR%\input_handler.obj" "%SRC_DIR%\input_handler.asm"
if errorlevel 1 (
    echo [ERROR] Failed to assemble input_handler.asm
    exit /b 1
)

echo [BUILD] Assembling wndproc_input_bridge.asm...
"%ML64%" /c /Zi /Zf /W3 /nologo /I"%INCLUDE_PATH%" /Fo"%BUILD_DIR%\wndproc_input_bridge.obj" "%SRC_DIR%\wndproc_input_bridge.asm"
if errorlevel 1 (
    echo [ERROR] Failed to assemble wndproc_input_bridge.asm
    exit /b 1
)

echo [BUILD] Assembling editor.asm...
"%ML64%" /c /Zi /Zf /W3 /nologo /I"%INCLUDE_PATH%" /Fo"%BUILD_DIR%\editor.obj" "%KERNEL_DIR%\editor.asm"
if errorlevel 1 (
    echo [ERROR] Failed to assemble editor.asm
    exit /b 1
)

echo [BUILD] Assembling memory.asm...
"%ML64%" /c /Zi /Zf /W3 /nologo /I"%INCLUDE_PATH%" /Fo"%BUILD_DIR%\memory.obj" "%SRC_DIR%\memory.asm"
if errorlevel 1 (
    echo [ERROR] Failed to assemble memory.asm
    exit /b 1
)

REM ============================================================================
REM Link
REM ============================================================================

echo [BUILD] Linking editor_pipeline.dll...

"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain ^
    /LIBPATH:"%MASM_PATH%\lib\x64" ^
    /LIBPATH:"%WINSDK_PATH%\Lib\%WINSDK_VER%\um\x64" ^
    /LIBPATH:"%WINSDK_PATH%\Lib\%WINSDK_VER%\ucrt\x64" ^
    /OUT:"%OUT_DIR%\editor_pipeline.dll" ^
    /PDB:"%OUT_DIR%\editor_pipeline.pdb" ^
    "%BUILD_DIR%\input_handler.obj" ^
    "%BUILD_DIR%\wndproc_input_bridge.obj" ^
    "%BUILD_DIR%\editor.obj" ^
    "%BUILD_DIR%\memory.obj" ^
    user32.lib kernel32.lib gdi32.lib

if errorlevel 1 (
    echo [ERROR] Failed to link editor_pipeline.dll
    exit /b 1
)

echo [BUILD] Linking editor_pipeline.exe (standalone test)...

"%LINK%" /SUBSYSTEM:WINDOWS /DEBUG /INCREMENTAL:NO /ENTRY:WinMain ^
    /LIBPATH:"%MASM_PATH%\lib\x64" ^
    /LIBPATH:"%WINSDK_PATH%\Lib\%WINSDK_VER%\um\x64" ^
    /LIBPATH:"%WINSDK_PATH%\Lib\%WINSDK_VER%\ucrt\x64" ^
    /OUT:"%OUT_DIR%\editor_pipeline.exe" ^
    /PDB:"%OUT_DIR%\editor_pipeline.pdb" ^
    "%BUILD_DIR%\input_handler.obj" ^
    "%BUILD_DIR%\wndproc_input_bridge.obj" ^
    "%BUILD_DIR%\editor.obj" ^
    "%BUILD_DIR%\memory.obj" ^
    user32.lib kernel32.lib gdi32.lib

if errorlevel 1 (
    echo [ERROR] Failed to link editor_pipeline.exe
    exit /b 1
)

REM ============================================================================
REM Verify
REM ============================================================================

echo [BUILD] Verifying output...

if exist "%OUT_DIR%\editor_pipeline.dll" (
    echo [SUCCESS] Built: %OUT_DIR%\editor_pipeline.dll
    for %%F in ("%OUT_DIR%\editor_pipeline.dll") do echo [SIZE] %%~zF bytes
)

if exist "%OUT_DIR%\editor_pipeline.exe" (
    echo [SUCCESS] Built: %OUT_DIR%\editor_pipeline.exe
    for %%F in ("%OUT_DIR%\editor_pipeline.exe") do echo [SIZE] %%~zF bytes
)

echo [BUILD] Editor pipeline build complete!
echo [BUILD] Output directory: %OUT_DIR%

exit /b 0