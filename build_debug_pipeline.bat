@echo off
REM ============================================================================
REM build_debug_pipeline.bat - Build script for Debug Event Pipeline
REM ============================================================================
REM Builds the debug event ring buffer and IDE bridge modules:
REM   - debug_event_ring.asm (lock-free SPSC ring buffer)
REM   - ide_debug_bridge.asm (IDE UI thread consumer)
REM
REM Tool: ml64.exe (MASM x64)
REM Link: link.exe (MSVC linker)
REM ============================================================================

setlocal enabledelayedexpansion

echo ==============================================================================
echo Debug Event Pipeline Build
echo ==============================================================================

REM ============================================================================
REM Configuration
REM ============================================================================

set "MASM_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "WINSDK_PATH=C:\Program Files (x86)\Windows Kits\10"
set "WINSDK_VER=10.0.22621.0"

set "ML64=%MASM_PATH%\ml64.exe"
set "LINK=%MASM_PATH%\link.exe"

set "SRC_DIR=d:\rawrxd\src\asm"
set "BUILD_DIR=d:\rawrxd\build-debug-pipeline"
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

echo [ASM] Assembling debug_event_ring.asm...
"%ML64%" /c /Zi /Zf /W3 /nologo /I"%INCLUDE_PATH%" /Fo"%BUILD_DIR%\debug_event_ring.obj" "%SRC_DIR%\debug_event_ring.asm"
if errorlevel 1 (
    echo [ERROR] Failed to assemble debug_event_ring.asm
    exit /b 1
)

echo [ASM] Assembling ide_debug_bridge.asm...
"%ML64%" /c /Zi /Zf /W3 /nologo /I"%INCLUDE_PATH%" /Fo"%BUILD_DIR%\ide_debug_bridge.obj" "%SRC_DIR%\ide_debug_bridge.asm"
if errorlevel 1 (
    echo [ERROR] Failed to assemble ide_debug_bridge.asm
    exit /b 1
)

echo [ASM] Assembling RawrXD_UnifiedDebugger.asm...
"%ML64%" /c /Zi /Zf /W3 /nologo /I"%INCLUDE_PATH%" /Fo"%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" "%SRC_DIR%\RawrXD_UnifiedDebugger.asm"
if errorlevel 1 (
    echo [ERROR] Failed to assemble RawrXD_UnifiedDebugger.asm
    exit /b 1
)

echo [ASM] Assembling RawrXD_Debug_Engine.asm...
"%ML64%" /c /Zi /Zf /W3 /nologo /I"%INCLUDE_PATH%" /Fo"%BUILD_DIR%\RawrXD_Debug_Engine.obj" "%SRC_DIR%\RawrXD_Debug_Engine.asm"
if errorlevel 1 (
    echo [ERROR] Failed to assemble RawrXD_Debug_Engine.asm
    exit /b 1
)

REM ============================================================================
REM Link
REM ============================================================================

echo [LINK] Linking debug_pipeline.dll...

"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain ^
    /LIBPATH:"%LIB_PATH%" ^
    /OUT:"%OUT_DIR%\debug_pipeline.dll" ^
    /PDB:"%OUT_DIR%\debug_pipeline.pdb" ^
    "%BUILD_DIR%\debug_event_ring.obj" ^
    "%BUILD_DIR%\ide_debug_bridge.obj" ^
    "%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" ^
    "%BUILD_DIR%\RawrXD_Debug_Engine.obj" ^
    kernel32.lib

if errorlevel 1 (
    echo [ERROR] Failed to link debug_pipeline.dll
    exit /b 1
)

echo [LINK] Linking debug_pipeline.exe (standalone test)...

"%LINK%" /SUBSYSTEM:CONSOLE /DEBUG /INCREMENTAL:NO /ENTRY:mainCRTStartup ^
    /LIBPATH:"%LIB_PATH%" ^
    /OUT:"%OUT_DIR%\debug_pipeline.exe" ^
    /PDB:"%OUT_DIR%\debug_pipeline.pdb" ^
    "%BUILD_DIR%\debug_event_ring.obj" ^
    "%BUILD_DIR%\ide_debug_bridge.obj" ^
    "%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" ^
    "%BUILD_DIR%\RawrXD_Debug_Engine.obj" ^
    kernel32.lib

if errorlevel 1 (
    echo [ERROR] Failed to link debug_pipeline.exe
    exit /b 1
)

REM ============================================================================
REM Verify
REM ============================================================================

echo [BUILD] Verifying output...

if exist "%OUT_DIR%\debug_pipeline.dll" (
    echo [SUCCESS] Built: %OUT_DIR%\debug_pipeline.dll
    for %%F in ("%OUT_DIR%\debug_pipeline.dll") do echo [SIZE] %%~zF bytes
)

if exist "%OUT_DIR%\debug_pipeline.exe" (
    echo [SUCCESS] Built: %OUT_DIR%\debug_pipeline.exe
    for %%F in ("%OUT_DIR%\debug_pipeline.exe") do echo [SIZE] %%~zF bytes
)

echo [BUILD] Debug pipeline build complete!
echo [BUILD] Output directory: %OUT_DIR%

exit /b 0