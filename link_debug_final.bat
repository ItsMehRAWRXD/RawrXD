@echo off
setlocal enabledelayedexpansion

echo ==============================================================================
echo Debug Event Pipeline Linker
echo ==============================================================================

call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1

if errorlevel 1 (
    echo [ERROR] Failed to initialize VS environment
    exit /b 1
)

echo [LINK] Environment initialized

set "MASM_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "SRC_DIR=d:\rawrxd\src\asm"
set "BUILD_DIR=d:\rawrxd\build-debug-pipeline"
set "OUT_DIR=%BUILD_DIR%\bin"

if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

echo [ASM] Assembling debug_event_ring.asm...
"%MASM_PATH%\ml64.exe" /c /Zi /Zf /W3 /nologo /Fo"%BUILD_DIR%\debug_event_ring.obj" "%SRC_DIR%\debug_event_ring.asm"
if errorlevel 1 (
    echo [ERROR] Failed to assemble debug_event_ring.asm
    exit /b 1
)

echo [ASM] Assembling ide_debug_bridge.asm...
"%MASM_PATH%\ml64.exe" /c /Zi /Zf /W3 /nologo /Fo"%BUILD_DIR%\ide_debug_bridge.obj" "%SRC_DIR%\ide_debug_bridge.asm"
if errorlevel 1 (
    echo [ERROR] Failed to assemble ide_debug_bridge.asm
    exit /b 1
)

echo [ASM] Assembling RawrXD_UnifiedDebugger.asm...
"%MASM_PATH%\ml64.exe" /c /Zi /Zf /W3 /nologo /Fo"%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" "%SRC_DIR%\RawrXD_UnifiedDebugger.asm"
if errorlevel 1 (
    echo [ERROR] Failed to assemble RawrXD_UnifiedDebugger.asm
    exit /b 1
)

echo [ASM] Assembling RawrXD_Debug_Engine.asm...
"%MASM_PATH%\ml64.exe" /c /Zi /Zf /W3 /nologo /Fo"%BUILD_DIR%\RawrXD_Debug_Engine.obj" "%SRC_DIR%\RawrXD_Debug_Engine.asm"
if errorlevel 1 (
    echo [ERROR] Failed to assemble RawrXD_Debug_Engine.asm
    exit /b 1
)

echo [ASM] Assembling debug_dllmain.asm...
"%MASM_PATH%\ml64.exe" /c /Zi /Zf /W3 /nologo /Fo"%BUILD_DIR%\debug_dllmain.obj" "%SRC_DIR%\debug_dllmain.asm"
if errorlevel 1 (
    echo [ERROR] Failed to assemble debug_dllmain.asm
    exit /b 1
)

echo [LINK] Linking debug_pipeline.dll...

link.exe /DLL /DEBUG /INCREMENTAL:NO /LARGEADDRESSAWARE:NO /ENTRY:DllMain ^
    /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" ^
    /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" ^
    /OUT:"%OUT_DIR%\debug_pipeline.dll" ^
    "%BUILD_DIR%\debug_dllmain.obj" ^
    "%BUILD_DIR%\debug_event_ring.obj" ^
    "%BUILD_DIR%\ide_debug_bridge.obj" ^
    "%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" ^
    kernel32.lib gdi32.lib

if errorlevel 1 (
    echo [ERROR] Linker failed with exit code %ERRORLEVEL%
    exit /b 1
)

echo [SUCCESS] Build complete
dir "%OUT_DIR%\*.dll" 2>nul

endlocal