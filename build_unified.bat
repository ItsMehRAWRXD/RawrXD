@echo off
setlocal enabledelayedexpansion

echo ============================================================================
echo RawrXD Unified Build - Environment Initialized
echo ============================================================================

:: 1. Initialize Visual Studio Environment
call "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvarsall.bat" x64
if %errorlevel% neq 0 (
    echo Error: Could not initialize MSVC environment.
    exit /b 1
)

:: 2. Setup paths
set BUILD_DIR=d:\rawrxd\build-master
set BIN_DIR=%BUILD_DIR%\bin
set ASM_DIR=d:\rawrxd\src\asm

if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"

echo [BUILD] Assembling core modules...

:: 3. Assemble core modules (not all *.asm, just the ones we need)
ml64 /c /Zi /W3 /nologo /Fo"%BUILD_DIR%\input_handler.obj" "%ASM_DIR%\input_handler.asm"
if !errorlevel! neq 0 exit /b 1

ml64 /c /Zi /W3 /nologo /Fo"%BUILD_DIR%\wndproc_input_bridge.obj" "%ASM_DIR%\wndproc_input_bridge.asm"
if !errorlevel! neq 0 exit /b 1

ml64 /c /Zi /W3 /nologo /Fo"%BUILD_DIR%\memory.obj" "%ASM_DIR%\memory.asm"
if !errorlevel! neq 0 exit /b 1

ml64 /c /Zi /W3 /nologo /Fo"%BUILD_DIR%\debug_event_ring.obj" "%ASM_DIR%\debug_event_ring.asm"
if !errorlevel! neq 0 exit /b 1

ml64 /c /Zi /W3 /nologo /Fo"%BUILD_DIR%\ide_debug_bridge.obj" "%ASM_DIR%\ide_debug_bridge.asm"
if !errorlevel! neq 0 exit /b 1

ml64 /c /Zi /W3 /nologo /Fo"%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" "%ASM_DIR%\RawrXD_UnifiedDebugger.asm"
if !errorlevel! neq 0 exit /b 1

ml64 /c /Zi /W3 /nologo /Fo"%BUILD_DIR%\syntax_highlight.obj" "%ASM_DIR%\syntax_highlight.asm"
if !errorlevel! neq 0 exit /b 1

echo [BUILD] Linking unified DLL...

:: 4. Link (Unified) with /MT for static CRT
link /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain /MT ^
    /OUT:"%BIN_DIR%\RawrXD_Unified.dll" ^
    "%BUILD_DIR%\input_handler.obj" ^
    "%BUILD_DIR%\wndproc_input_bridge.obj" ^
    "%BUILD_DIR%\memory.obj" ^
    "%BUILD_DIR%\debug_event_ring.obj" ^
    "%BUILD_DIR%\ide_debug_bridge.obj" ^
    "%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" ^
    "%BUILD_DIR%\syntax_highlight.obj" ^
    kernel32.lib user32.lib

if %errorlevel% neq 0 (
    echo [ERROR] Link failed
    exit /b 1
)

echo ============================================================================
echo Build Complete
echo ============================================================================

if exist "%BIN_DIR%\RawrXD_Unified.dll" (
    echo [SUCCESS] %BIN_DIR%\RawrXD_Unified.dll
    for %%F in ("%BIN_DIR%\RawrXD_Unified.dll") do echo [SIZE] %%~zF bytes
)

endlocal