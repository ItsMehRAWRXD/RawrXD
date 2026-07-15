@echo off
setlocal enabledelayedexpansion

echo ============================================================================
echo RawrXD Master Build - All ASM Modules
echo ============================================================================

REM Tool paths
set "MASM_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "WINSDK_PATH=C:\Program Files (x86)\Windows Kits\10"
set "WINSDK_VER=10.0.22621.0"

set "ML64=%MASM_PATH%\ml64.exe"
set "LINK=%MASM_PATH%\link.exe"

set "SRC=d:\rawrxd\src\asm"
set "BUILD=d:\rawrxd\build-master"
set "OUT=%BUILD%\bin"

REM Create directories
if not exist "%BUILD%" mkdir "%BUILD%"
if not exist "%OUT%" mkdir "%OUT%"

REM Include paths
set "INC=%MASM_PATH%\include;%WINSDK_PATH%\Include\%WINSDK_VER%\um;%WINSDK_PATH%\Include\%WINSDK_VER%\shared;%SRC%"

REM Library paths  
set "LIB=%MASM_PATH%\lib\x64;%WINSDK_PATH%\Lib\%WINSDK_VER%\um\x64;%WINSDK_PATH%\Lib\%WINSDK_VER%\ucrt\x64"

echo [BUILD] Assembling core modules...

REM Editor Pipeline
echo [ASM] input_handler.asm..."%ML64%" /c /Zi /W3 /nologo /I"%INC%" /Fo"%BUILD%\input_handler.obj" "%SRC%\input_handler.asm" || exit /b 1
echo [ASM] wndproc_input_bridge.asm..."%ML64%" /c /Zi /W3 /nologo /I"%INC%" /Fo"%BUILD%\wndproc_input_bridge.obj" "%SRC%\wndproc_input_bridge.asm" || exit /b 1
echo [ASM] editor.asm..."%ML64%" /c /Zi /W3 /nologo /I"%INC%" /Fo"%BUILD%\editor.obj" "%SRC%\editor.asm" || exit /b 1
echo [ASM] memory.asm..."%ML64%" /c /Zi /W3 /nologo /I"%INC%" /Fo"%BUILD%\memory.obj" "%SRC%\memory.asm" || exit /b 1

REM Debug Pipeline
echo [ASM] debug_event_ring.asm..."%ML64%" /c /Zi /W3 /nologo /I"%INC%" /Fo"%BUILD%\debug_event_ring.obj" "%SRC%\debug_event_ring.asm" || exit /b 1
echo [ASM] ide_debug_bridge.asm..."%ML64%" /c /Zi /W3 /nologo /I"%INC%" /Fo"%BUILD%\ide_debug_bridge.obj" "%SRC%\ide_debug_bridge.asm" || exit /b 1
echo [ASM] RawrXD_UnifiedDebugger.asm..."%ML64%" /c /Zi /W3 /nologo /I"%INC%" /Fo"%BUILD%\RawrXD_UnifiedDebugger.obj" "%SRC%\RawrXD_UnifiedDebugger.asm" || exit /b 1

REM Syntax Pipeline
echo [ASM] syntax_highlight.asm..."%ML64%" /c /Zi /W3 /nologo /I"%INC%" /Fo"%BUILD%\syntax_highlight.obj" "%SRC%\syntax_highlight.asm" || exit /b 1

echo [BUILD] Linking unified DLL...

"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain ^
    /LIBPATH:"%LIB%" ^
    /OUT:"%OUT%\RawrXD_Unified.dll" ^
    /PDB:"%OUT%\RawrXD_Unified.pdb" ^
    "%BUILD%\input_handler.obj" ^
    "%BUILD%\wndproc_input_bridge.obj" ^
    "%BUILD%\editor.obj" ^
    "%BUILD%\memory.obj" ^
    "%BUILD%\debug_event_ring.obj" ^
    "%BUILD%\ide_debug_bridge.obj" ^
    "%BUILD%\RawrXD_UnifiedDebugger.obj" ^
    "%BUILD%\syntax_highlight.obj" ^
    kernel32.lib user32.lib

if errorlevel 1 (
    echo [ERROR] Link failed
    exit /b 1
)

echo ============================================================================
echo Build Complete
echo ============================================================================

if exist "%OUT%\RawrXD_Unified.dll" (
    echo [SUCCESS] %OUT%\RawrXD_Unified.dll
    for %%F in ("%OUT%\RawrXD_Unified.dll") do echo [SIZE] %%~zF bytes
)

exit /b 0