@echo off
setlocal enabledelayedexpansion

echo ============================================================================
echo RawrXD Master Build - Link Only
echo ============================================================================

set "MASM_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "WINSDK_PATH=C:\Program Files (x86)\Windows Kits\10"
set "WINSDK_VER=10.0.22621.0"

set "LINK=%MASM_PATH%\link.exe"

set "BUILD_DIR=d:\rawrxd\build-master"
set "OUT_DIR=%BUILD_DIR%\bin"

REM Set up library paths
set "LIB_PATH=%MASM_PATH%\lib\x64"
set "LIB_PATH=%LIB_PATH%;%WINSDK_PATH%\Lib\%WINSDK_VER%\um\x64"
set "LIB_PATH=%LIB_PATH%;%WINSDK_PATH%\Lib\%WINSDK_VER%\ucrt\x64"

echo [LINK] Linking RawrXD_Unified.dll...

echo LINK command:
echo "%LINK%" /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain /LIBPATH:"%LIB_PATH%" /OUT:"%OUT_DIR%\RawrXD_Unified.dll" /PDB:"%OUT_DIR%\RawrXD_Unified.pdb" "%BUILD_DIR%\input_handler.obj" "%BUILD_DIR%\wndproc_input_bridge.obj" "%BUILD_DIR%\memory.obj" "%BUILD_DIR%\debug_event_ring.obj" "%BUILD_DIR%\ide_debug_bridge.obj" "%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" "%BUILD_DIR%\syntax_highlight.obj" kernel32.lib

"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain ^
    /LIBPATH:"%LIB_PATH%" ^
    /OUT:"%OUT_DIR%\RawrXD_Unified.dll" ^
    /PDB:"%OUT_DIR%\RawrXD_Unified.pdb" ^
    "%BUILD_DIR%\input_handler.obj" ^
    "%BUILD_DIR%\wndproc_input_bridge.obj" ^
    "%BUILD_DIR%\memory.obj" ^
    "%BUILD_DIR%\debug_event_ring.obj" ^
    "%BUILD_DIR%\ide_debug_bridge.obj" ^
    "%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" ^
    "%BUILD_DIR%\syntax_highlight.obj" ^
    kernel32.lib

echo Exit code: %ERRORLEVEL%

if exist "%OUT_DIR%\RawrXD_Unified.dll" (
    echo [SUCCESS] Built: %OUT_DIR%\RawrXD_Unified.dll
    for %%F in ("%OUT_DIR%\RawrXD_Unified.dll") do echo [SIZE] %%~zF bytes
) else (
    echo [ERROR] DLL not found
)

endlocal