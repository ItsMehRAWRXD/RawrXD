@echo off
setlocal enabledelayedexpansion

echo [LINK] RawrXD Working - Response File Test
echo ===========================================

set "MASM_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "WINSDK_PATH=C:\Program Files (x86)\Windows Kits\10"
set "WINSDK_VER=10.0.22621.0"

set "LINK=%MASM_PATH%\link.exe"

set "BUILD_DIR=d:\rawrxd\build-master"
set "OUT_DIR=%BUILD_DIR%\bin"

set "LIB_PATH=%MASM_PATH%\lib\x64"
set "LIB_PATH=%LIB_PATH%;%WINSDK_PATH%\Lib\%WINSDK_VER%\um\x64"
set "LIB_PATH=%LIB_PATH%;%WINSDK_PATH%\Lib\%WINSDK_VER%\ucrt\x64"

echo Creating response file for working 7 objects...

echo /DLL > link_work.rsp
echo /DEBUG >> link_work.rsp
echo /INCREMENTAL:NO >> link_work.rsp
echo /ENTRY:DllMain >> link_work.rsp
echo /OUT:"%OUT_DIR%\RawrXD_Test.dll" >> link_work.rsp
echo /PDB:"%OUT_DIR%\RawrXD_Test.pdb" >> link_work.rsp
echo "%BUILD_DIR%\input_handler.obj" >> link_work.rsp
echo "%BUILD_DIR%\wndproc_input_bridge.obj" >> link_work.rsp
echo "%BUILD_DIR%\memory.obj" >> link_work.rsp
echo "%BUILD_DIR%\debug_event_ring.obj" >> link_work.rsp
echo "%BUILD_DIR%\ide_debug_bridge.obj" >> link_work.rsp
echo "%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" >> link_work.rsp
echo "%BUILD_DIR%\syntax_highlight.obj" >> link_work.rsp
echo kernel32.lib >> link_work.rsp

echo Response file created.
type link_work.rsp
echo.
echo [LINK] Linking with response file...

"%LINK%" @link_work.rsp /LIBPATH:"%LIB_PATH%"

echo Exit code: %ERRORLEVEL%

if exist "%OUT_DIR%\RawrXD_Test.dll" (
    echo [SUCCESS] Built: %OUT_DIR%\RawrXD_Test.dll
    for %%F in ("%OUT_DIR%\RawrXD_Test.dll") do echo [SIZE] %%~zF bytes
) else (
    echo [ERROR] DLL not created
)

REM Cleanup
del link_work.rsp 2>nul
del "%OUT_DIR%\RawrXD_Test.dll" 2>nul
del "%OUT_DIR%\RawrXD_Test.pdb" 2>nul

endlocal
