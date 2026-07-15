@echo off
setlocal enabledelayedexpansion

echo Linking editor_pipeline.dll...

set "MASM_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "WINSDK_PATH=C:\Program Files (x86)\Windows Kits\10"
set "WINSDK_VER=10.0.22621.0"

set "LINK_EXE=%MASM_PATH%\link.exe"
set "LIB_PATH=%MASM_PATH%\..\..\..\..\VC\Tools\MSVC\14.50.35717\lib\x64"
set "LIB_PATH=%LIB_PATH%;%WINSDK_PATH%\Lib\%WINSDK_VER%\um\x64"
set "LIB_PATH=%LIB_PATH%;%WINSDK_PATH%\Lib\%WINSDK_VER%\ucrt\x64"

set "LIB=%LIB_PATH%"
set "PATH=%MASM_PATH%;%PATH%"

echo Using linker: %LINK_EXE%
echo LIB=%LIB%
echo Output: d:\rawrxd\build-editor-pipeline\bin\editor_pipeline.dll

"%LINK_EXE%" /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain /OUT:d:\rawrxd\build-editor-pipeline\bin\editor_pipeline.dll d:\rawrxd\build-editor-pipeline\input_handler.obj d:\rawrxd\build-editor-pipeline\wndproc_input_bridge.obj d:\rawrxd\build-editor-pipeline\editor.obj d:\rawrxd\build-editor-pipeline\memory.obj user32.lib kernel32.lib gdi32.lib

echo Exit code: %ERRORLEVEL%

if exist "d:\rawrxd\build-editor-pipeline\bin\editor_pipeline.dll" (
    echo SUCCESS: DLL created
    dir "d:\rawrxd\build-editor-pipeline\bin\editor_pipeline.dll"
) else (
    echo FAILED: DLL not created
)

endlocal