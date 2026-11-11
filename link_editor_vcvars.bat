@echo off
call "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

echo Linking editor_pipeline.dll...

link.exe /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain ^
    /OUT:d:\rawrxd\build-editor-pipeline\bin\editor_pipeline.dll ^
    d:\rawrxd\build-editor-pipeline\input_handler.obj ^
    d:\rawrxd\build-editor-pipeline\wndproc_input_bridge.obj ^
    d:\rawrxd\build-editor-pipeline\editor.obj ^
    d:\rawrxd\build-editor-pipeline\memory.obj ^
    user32.lib kernel32.lib gdi32.lib

echo Exit code: %ERRORLEVEL%

if exist "d:\rawrxd\build-editor-pipeline\bin\editor_pipeline.dll" (
    echo SUCCESS: DLL created
    dir "d:\rawrxd\build-editor-pipeline\bin\editor_pipeline.dll"
) else (
    echo FAILED: DLL not created
)