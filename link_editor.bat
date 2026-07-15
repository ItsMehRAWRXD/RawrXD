@echo off
set "LINK_EXE=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "LIB1=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64"
set "LIB2=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"
set "LIB3=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64"

"%LINK_EXE%" /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain ^
    /LIBPATH:"%LIB1%" ^
    /LIBPATH:"%LIB2%" ^
    /LIBPATH:"%LIB3%" ^
    /OUT:d:\rawrxd\build-editor-pipeline\bin\editor_pipeline.dll ^
    d:\rawrxd\build-editor-pipeline\input_handler.obj ^
    d:\rawrxd\build-editor-pipeline\wndproc_input_bridge.obj ^
    d:\rawrxd\build-editor-pipeline\editor.obj ^
    d:\rawrxd\build-editor-pipeline\memory.obj ^
    user32.lib kernel32.lib gdi32.lib