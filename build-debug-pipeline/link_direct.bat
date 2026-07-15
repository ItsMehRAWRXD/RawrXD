@echo off
echo [LINK] Direct link using local link.exe
echo =======================================

cd /d d:\rawrxd\build-debug-pipeline

echo Current directory: %CD%
echo.

link.exe /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain /LIBPATH:"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\lib\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" /OUT:"d:\rawrxd\build-master\bin\RawrXD_Unified.dll" /PDB:"d:\rawrxd\build-master\bin\RawrXD_Unified.pdb" "d:\rawrxd\build-master\input_handler.obj" "d:\rawrxd\build-master\wndproc_input_bridge.obj" "d:\rawrxd\build-master\memory.obj" "d:\rawrxd\build-master\debug_event_ring.obj" "d:\rawrxd\build-master\ide_debug_bridge.obj" "d:\rawrxd\build-master\RawrXD_UnifiedDebugger.obj" "d:\rawrxd\build-master\syntax_highlight.obj" kernel32.lib

echo Exit: %ERRORLEVEL%

if exist "d:\rawrxd\build-master\bin\RawrXD_Unified.dll" (
    echo SUCCESS
    for %%F in ("d:\rawrxd\build-master\bin\RawrXD_Unified.dll") do echo Size: %%~zF bytes
) else (
    echo FAILED
)
