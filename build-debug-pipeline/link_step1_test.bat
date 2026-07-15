@echo off
echo [TEST] Step 1 with kernel32 only...

set "MASM_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "LINK=%MASM_PATH%\link.exe"

set "BUILD_DIR=d:\rawrxd\build-master"
set "OUT_DIR=%BUILD_DIR%\bin"

set "LIB_PATH=%MASM_PATH%\lib\x64"

cd /d d:\rawrxd\build-debug-pipeline

"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain /LIBPATH:"%LIB_PATH%" /OUT:"%OUT_DIR%\test_step1.dll" "%BUILD_DIR%\input_handler.obj" "%BUILD_DIR%\wndproc_input_bridge.obj" "%BUILD_DIR%\memory.obj" "%BUILD_DIR%\debug_event_ring.obj" "%BUILD_DIR%\ide_debug_bridge.obj" "%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" "%BUILD_DIR%\syntax_highlight.obj" kernel32.lib /SUBSYSTEM:WINDOWS /MACHINE:X64

echo Exit: %ERRORLEVEL%
if exist "%OUT_DIR%\test_step1.dll" (echo SUCCESS) else (echo FAILED)
