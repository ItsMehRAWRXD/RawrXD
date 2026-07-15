@echo off
setlocal enabledelayedexpansion

echo [LINK] RawrXD Batch Link Test
echo ==============================

set "MASM_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "LINK=%MASM_PATH%\link.exe"

set "BUILD_DIR=d:\rawrxd\build-master"
set "OUT_DIR=%BUILD_DIR%\bin"

set "LIB_PATH=%MASM_PATH%\lib\x64"

REM Test 1: Core 7 objects (known working)
echo.
echo [TEST 1] Core 7 objects...
"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /NOENTRY /LIBPATH:"%LIB_PATH%" /OUT:"%OUT_DIR%\test1.dll" "%BUILD_DIR%\input_handler.obj" "%BUILD_DIR%\wndproc_input_bridge.obj" "%BUILD_DIR%\memory.obj" "%BUILD_DIR%\debug_event_ring.obj" "%BUILD_DIR%\ide_debug_bridge.obj" "%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" "%BUILD_DIR%\syntax_highlight.obj" kernel32.lib /SUBSYSTEM:WINDOWS /MACHINE:X64
echo Exit: %ERRORLEVEL%
if exist "%OUT_DIR%\test1.dll" (echo SUCCESS) else (echo FAILED)

REM Test 2: Core + main
echo.
echo [TEST 2] Core + main.obj...
"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /NOENTRY /LIBPATH:"%LIB_PATH%" /OUT:"%OUT_DIR%\test2.dll" "%BUILD_DIR%\input_handler.obj" "%BUILD_DIR%\wndproc_input_bridge.obj" "%BUILD_DIR%\memory.obj" "%BUILD_DIR%\debug_event_ring.obj" "%BUILD_DIR%\ide_debug_bridge.obj" "%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" "%BUILD_DIR%\syntax_highlight.obj" "%BUILD_DIR%\main.obj" kernel32.lib /SUBSYSTEM:WINDOWS /MACHINE:X64
echo Exit: %ERRORLEVEL%
if exist "%OUT_DIR%\test2.dll" (echo SUCCESS) else (echo FAILED)

REM Test 3: Core + main + inference
echo.
echo [TEST 3] Core + main + inference...
"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /NOENTRY /LIBPATH:"%LIB_PATH%" /OUT:"%OUT_DIR%\test3.dll" "%BUILD_DIR%\input_handler.obj" "%BUILD_DIR%\wndproc_input_bridge.obj" "%BUILD_DIR%\memory.obj" "%BUILD_DIR%\debug_event_ring.obj" "%BUILD_DIR%\ide_debug_bridge.obj" "%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" "%BUILD_DIR%\syntax_highlight.obj" "%BUILD_DIR%\main.obj" "%BUILD_DIR%\inference.obj" kernel32.lib /SUBSYSTEM:WINDOWS /MACHINE:X64
echo Exit: %ERRORLEVEL%
if exist "%OUT_DIR%\test3.dll" (echo SUCCESS) else (echo FAILED)

REM Test 4: Core + main + inference + agent
echo.
echo [TEST 4] Core + main + inference + agent...
"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /NOENTRY /LIBPATH:"%LIB_PATH%" /OUT:"%OUT_DIR%\test4.dll" "%BUILD_DIR%\input_handler.obj" "%BUILD_DIR%\wndproc_input_bridge.obj" "%BUILD_DIR%\memory.obj" "%BUILD_DIR%\debug_event_ring.obj" "%BUILD_DIR%\ide_debug_bridge.obj" "%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" "%BUILD_DIR%\syntax_highlight.obj" "%BUILD_DIR%\main.obj" "%BUILD_DIR%\inference.obj" "%BUILD_DIR%\agent.obj" kernel32.lib /SUBSYSTEM:WINDOWS /MACHINE:X64
echo Exit: %ERRORLEVEL%
if exist "%OUT_DIR%\test4.dll" (echo SUCCESS) else (echo FAILED)

REM Test 5: Core + main + inference + agent + lsp
echo.
echo [TEST 5] Core + main + inference + agent + lsp...
"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /NOENTRY /LIBPATH:"%LIB_PATH%" /OUT:"%OUT_DIR%\test5.dll" "%BUILD_DIR%\input_handler.obj" "%BUILD_DIR%\wndproc_input_bridge.obj" "%BUILD_DIR%\memory.obj" "%BUILD_DIR%\debug_event_ring.obj" "%BUILD_DIR%\ide_debug_bridge.obj" "%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" "%BUILD_DIR%\syntax_highlight.obj" "%BUILD_DIR%\main.obj" "%BUILD_DIR%\inference.obj" "%BUILD_DIR%\agent.obj" "%BUILD_DIR%\lsp.obj" kernel32.lib /SUBSYSTEM:WINDOWS /MACHINE:X64
echo Exit: %ERRORLEVEL%
if exist "%OUT_DIR%\test5.dll" (echo SUCCESS) else (echo FAILED)

REM Cleanup test files
del "%OUT_DIR%\test*.dll" 2>nul
del "%OUT_DIR%\test*.pdb" 2>nul

echo.
echo Tests complete.

endlocal
