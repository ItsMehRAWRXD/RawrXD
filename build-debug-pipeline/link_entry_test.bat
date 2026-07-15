@echo off
setlocal enabledelayedexpansion

echo [LINK] Entry Point Test
echo =======================

set "MASM_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "LINK=%MASM_PATH%\link.exe"

set "BUILD_DIR=d:\rawrxd\build-master"
set "OUT_DIR=%BUILD_DIR%\bin"

set "LIB_PATH=%MASM_PATH%\lib\x64"

REM Test with /ENTRY:DllMain (like working script)
echo.
echo [TEST A] With /ENTRY:DllMain...
"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain /LIBPATH:"%LIB_PATH%" /OUT:"%OUT_DIR%\testA.dll" "%BUILD_DIR%\input_handler.obj" "%BUILD_DIR%\wndproc_input_bridge.obj" "%BUILD_DIR%\memory.obj" "%BUILD_DIR%\debug_event_ring.obj" "%BUILD_DIR%\ide_debug_bridge.obj" "%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" "%BUILD_DIR%\syntax_highlight.obj" kernel32.lib /SUBSYSTEM:WINDOWS /MACHINE:X64
echo Exit: %ERRORLEVEL%
if exist "%OUT_DIR%\testA.dll" (echo SUCCESS - Size: & for %%F in ("%OUT_DIR%\testA.dll") do echo %%~zF bytes) else (echo FAILED)

REM Test with /NOENTRY
echo.
echo [TEST B] With /NOENTRY...
"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /NOENTRY /LIBPATH:"%LIB_PATH%" /OUT:"%OUT_DIR%\testB.dll" "%BUILD_DIR%\input_handler.obj" "%BUILD_DIR%\wndproc_input_bridge.obj" "%BUILD_DIR%\memory.obj" "%BUILD_DIR%\debug_event_ring.obj" "%BUILD_DIR%\ide_debug_bridge.obj" "%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" "%BUILD_DIR%\syntax_highlight.obj" kernel32.lib /SUBSYSTEM:WINDOWS /MACHINE:X64
echo Exit: %ERRORLEVEL%
if exist "%OUT_DIR%\testB.dll" (echo SUCCESS - Size: & for %%F in ("%OUT_DIR%\testB.dll") do echo %%~zF bytes) else (echo FAILED)

REM Cleanup
del "%OUT_DIR%\test*.dll" 2>nul
del "%OUT_DIR%\test*.pdb" 2>nul

echo.
echo Tests complete.

endlocal
