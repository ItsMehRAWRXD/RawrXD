@echo off
setlocal enabledelayedexpansion

echo [TEST] Building different sized DLLs
echo =====================================

set "MASM_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "WINSDK_PATH=C:\Program Files (x86)\Windows Kits\10"
set "WINSDK_VER=10.0.22621.0"

set "LINK=%MASM_PATH%\link.exe"

set "BUILD_DIR=d:\rawrxd\build-master"
set "BIN_DIR=%BUILD_DIR%\bin"
set "DEBUG_PIPE=d:\rawrxd\build-debug-pipeline"

set "LIB_PATH=%MASM_PATH%\lib\x64"
set "LIB_PATH=%LIB_PATH%;%WINSDK_PATH%\Lib\%WINSDK_VER%\um\x64"
set "LIB_PATH=%LIB_PATH%;%WINSDK_PATH%\Lib\%WINSDK_VER%\ucrt\x64"

REM Test 1: Just 1 object
echo.
echo [TEST 1] Single object (input_handler.obj)...
cd /d "%DEBUG_PIPE%"
"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain /LIBPATH:"%LIB_PATH%" /OUT:"%BIN_DIR%\test1.dll" /PDB:"%BIN_DIR%\test1.pdb" "%BUILD_DIR%\input_handler.obj" kernel32.lib 2>nul
echo Exit: %ERRORLEVEL%
if exist "%BIN_DIR%\test1.dll" (for %%F in ("%BIN_DIR%\test1.dll") do echo Size: %%~zF bytes) else (echo FAILED)

REM Test 2: Core 7 objects
echo.
echo [TEST 2] Core 7 objects...
"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain /LIBPATH:"%LIB_PATH%" /OUT:"%BIN_DIR%\test7.dll" /PDB:"%BIN_DIR%\test7.pdb" "%BUILD_DIR%\input_handler.obj" "%BUILD_DIR%\wndproc_input_bridge.obj" "%BUILD_DIR%\memory.obj" "%BUILD_DIR%\debug_event_ring.obj" "%BUILD_DIR%\ide_debug_bridge.obj" "%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" "%BUILD_DIR%\syntax_highlight.obj" kernel32.lib 2>nul
echo Exit: %ERRORLEVEL%
if exist "%BIN_DIR%\test7.dll" (for %%F in ("%BIN_DIR%\test7.dll") do echo Size: %%~zF bytes) else (echo FAILED)

REM Test 3: Core 7 + main + inference
echo.
echo [TEST 3] Core 7 + main + inference...
"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain /LIBPATH:"%LIB_PATH%" /OUT:"%BIN_DIR%\test9.dll" /PDB:"%BIN_DIR%\test9.pdb" "%BUILD_DIR%\input_handler.obj" "%BUILD_DIR%\wndproc_input_bridge.obj" "%BUILD_DIR%\memory.obj" "%BUILD_DIR%\debug_event_ring.obj" "%BUILD_DIR%\ide_debug_bridge.obj" "%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" "%BUILD_DIR%\syntax_highlight.obj" "%BUILD_DIR%\main.obj" "%BUILD_DIR%\inference.obj" kernel32.lib 2>nul
echo Exit: %ERRORLEVEL%
if exist "%BIN_DIR%\test9.dll" (for %%F in ("%BIN_DIR%\test9.dll") do echo Size: %%~zF bytes) else (echo FAILED)

REM Cleanup
del "%BIN_DIR%\test*.dll" 2>nul
del "%BIN_DIR%\test*.pdb" 2>nul

echo.
echo Tests complete.

endlocal
