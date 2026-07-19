/*===========================================================================
 * build_ide_with_debugger.bat
 * Build RawrXD IDE with Debugger Integration
 *===========================================================================*/

@echo off
setlocal enabledelayedexpansion

echo ============================================
echo RawrXD IDE with Debugger Integration Build
echo ============================================
echo.

set SRC_DIR=D:\RawrXD\src
set OUT_DIR=D:\RawrXD\bin
set OBJ_DIR=D:\RawrXD\obj

if not exist %OUT_DIR% mkdir %OUT_DIR%
if not exist %OBJ_DIR% mkdir %OBJ_DIR%

echo [1/6] Compiling SovereignCDB_Engine.cpp...
cl /c /W4 /O2 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE ^
    /Fo%OBJ_DIR%\SovereignCDB_Engine.obj ^
    %SRC_DIR%\debugger\SovereignCDB_Engine.cpp ^
    /EHsc /std:c++17
if errorlevel 1 goto :error

echo [2/6] Compiling DebuggerService.cpp...
cl /c /W4 /O2 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE ^
    /Fo%OBJ_DIR%\DebuggerService.obj ^
    %SRC_DIR%\ide\DebuggerService.cpp ^
    /EHsc /std:c++17
if errorlevel 1 goto :error

echo [3/6] Compiling IDE_DebuggerIntegration.cpp...
cl /c /W4 /O2 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE ^
    /Fo%OBJ_DIR%\IDE_DebuggerIntegration.obj ^
    %SRC_DIR%\ide\IDE_DebuggerIntegration.cpp ^
    /EHsc /std:c++17
if errorlevel 1 goto :error

echo [4/6] Compiling RawrXD_IDE_Win32.cpp...
cl /c /W4 /O2 /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE ^
    /Fo%OBJ_DIR%\RawrXD_IDE_Win32.obj ^
    %SRC_DIR%\ide\RawrXD_IDE_Win32.cpp ^
    /EHsc /std:c++17
if errorlevel 1 goto :error

echo [5/6] Linking RawrXD_IDE.exe...
link /OUT:%OUT_DIR%\RawrXD_IDE.exe ^
    %OBJ_DIR%\RawrXD_IDE_Win32.obj ^
    %OBJ_DIR%\SovereignCDB_Engine.obj ^
    %OBJ_DIR%\DebuggerService.obj ^
    %OBJ_DIR%\IDE_DebuggerIntegration.obj ^
    user32.lib gdi32.lib comctl32.lib comdlg32.lib ^
    shell32.lib shlwapi.lib advapi32.lib ole32.lib ^
    dbghelp.lib synchronization.lib
if errorlevel 1 goto :error

echo [6/6] Build complete!
echo.
echo Output: %OUT_DIR%\RawrXD_IDE.exe
echo.
echo Debugger Integration Features:
echo   - SovereignCDB_Engine (bare-metal Win32 debugging)
echo   - DebuggerService (SPSC ring buffer event bridge)
echo   - Debug Toolbar (Start/Stop/Step)
echo   - Register Viewer Panel
echo   - Memory Viewer Panel
echo   - Call Stack Panel
echo.
goto :end

:error
echo.
echo BUILD FAILED!
echo.
exit /b 1

:end
endlocal
