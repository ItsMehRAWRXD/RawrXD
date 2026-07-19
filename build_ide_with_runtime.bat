@echo off
REM Build RawrXD IDE with SovereignRuntime integration
REM This creates the unified IDE that shares the same backend as the CLI

echo ============================================
echo RawrXD IDE + SovereignRuntime Build
echo ============================================

set SRC_DIR=d:\RawrXD\src
set BUILD_DIR=d:\RawrXD\build_ide

if not exist %BUILD_DIR% mkdir %BUILD_DIR%

REM Compiler settings
set CC=cl
set CFLAGS=/W4 /O2 /DUNICODE /D_UNICODE /EHsc /std:c++17
set CFLAGS=%CFLAGS% /I%SRC_DIR% /I%SRC_DIR%\ide /I%SRC_DIR%\runtime /I%SRC_DIR%\asm
set CFLAGS=%CFLAGS% /DRAWRXD_IDE_RUNTIME_BRIDGE

REM Linker settings
set LDFLAGS=/link user32.lib gdi32.lib comctl32.lib comdlg32.lib shell32.lib shlwapi.lib advapi32.lib ole32.lib

REM Source files
set IDE_SRC=%SRC_DIR%\ide\RawrXD_IDE_Win32.cpp
set BRIDGE_SRC=%SRC_DIR%\ide\RawrXD_IDE_RuntimeBridge.cpp
set RUNTIME_SRC=%SRC_DIR%\runtime\SovereignRuntime.cpp

REM Object files
set IDE_OBJ=%BUILD_DIR%\RawrXD_IDE_Win32.obj
set BRIDGE_OBJ=%BUILD_DIR%\RawrXD_IDE_RuntimeBridge.obj
set RUNTIME_OBJ=%BUILD_DIR%\SovereignRuntime.obj

echo.
echo [1/4] Compiling IDE Win32...
%CC% /c %CFLAGS% %IDE_SRC% /Fo%IDE_OBJ%
if errorlevel 1 goto :error

echo.
echo [2/4] Compiling Runtime Bridge...
%CC% /c %CFLAGS% %BRIDGE_SRC% /Fo%BRIDGE_OBJ%
if errorlevel 1 goto :error

echo.
echo [3/4] Compiling SovereignRuntime...
%CC% /c %CFLAGS% %RUNTIME_SRC% /Fo%RUNTIME_OBJ%
if errorlevel 1 goto :error

echo.
echo [4/4] Linking RawrXD_IDE.exe...
%CC% %IDE_OBJ% %BRIDGE_OBJ% %RUNTIME_OBJ% %LDFLAGS% /Fe%BUILD_DIR%\RawrXD_IDE.exe
if errorlevel 1 goto :error

echo.
echo ============================================
echo Build SUCCESSFUL
echo ============================================
echo Output: %BUILD_DIR%\RawrXD_IDE.exe
echo.
echo This IDE uses the same backend as:
echo   - rawrxd-infer.exe (CLI)
echo   - SovereignRuntime.dll (shared library)
echo.
goto :end

:error
echo.
echo ============================================
echo Build FAILED
echo ============================================
exit /b 1

:end
