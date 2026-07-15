@echo off
REM Build script for RawrXD Vertical Slice Test
REM Tests the entire DAP -> DebugBackend -> Windows API stack

echo Building RawrXD Vertical Slice Test...
echo.

set SRC_DIR=%~dp0..
set BUILD_DIR=%SRC_DIR%\..\..\build\debug

if not exist %BUILD_DIR% mkdir %BUILD_DIR%

echo Compiling VerticalTest.cpp...
cl.exe /nologo /EHsc /O2 /W4 /DUNICODE /D_UNICODE ^
    /I%SRC_DIR% ^
    %SRC_DIR%\VerticalTest.cpp ^
    %SRC_DIR%\DebugBackend.cpp ^
    %SRC_DIR%\DebugBridge.cpp ^
    %SRC_DIR%\DAPAdapter.cpp ^
    /Fe%BUILD_DIR%\VerticalTest.exe ^
    /link /DEBUG /PDB:%BUILD_DIR%\VerticalTest.pdb ^
    dbghelp.lib kernel32.lib user32.lib

if %ERRORLEVEL% neq 0 (
    echo.
    echo BUILD FAILED
    exit /b 1
)

echo.
echo BUILD SUCCESSFUL
echo Output: %BUILD_DIR%\VerticalTest.exe
echo.
echo Run with: %BUILD_DIR%\VerticalTest.exe
