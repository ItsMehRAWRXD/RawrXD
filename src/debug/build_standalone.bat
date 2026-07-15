@echo off
REM Standalone build script for VerticalTest
REM Does not require CMake - uses cl.exe directly

echo Building RawrXD Vertical Slice Test...
echo.

set SRC_DIR=d:\rawrxd\src\debug
set OUT_DIR=d:\rawrxd\build\bin

if not exist %OUT_DIR% mkdir %OUT_DIR%

echo Compiling...
echo Source: %SRC_DIR%
echo Output: %OUT_DIR%\VerticalTest.exe
echo.

"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.40.33807\bin\Hostx64\x64\cl.exe" ^
    /nologo ^
    /EHsc ^
    /O2 ^
    /W4 ^
    /DUNICODE ^
    /D_UNICODE ^
    /I"%SRC_DIR%" ^
    "%SRC_DIR%\VerticalTest.cpp" ^
    "%SRC_DIR%\DebugBackend.cpp" ^
    "%SRC_DIR%\DebugBridge.cpp" ^
    "%SRC_DIR%\DAPAdapter.cpp" ^
    /Fe"%OUT_DIR%\VerticalTest.exe" ^
    /Fo"%OUT_DIR%\\" ^
    /link ^
    dbghelp.lib ^
    kernel32.lib ^
    user32.lib ^
    /SUBSYSTEM:CONSOLE

if %ERRORLEVEL% neq 0 (
    echo.
    echo BUILD FAILED
    exit /b 1
)

echo.
echo BUILD SUCCESSFUL
echo Output: %OUT_DIR%\VerticalTest.exe
echo.
echo Run with: %OUT_DIR%\VerticalTest.exe
