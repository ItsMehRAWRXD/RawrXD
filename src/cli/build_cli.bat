@echo off
REM ============================================================================
REM RawrXD CLI Component Build Script
REM Builds cli_stream.cpp and cli_history.asm for pipe/REPL testing
REM ============================================================================

setlocal enabledelayedexpansion

set "ML64=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\ml64.exe"
set "CL=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe"
set "LINK=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe"

set SRC_MASM=d:\rawrxd\src\masm
set SRC_CLI=d:\rawrxd\src\cli
set OUT_DIR=d:\rawrxd\build-ninja\cli_test

if not exist %OUT_DIR% mkdir %OUT_DIR%

echo ============================================================================
echo RawrXD CLI Component Build
echo ============================================================================
echo.

echo [1/4] Assembling cli_history.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo "%OUT_DIR%\cli_history.obj" "%SRC_MASM%\cli_history.asm"
if errorlevel 1 (
    echo ERROR: MASM assembly failed!
    exit /b 1
)
echo       Success: cli_history.obj created

echo [2/4] Compiling cli_stream.cpp...
"%CL%" /c /W4 /nologo /Zi /EHsc /Fo"%OUT_DIR%\cli_stream.obj" /I"d:\rawrxd\include" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt" /I"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include" "%SRC_CLI%\cli_stream.cpp"
if errorlevel 1 (
    echo ERROR: C++ compilation failed!
    exit /b 1
)
echo       Success: cli_stream.obj created

echo [3/4] Compiling cli_main.cpp (test entry point)...
"%CL%" /c /W4 /nologo /Zi /EHsc /Fo"%OUT_DIR%\cli_main.obj" /I"d:\rawrxd\include" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt" /I"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include" "%SRC_CLI%\cli_main.cpp"
if errorlevel 1 (
    echo ERROR: C++ main compilation failed!
    exit /b 1
)
echo       Success: cli_main.obj created

echo [4/4] Linking test_vm.exe...
set "LINK_CMD=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe"
"%LINK_CMD%" /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /OUT:"%OUT_DIR%\test_vm.exe" ^
    "%OUT_DIR%\cli_stream.obj" ^
    "%OUT_DIR%\cli_history.obj" ^
    "%OUT_DIR%\cli_main.obj" ^
    kernel32.lib user32.lib
if errorlevel 1 (
    echo ERROR: Linking failed!
    exit /b 1
)
echo       Success: test_vm.exe created

echo.
echo ============================================================================
echo Build Complete!
echo ============================================================================
echo.
echo Test executable: %OUT_DIR%\test_vm.exe
echo.
echo Verification commands:
echo   Pipe mode:   type cli_history.asm ^| %OUT_DIR%\test_vm.exe --headless
echo   REPL mode:   %OUT_DIR%\test_vm.exe
echo   Stderr test: %OUT_DIR%\test_vm.exe --headless 2^> diagnostics.log
echo.

endlocal
goto :eof
