@echo off
REM Phase 11 Integration Test Build (C Version)
REM Uses VS Developer Command Prompt
setlocal enabledelayedexpansion

call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

set ROOT=D:\RawrXD
set BUILD_DIR=%ROOT%\build\phase11_test
set LOADER_LIB=%ROOT%\build\120b_loader\RawrXD_120B_Loader.lib
set LOADER_HDR=%ROOT%\build\120b_loader\RawrXD_120B_Loader.h

echo ========================================
echo Phase 11 Integration Test Build (C)
echo ========================================

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

REM Source files
set SRC=%ROOT%\src\tests\phase11_validation_test.c
set OBJ=%BUILD_DIR%\phase11_validation_test.obj
set EXE=%BUILD_DIR%\phase11_validation_test.exe

echo Compiling C test...
cl /TC /O2 /W3 /nologo /c /Fo"%OBJ%" /I"%ROOT%\build\120b_loader" "%SRC%"

if errorlevel 1 (
    echo Compilation FAILED
    exit /b 1
)

echo Linking with assembly library...
link /OUT:"%EXE%" /LIBPATH:"%ROOT%\build\120b_loader" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" %OBJ% RawrXD_120B_Loader.lib kernel32.lib /nologo

if errorlevel 1 (
    echo Linking FAILED
    exit /b 1
)

echo.
echo ========================================
echo Build SUCCESSFUL
echo Executable: %EXE%
echo ========================================

if "%1"=="-run" (
    echo.
    echo Running test...
    "%EXE%"
)

endlocal
