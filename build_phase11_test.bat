@echo off
REM Phase 11 Integration Test Build
setlocal enabledelayedexpansion

set ROOT=D:\RawrXD
set BUILD_DIR=%ROOT%\build\phase11_test
set LOADER_LIB=%ROOT%\build\120b_loader\RawrXD_120B_Loader.lib

REM VS2022 paths
set VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231
set CL="%VS_PATH%\bin\Hostx64\x64\cl.exe"
set LINK="%VS_PATH%\bin\Hostx64\x64\link.exe"

echo ========================================
echo Phase 11 Integration Test Build
echo ========================================

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

REM Source files
set SRC=%ROOT%\src\tests\phase11_integration_test.cpp
set OBJ=%BUILD_DIR%\phase11_integration_test.obj
set EXE=%BUILD_DIR%\phase11_integration_test.exe

echo Compiling...
%CL% /std:c++20 /O2 /EHsc /MD /W3 /nologo ^
    /I"%ROOT%\src" ^
    /I"%ROOT%\src\core" ^
    /I"%ROOT%\src\swarm" ^
    /I"%ROOT%\build\120b_loader" ^
    /Fo"%OBJ%" ^
    /c "%SRC%"

if errorlevel 1 (
    echo Compilation FAILED
    exit /b 1
)

echo Linking...
%LINK% /OUT:"%EXE%" /LIBPATH:"%ROOT%\build\120b_loader" ^
    %OBJ% ^
    RawrXD_120B_Loader.lib ^
    kernel32.lib user32.lib advapi32.lib ^
    /nologo

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
