@echo off
REM Build script for Deep2Engine Smoketest
REM Uses MSVC with AVX2/AVX-512 support

echo Building Deep2Engine Smoketest...
echo.

REM Setup VS2022 environment
if exist "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
) else (
    echo ERROR: Could not find vcvars64.bat
    exit /b 1
)

set SRC_DIR=%~dp0
set BUILD_DIR=%SRC_DIR%\smoketest_build

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo Compiling Deep2Engine_SmokeTest.cpp...

cl.exe /nologo /W4 /O2 /arch:AVX2 /EHsc /std:c++20 ^
    /I"%SRC_DIR%" ^
    /I"%SRC_DIR%\.." ^
    /I"%SRC_DIR%\..\..\include" ^
    /I"%SRC_DIR%\..\sampling" ^
    /D_CRT_SECURE_NO_WARNINGS ^
    /Fe"%BUILD_DIR%\Deep2Engine_SmokeTest.exe" ^
    "%SRC_DIR%\Deep2Engine_SmokeTest.cpp" ^
    /link /SUBSYSTEM:CONSOLE

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo BUILD FAILED
    exit /b %ERRORLEVEL%
)

echo.
echo BUILD SUCCESSFUL
echo Executable: %BUILD_DIR%\Deep2Engine_SmokeTest.exe
echo.
echo Running smoketest...
echo.

"%BUILD_DIR%\Deep2Engine_SmokeTest.exe"

exit /b %ERRORLEVEL%
