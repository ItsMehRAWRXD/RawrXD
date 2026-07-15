@echo off
REM Quick build test - compiles just the integration test

echo Building RawrXD Integration Test...
echo.

set MSVC_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717
set PATH=%MSVC_PATH%\bin\Hostx64\x64;%PATH%
set INCLUDE=%MSVC_PATH%\include;%INCLUDE%
set LIB=%MSVC_PATH%\lib\x64;%LIB%

set ROOT_DIR=%CD%
set BUILD_DIR=%ROOT_DIR%\build-test

if not exist %BUILD_DIR% mkdir %BUILD_DIR%

echo Compiling integration test...
cl /EHsc /std:c++20 /O2 /W3 /Fe:%BUILD_DIR%\runtime_test.exe ^
    src\integration\tests\runtime_test.cpp ^
    src\integration\runtime.cpp ^
    src\core\scheduler\scheduler.cpp ^
    src\core\router\router.cpp ^
    src\core\executor\executor.cpp ^
    src\core\policy\policy.cpp ^
    /I src\core\scheduler ^
    /I src\core\router ^
    /I src\core\executor ^
    /I src\core\policy ^
    /I src\integration

if errorlevel 1 (
    echo Build FAILED!
    exit /b 1
)

echo.
echo Build SUCCESSFUL!
echo.
echo Running test...
%BUILD_DIR%\runtime_test.exe

pause
