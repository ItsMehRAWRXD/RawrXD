@echo off
REM Build script for Layer 0: Scheduler
REM Builds standalone in ~30 seconds

echo Building RawrXD-Scheduler (Layer 0)...
echo.

set BUILD_DIR=build-scheduler
set SOURCE_DIR=src\core\scheduler
set MSVC_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717

REM Add MSVC to PATH
set PATH=%MSVC_PATH%\bin\Hostx64\x64;%PATH%
set INCLUDE=%MSVC_PATH%\include;%INCLUDE%
set LIB=%MSVC_PATH%\lib\x64;%LIB%

REM Create build directory
if not exist %BUILD_DIR% mkdir %BUILD_DIR%

cd %BUILD_DIR%

REM Configure with CMake
echo Configuring...
cmake ..\%SOURCE_DIR% -G "Ninja" ^
    -DCMAKE_BUILD_TYPE=Release ^
    -DBUILD_TESTING=ON ^
    -DCMAKE_CXX_COMPILER="%MSVC_PATH%\bin\Hostx64\x64\cl.exe"

if errorlevel 1 (
    echo Configuration failed!
    exit /b 1
)

REM Build
echo Building...
ninja

if errorlevel 1 (
    echo Build failed!
    exit /b 1
)

echo.
echo Build successful!
echo.
echo Running tests...
ctest --output-on-failure

cd ..

echo.
echo Scheduler library built: %BUILD_DIR%\RawrXD-Scheduler.lib
echo.
pause
