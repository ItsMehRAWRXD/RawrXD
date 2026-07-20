@echo off
:: Agent Platform Build Script
:: Builds the RawrXD Agent Platform Layer test harness

echo ========================================
echo RawrXD Agent Platform Build
echo ========================================

set SRC_DIR=d:\RawrXD\src\platform
set BUILD_DIR=d:\RawrXD\build\platform
set CXX=C:\msys64\mingw64\bin\g++.exe

:: Create build directory
if not exist %BUILD_DIR% mkdir %BUILD_DIR%
cd /d %BUILD_DIR%

echo.
echo [1/2] Compiling AgentPlatform_Test.cpp...
"%CXX%" -std=c++17 -Wall -Wextra -O2 -g -I"d:\RawrXD\src" -I"d:\RawrXD\Ship" -I"d:\RawrXD\src\nevm" -I"d:\RawrXD\history\runoff\part_0019" -I"d:\RawrXD\.archived_orphans\runoff\code_overflow\part_0001" -o AgentPlatform_Test.exe "%SRC_DIR%\AgentPlatform_Test.cpp" -static-libgcc -static-libstdc++ -lws2_32

if errorlevel 1 (
    echo [ERROR] Compilation failed!
    exit /b 1
)

echo.
echo [2/2] Build successful!
echo.
echo Running tests...
AgentPlatform_Test.exe

exit /b 0
