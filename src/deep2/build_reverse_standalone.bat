@echo off
REM ============================================================================
REM build_reverse_standalone.bat - Build standalone reverse integration test
REM ============================================================================
setlocal EnableDelayedExpansion

echo =================================================================
echo BigDaddyG Reverse Engine - Standalone Build
echo =================================================================

set SRC_DIR=d:\RawrXD\src
set DEEP2_DIR=%SRC_DIR%\deep2
set REVERSE_DIR=%SRC_DIR%\reverse
set OUT_DIR=%DEEP2_DIR%\bin
set OBJ_DIR=%DEEP2_DIR%\obj

REM Create output directories
if not exist %OUT_DIR% mkdir %OUT_DIR%
if not exist %OBJ_DIR% mkdir %OBJ_DIR%

REM Find compiler
set COMPILER=g++
where g++ >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: g++ not found in PATH
    exit /b 1
)

echo Compiler: %COMPILER%

REM Compiler flags
set CFLAGS=-std=c++17 -O2 -mavx2 -mfma -DNDEBUG -DWIN32_LEAN_AND_MEAN
set CFLAGS=%CFLAGS% -I%SRC_DIR% -I%DEEP2_DIR% -I%REVERSE_DIR%

REM Link flags
set LDFLAGS=-static-libgcc -static-libstdc++ -lpthread

echo.
echo [1/2] Compiling Reverse Engine...
echo.

%COMPILER% %CFLAGS% -c %REVERSE_DIR%\ReverseEngine.cpp -o %OBJ_DIR%\ReverseEngine.o
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to compile ReverseEngine.cpp
    exit /b 1
)

%COMPILER% %CFLAGS% -c %REVERSE_DIR%\ReverseModelLoader.cpp -o %OBJ_DIR%\ReverseModelLoader.o
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to compile ReverseModelLoader.cpp
    exit /b 1
)

echo.
echo [2/2] Compiling ReverseIntegration + Test...
echo.

%COMPILER% %CFLAGS% -c %DEEP2_DIR%\ReverseIntegration.cpp -o %OBJ_DIR%\ReverseIntegration.o
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to compile ReverseIntegration.cpp
    exit /b 1
)

%COMPILER% %CFLAGS% -c %DEEP2_DIR%\reverse_integration_standalone_test.cpp -o %OBJ_DIR%\reverse_integration_standalone_test.o
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to compile reverse_integration_standalone_test.cpp
    exit /b 1
)

echo.
echo Linking...
echo.

%COMPILER% %OBJ_DIR%\reverse_integration_standalone_test.o ^
    %OBJ_DIR%\ReverseIntegration.o ^
    %OBJ_DIR%\ReverseEngine.o ^
    %OBJ_DIR%\ReverseModelLoader.o ^
    -o %OUT_DIR%\reverse_integration_standalone_test.exe ^
    %LDFLAGS%

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Linking failed
    exit /b 1
)

echo.
echo =================================================================
echo BUILD SUCCESSFUL
echo =================================================================
echo Output: %OUT_DIR%\reverse_integration_standalone_test.exe
echo.
echo To run tests:
echo   %OUT_DIR%\reverse_integration_standalone_test.exe
echo.

endlocal
