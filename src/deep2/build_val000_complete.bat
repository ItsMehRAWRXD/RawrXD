@echo off
REM ============================================================================
REM build_val000_complete.bat - Build VAL-000 + BigDaddyG Reverse Integration
REM ============================================================================
setlocal EnableDelayedExpansion

echo =================================================================
echo VAL-000 Sovereign Runtime + BigDaddyG Reverse Engine Build
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
    echo Please install MinGW-w64 or MSYS2
    exit /b 1
)

echo Compiler: %COMPILER%

REM Compiler flags
set CFLAGS=-std=c++17 -O2 -mavx2 -mfma -DNDEBUG -DWIN32_LEAN_AND_MEAN
set CFLAGS=%CFLAGS% -I%SRC_DIR% -I%DEEP2_DIR% -I%REVERSE_DIR%
set CFLAGS=%CFLAGS% -I%SRC_DIR%\sampling -I%SRC_DIR%\gguf

REM Link flags
set LDFLAGS=-static-libgcc -static-libstdc++ -lpthread

echo.
echo [1/3] Compiling Reverse Engine...
echo.

REM Compile reverse engine components
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
echo [2/3] Compiling Deep2 Engine + Reverse Integration...
echo.

REM Compile Deep2 engine components
%COMPILER% %CFLAGS% -c %DEEP2_DIR%\Deep2Engine.cpp -o %OBJ_DIR%\Deep2Engine.o
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to compile Deep2Engine.cpp
    exit /b 1
)

%COMPILER% %CFLAGS% -c %DEEP2_DIR%\ReverseIntegration.cpp -o %OBJ_DIR%\ReverseIntegration.o
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to compile ReverseIntegration.cpp
    exit /b 1
)

REM Compile other Deep2 components (if they exist and are needed)
REM Note: For integration test, we only need the core engine + reverse

echo.
echo [3/3] Compiling Integration Test...
echo.

%COMPILER% %CFLAGS% -c %DEEP2_DIR%\val000_integration_test.cpp -o %OBJ_DIR%\val000_integration_test.o
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to compile val000_integration_test.cpp
    exit /b 1
)

echo.
echo Linking...
echo.

%COMPILER% %OBJ_DIR%\val000_integration_test.o ^
    %OBJ_DIR%\Deep2Engine.o ^
    %OBJ_DIR%\ReverseIntegration.o ^
    %OBJ_DIR%\ReverseEngine.o ^
    %OBJ_DIR%\ReverseModelLoader.o ^
    -o %OUT_DIR%\val000_integration_test.exe ^
    %LDFLAGS%

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Linking failed
    exit /b 1
)

echo.
echo =================================================================
echo BUILD SUCCESSFUL
echo =================================================================
echo Output: %OUT_DIR%\val000_integration_test.exe
echo.
echo To run tests:
echo   %OUT_DIR%\val000_integration_test.exe
echo.

endlocal
