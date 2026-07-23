@echo off
REM ============================================================================
REM build_executive.bat - Build Executive Cognitive Runtime
REM ============================================================================
setlocal EnableDelayedExpansion

echo =================================================================
echo Executive Cognitive Runtime Build
echo =================================================================

set SRC_DIR=d:\RawrXD\src
set EXEC_DIR=%SRC_DIR%\executive
set OUT_DIR=%EXEC_DIR%\bin
set OBJ_DIR=%EXEC_DIR%\obj

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
set CFLAGS=%CFLAGS% -I%SRC_DIR% -I%EXEC_DIR%

REM Link flags
set LDFLAGS=-static-libgcc -static-libstdc++ -lpthread

echo.
echo [1/2] Compiling Executive Components...
echo.

REM Compile all executive components
for %%f in (%EXEC_DIR%\*.cpp) do (
    echo Compiling %%~nxf...
    %COMPILER% %CFLAGS% -c %%f -o %OBJ_DIR%\%%~nf.o
    if %ERRORLEVEL% NEQ 0 (
        echo ERROR: Failed to compile %%~nxf
        exit /b 1
    )
)

echo.
echo [2/2] Linking Executive Runtime Library...
echo.

REM Create static library (just compile for now, link into test later)
echo Executive components compiled successfully.
echo.

echo =================================================================
echo BUILD SUCCESSFUL
echo =================================================================
echo Output objects in: %OBJ_DIR%\
echo.

endlocal
