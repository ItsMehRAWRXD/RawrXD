@echo off
REM build_sovereign_runtime.bat - Build Phase 8.1 Sovereign Runtime Bridge
REM Production Runtime Integration

echo ============================================
echo Building Sovereign Runtime Bridge (Phase 8.1)
echo ============================================

set SRC_DIR=src\runtime
set OUT_DIR=.
set CC=gcc
set CXX=g++

REM Compiler flags
set CFLAGS=-O3 -march=native -ffast-math -funroll-loops
set CFLAGS=%CFLAGS% -Wall -Wextra -Werror
set CFLAGS=%CFLAGS% -DWIN32_LEAN_AND_MEAN -D_CRT_SECURE_NO_WARNINGS
set CFLAGS=%CFLAGS% -DSOVEREIGN_RUNTIME_EXPORTS

REM Include paths
set INCLUDES=-I%SRC_DIR%

REM Source files
set SOURCES=%SRC_DIR%\tensor_binding.cpp
set SOURCES=%SOURCES% %SRC_DIR%\sovereign_runtime.cpp
set SOURCES=%SOURCES% %SRC_DIR%\tokenizer_bridge.cpp
set SOURCES=%SOURCES% %SRC_DIR%\kv_runtime_bridge.cpp

echo.
echo Source files:
echo %SOURCES%
echo.

REM Build DLL
echo Building sovereign_runtime.dll...
%CXX% %CFLAGS% %INCLUDES% -shared -o %OUT_DIR%\sovereign_runtime.dll %SOURCES% -Wl,--out-implib,%OUT_DIR%\sovereign_runtime.lib

if %ERRORLEVEL% neq 0 (
    echo ERROR: Build failed!
    exit /b 1
)

echo.
echo ============================================
echo Build successful!
echo ============================================
echo Output files:
dir /b %OUT_DIR%\sovereign_runtime.dll %OUT_DIR%\sovereign_runtime.lib 2>nul
echo.

REM Build test harness
echo Building test harness...
%CXX% %CFLAGS% %INCLUDES% -o %OUT_DIR%\test_sovereign_runtime.exe test_sovereign_runtime.cpp -L%OUT_DIR% -lsovereign_runtime

if %ERRORLEVEL% neq 0 (
    echo WARNING: Test harness build failed (may need implementation)
) else (
    echo Test harness built successfully
)

echo.
echo Done!