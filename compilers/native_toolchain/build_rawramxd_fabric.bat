@echo off
REM build_rawramxd_fabric.bat - Build Phase 8.2 RawRamXD Fabric Integration
REM VRAM Residency, RAM Spill, Predictive Prefetch, Tensor Migration

echo ============================================
echo Building RawRamXD Fabric (Phase 8.2)
echo ============================================

set SRC_DIR=src\fabric
set OUT_DIR=.
set CXX=g++

REM Compiler flags
set CFLAGS=-O3 -march=native -ffast-math -funroll-loops
set CFLAGS=%CFLAGS% -Wall -Wextra
set CFLAGS=%CFLAGS% -DWIN32_LEAN_AND_MEAN -D_CRT_SECURE_NO_WARNINGS

REM Include paths
set INCLUDES=-I%SRC_DIR% -Isrc\runtime

REM Source files for fabric DLL
set FABRIC_SOURCES=%SRC_DIR%\rawramxd_fabric.cpp
set FABRIC_SOURCES=%FABRIC_SOURCES% %SRC_DIR%\rawramxd_fabric_part2.cpp

echo.
echo Building fabric DLL...
%CXX% %CFLAGS% %INCLUDES% -shared -o %OUT_DIR%\rawramxd_fabric.dll %FABRIC_SOURCES% -Wl,--out-implib,%OUT_DIR%\rawramxd_fabric.lib -DRAWRAMXD_FABRIC_EXPORTS

if %ERRORLEVEL% neq 0 (
    echo ERROR: Fabric DLL build failed!
    exit /b 1
)

echo.
echo Building bridge DLL...
set BRIDGE_SOURCES=%SRC_DIR%\sovereign_fabric_bridge.cpp
%CXX% %CFLAGS% %INCLUDES% -shared -o %OUT_DIR%\sovereign_fabric_bridge.dll %BRIDGE_SOURCES% -L%OUT_DIR% -lrawramxd_fabric -lsovereign_runtime -Wl,--out-implib,%OUT_DIR%\sovereign_fabric_bridge.lib

if %ERRORLEVEL% neq 0 (
    echo WARNING: Bridge DLL build failed
) else (
    echo Bridge DLL built successfully
)

echo.
echo ============================================
echo Build complete!
echo ============================================
echo Output files:
dir /b %OUT_DIR%\rawramxd_fabric.dll %OUT_DIR%\rawramxd_fabric.lib 2>nul
dir /b %OUT_DIR%\sovereign_fabric_bridge.dll 2>nul
echo.

echo Done!