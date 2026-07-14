@echo off
REM ============================================================================
REM RAWRXD FINAL UNIFIED SYSTEM - BUILD SCRIPT (GCC)
REM Zero-Dependency Model Loading & Streaming + Complete Infrastructure
REM ============================================================================

setlocal enabledelayedexpansion

REM Configuration - use absolute paths
set "SRC_DIR=D:\rawrxd\src"
set "OUT_DIR=D:\rawrxd\bin"
set "OBJ_DIR=D:\rawrxd\obj"

REM Compiler settings
set "CXX=g++.exe"
set "CXXFLAGS=-std=c++20 -O2 -Wall -Wextra -D_CRT_SECURE_NO_WARNINGS -DWIN32_LEAN_AND_MEAN -DNOMINMAX -I%SRC_DIR%"
set "LDFLAGS=-static-libgcc -static-libstdc++"

REM Create output directories
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"
if not exist "%OBJ_DIR%" mkdir "%OBJ_DIR%"

echo.
echo ============================================================================
echo  RAWRXD FINAL UNIFIED SYSTEM - BUILD (GCC)
echo ============================================================================
echo.
echo  Source: %SRC_DIR%
echo  Output: %OUT_DIR%
echo  Objects: %OBJ_DIR%
echo.

REM Compile each source file
echo [1/5] Compiling RawrXD_Final_Unified.cpp...
%CXX% %CXXFLAGS% -c -o "%OBJ_DIR%\RawrXD_Final_Unified.o" "%SRC_DIR%\RawrXD_Final_Unified.cpp"
if errorlevel 1 goto :compile_error

echo [2/5] Compiling RawrXD_Final_Unified_Part2.cpp...
%CXX% %CXXFLAGS% -c -o "%OBJ_DIR%\RawrXD_Final_Unified_Part2.o" "%SRC_DIR%\RawrXD_Final_Unified_Part2.cpp"
if errorlevel 1 goto :compile_error

echo [3/5] Compiling RawrXD_Final_Unified_Part3.cpp...
%CXX% %CXXFLAGS% -c -o "%OBJ_DIR%\RawrXD_Final_Unified_Part3.o" "%SRC_DIR%\RawrXD_Final_Unified_Part3.cpp"
if errorlevel 1 goto :compile_error

REM Link library
echo [4/5] Linking RawrXD_Unified.exe...
%CXX% %CXXFLAGS% %LDFLAGS% -o "%OUT_DIR%\RawrXD_Unified.exe" "%OBJ_DIR%\RawrXD_Final_Unified.o" "%OBJ_DIR%\RawrXD_Final_Unified_Part2.o" "%OBJ_DIR%\RawrXD_Final_Unified_Part3.o"
if errorlevel 1 goto :link_error

REM Build demo
echo [5/5] Building demo_unified.exe...
%CXX% %CXXFLAGS% %LDFLAGS% -o "%OUT_DIR%\demo_unified.exe" "%SRC_DIR%\demo_unified.cpp" "%OBJ_DIR%\RawrXD_Final_Unified.o" "%OBJ_DIR%\RawrXD_Final_Unified_Part2.o" "%OBJ_DIR%\RawrXD_Final_Unified_Part3.o"
if errorlevel 1 goto :link_error

echo.
echo ============================================================================
echo  BUILD SUCCESSFUL
echo ============================================================================
echo.
echo  Output: %OUT_DIR%\RawrXD_Unified.exe
echo  Demo: %OUT_DIR%\demo_unified.exe
echo.

REM Show file info
if exist "%OUT_DIR%\RawrXD_Unified.exe" (
    for %%F in ("%OUT_DIR%\RawrXD_Unified.exe") do (
        echo  Size: %%~zF bytes
    )
)

echo.
goto :end

:compile_error
echo.
echo ERROR: Compilation failed!
echo.
goto :end

:link_error
echo.
echo ERROR: Linking failed!
echo.
goto :end

:end
endlocal
