@echo off
:: Build script for model finder using MinGW

setlocal EnableDelayedExpansion

set SRC_DIR=d:\rawrxd\src
set BUILD_DIR=d:\rawrxd\build_deepseek_test
set OUT_EXE=%BUILD_DIR%\find_deepseek_model.exe

set CXX=C:\msys64\mingw64\bin\g++.exe

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo ============================================
echo Building Model Finder
echo ============================================
echo.

echo [1/1] Compiling find_deepseek_model.cpp...
"%CXX%" -O2 -std=c++17 -Wall -DWIN32_LEAN_AND_MEAN -DNOMINMAX -static-libgcc -static-libstdc++ ^
    -o "%OUT_EXE%" ^
    "%SRC_DIR%\find_deepseek_model.cpp"

if errorlevel 1 (
    echo [ERROR] Failed to compile
    exit /b 1
)

echo     OK: find_deepseek_model.exe

echo.
echo ============================================
echo Build SUCCESSFUL
echo Output: %OUT_EXE%
echo ============================================

endlocal
