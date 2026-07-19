@echo off
:: Build script for DeepSeek-V3.1 671B MoE Streamer Test using MinGW

setlocal EnableDelayedExpansion

:: Configuration
set SRC_DIR=d:\rawrxd\src
set BUILD_DIR=d:\rawrxd\build_deepseek_test
set OUT_EXE=%BUILD_DIR%\test_deepseek_v3_1_moe.exe

:: MinGW path
set CXX=C:\msys64\mingw64\bin\g++.exe

:: Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo ============================================
echo Building DeepSeek-V3.1 671B MoE Streamer Test
echo Using MinGW-w64
echo ============================================
echo.

:: Compile PrometheusMoE.cpp
echo [1/3] Compiling PrometheusMoE.cpp...
"%CXX%" -c -O2 -mavx2 -mfma -std=c++17 -Wall -Wextra -DWIN32_LEAN_AND_MEAN -DNOMINMAX ^
    -I"%SRC_DIR%" -I"%SRC_DIR%\inference" -I"%SRC_DIR%\core" ^
    -o "%BUILD_DIR%\PrometheusMoE.o" ^
    "%SRC_DIR%\inference\PrometheusMoE.cpp"

if errorlevel 1 (
    echo [ERROR] Failed to compile PrometheusMoE.cpp
    exit /b 1
)
echo     OK: PrometheusMoE.o

:: Compile test harness
echo.
echo [2/3] Compiling test_deepseek_v3_1_moe.cpp...
"%CXX%" -c -O2 -mavx2 -mfma -std=c++17 -Wall -Wextra -DWIN32_LEAN_AND_MEAN -DNOMINMAX ^
    -I"%SRC_DIR%" -I"%SRC_DIR%\inference" -I"%SRC_DIR%\core" ^
    -o "%BUILD_DIR%\test_deepseek_v3_1_moe.o" ^
    "%SRC_DIR%\test_deepseek_v3_1_moe.cpp"

if errorlevel 1 (
    echo [ERROR] Failed to compile test_deepseek_v3_1_moe.cpp
    exit /b 1
)
echo     OK: test_deepseek_v3_1_moe.o

:: Link
echo.
echo [3/3] Linking executable...
"%CXX%" -o "%OUT_EXE%" ^
    "%BUILD_DIR%\PrometheusMoE.o" ^
    "%BUILD_DIR%\test_deepseek_v3_1_moe.o" ^
    -static-libgcc -static-libstdc++ ^
    -lwinmm -lws2_32 -lkernel32 -luser32 -ladvapi32

if errorlevel 1 (
    echo [ERROR] Failed to link executable
    exit /b 1
)

echo     OK: test_deepseek_v3_1_moe.exe

echo.
echo ============================================
echo Build SUCCESSFUL
echo Output: %OUT_EXE%
echo ============================================
echo.
echo Usage:
echo   %OUT_EXE% [path_to_gguf]
echo.
echo Example:
echo   %OUT_EXE% F:\OllamaModels\blobs\sha256-044d50a3d79c
echo.

endlocal
