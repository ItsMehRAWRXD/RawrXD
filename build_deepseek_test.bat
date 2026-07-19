@echo off
:: Build script for DeepSeek-V3.1 671B MoE Streamer Test
:: Uses MSVC x64 toolchain

setlocal EnableDelayedExpansion

:: Configuration
set SRC_DIR=d:\rawrxd\src
set BUILD_DIR=d:\rawrxd\build_deepseek_test
set OUT_EXE=%BUILD_DIR%\test_deepseek_v3_1_moe.exe

:: Tool paths (from copilot-instructions.md)
set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set CL=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe

:: Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

:: Setup VS environment
call "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

echo ============================================
echo Building DeepSeek-V3.1 671B MoE Streamer Test
echo ============================================
echo.

:: Compile PrometheusMoE.cpp
echo [1/3] Compiling PrometheusMoE.cpp...
"%CL%" /c /W3 /O2 /arch:AVX2 /EHsc /nologo /Fo"%BUILD_DIR%\PrometheusMoE.obj" ^
    /I"%SRC_DIR%" /I"%SRC_DIR%\inference" /I"%SRC_DIR%\core" ^
    "%SRC_DIR%\inference\PrometheusMoE.cpp"

if errorlevel 1 (
    echo [ERROR] Failed to compile PrometheusMoE.cpp
    exit /b 1
)

:: Compile test harness
echo [2/3] Compiling test_deepseek_v3_1_moe.cpp...
"%CL%" /c /W3 /O2 /arch:AVX2 /EHsc /nologo /Fo"%BUILD_DIR%\test_deepseek_v3_1_moe.obj" ^
    /I"%SRC_DIR%" /I"%SRC_DIR%\inference" /I"%SRC_DIR%\core" ^
    "%SRC_DIR%\test_deepseek_v3_1_moe.cpp"

if errorlevel 1 (
    echo [ERROR] Failed to compile test_deepseek_v3_1_moe.cpp
    exit /b 1
)

:: Link
echo [3/3] Linking executable...
"%LINK%" /SUBSYSTEM:CONSOLE /OUT:"%OUT_EXE%" ^
    "%BUILD_DIR%\PrometheusMoE.obj" ^
    "%BUILD_DIR%\test_deepseek_v3_1_moe.obj"

if errorlevel 1 (
    echo [ERROR] Failed to link executable
    exit /b 1
)

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
