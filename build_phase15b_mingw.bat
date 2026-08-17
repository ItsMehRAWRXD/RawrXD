@echo off
::==============================================================================
:: build_phase15b_mingw.bat - Phase 15B: Real Executable Build (MinGW)
::
:: This script builds the actual RawrXDUnified.exe using MinGW/GCC.
:: Phase 15A was architecture verification - Phase 15B is the real build.
::
:: Output: RawrXDUnified.exe (fully linked, runnable)
::==============================================================================

setlocal enabledelayedexpansion

echo ============================================
echo RawrXD Phase 15B - Real Executable Build
echo Compiler: MinGW/GCC
echo ============================================
echo.

:: Configuration
set BUILD_DIR=build-phase15b
set SRC_DIR=src
set OUT_EXE=RawrXDUnified.exe

:: MinGW paths
set "MINGW_ROOT=C:\ProgramData\mingw64\mingw64"
set "CXX=%MINGW_ROOT%\bin\g++.exe"
set "WINDRES=%MINGW_ROOT%\bin\windres.exe"

if not exist "%CXX%" (
    echo [ERROR] MinGW g++ not found at %CXX%
    echo Please install MinGW-w64.
    exit /b 1
)

echo [INFO] Using MinGW from %MINGW_ROOT%

:: Create build directory
if not exist %BUILD_DIR% mkdir %BUILD_DIR%

:: Compiler flags
set "CXXFLAGS=-std=c++17 -O2 -Wall -Wextra -DUNICODE -D_UNICODE -DPHASE15_UNIFIED -DPHASE15B_REAL_BUILD -I%SRC_DIR% -I%SRC_DIR%\include -I%SRC_DIR%\3rdparty\ggml\include"
set "LDFLAGS=-static-libgcc -static-libstdc++ -Wl,--subsystem,console"

echo.
echo ============================================
echo Phase 15B Build Steps
echo ============================================
echo.

echo [1/8] Building Deep2Engine...
echo        - Core inference engine wrapper
"%CXX%" %CXXFLAGS% -c -o %BUILD_DIR%\Deep2Engine.obj %SRC_DIR%\deep2\Deep2Engine.cpp 2>&1
if errorlevel 1 (
    echo [FAIL] Deep2Engine compilation failed
    type %BUILD_DIR%\compile_error.log 2>nul
    exit /b 1
)
echo        [OK] Deep2Engine.obj

echo [2/8] Building Tokenizer...
echo        - GGUF tokenizer wrapper
"%CXX%" %CXXFLAGS% -c -o %BUILD_DIR%\Tokenizer.obj %SRC_DIR%\deep2\Tokenizer.cpp 2>&1
if errorlevel 1 (
    echo [FAIL] Tokenizer compilation failed
    exit /b 1
)
echo        [OK] Tokenizer.obj

echo [3/8] Building AdvancedSampler...
echo        - Token sampling engine
"%CXX%" %CXXFLAGS% -c -o %BUILD_DIR%\advanced_sampler.obj %SRC_DIR%\deep2\advanced_sampler.cpp 2>&1
if errorlevel 1 (
    echo [FAIL] AdvancedSampler compilation failed
    exit /b 1
)
echo        [OK] advanced_sampler.obj

echo [4/8] Building Deep2Provider...
echo        - AIProvider implementation
"%CXX%" %CXXFLAGS% -c -o %BUILD_DIR%\Deep2Provider.obj %SRC_DIR%\deep2\Deep2Provider.cpp 2>&1
if errorlevel 1 (
    echo [FAIL] Deep2Provider compilation failed
    exit /b 1
)
echo        [OK] Deep2Provider.obj

echo [5/8] Building ContextEngine...
echo        - Repository context indexer
"%CXX%" %CXXFLAGS% -c -o %BUILD_DIR%\ContextEngine.obj %SRC_DIR%\context\ContextEngine.cpp 2>&1
if errorlevel 1 (
    echo [FAIL] ContextEngine compilation failed
    exit /b 1
)
echo        [OK] ContextEngine.obj

echo [6/8] Building CompilerAgent...
echo        - Autonomous compile/fix agent
"%CXX%" %CXXFLAGS% -c -o %BUILD_DIR%\CompilerAgent.obj %SRC_DIR%\agent\CompilerAgent.cpp 2>&1
if errorlevel 1 (
    echo [FAIL] CompilerAgent compilation failed
    exit /b 1
)
echo        [OK] CompilerAgent.obj

echo [7/8] Building AIServiceAdapter...
echo        - Bridge to unified host
"%CXX%" %CXXFLAGS% -c -o %BUILD_DIR%\AIServiceAdapter.obj %SRC_DIR%\unified\AIServiceAdapter.cpp 2>&1
if errorlevel 1 (
    echo [FAIL] AIServiceAdapter compilation failed
    exit /b 1
)
echo        [OK] AIServiceAdapter.obj

echo [8/8] Building RawrXDHost and main...
echo        - Unified host orchestration
"%CXX%" %CXXFLAGS% -c -o %BUILD_DIR%\RawrXDHost.obj %SRC_DIR%\unified\RawrXDHost.cpp 2>&1
if errorlevel 1 (
    echo [FAIL] RawrXDHost compilation failed
    exit /b 1
)
echo        [OK] RawrXDHost.obj

"%CXX%" %CXXFLAGS% -c -o %BUILD_DIR%\main_unified.obj %SRC_DIR%\unified\main_unified.cpp 2>&1
if errorlevel 1 (
    echo [FAIL] main_unified compilation failed
    exit /b 1
)
echo        [OK] main_unified.obj

echo.
echo ============================================
echo Linking RawrXDUnified.exe
echo ============================================
echo.

:: Link all objects
echo [LINK] Creating executable...
"%CXX%" %CXXFLAGS% %LDFLAGS% -o %BUILD_DIR%\%OUT_EXE% ^
    %BUILD_DIR%\main_unified.obj ^
    %BUILD_DIR%\RawrXDHost.obj ^
    %BUILD_DIR%\AIServiceAdapter.obj ^
    %BUILD_DIR%\Deep2Provider.obj ^
    %BUILD_DIR%\Deep2Engine.obj ^
    %BUILD_DIR%\Tokenizer.obj ^
    %BUILD_DIR%\advanced_sampler.obj ^
    %BUILD_DIR%\ContextEngine.obj ^
    %BUILD_DIR%\CompilerAgent.obj ^
    -lkernel32 -luser32 -lshell32 -ladvapi32 ^
    2>&1

if errorlevel 1 (
    echo [FAIL] Link failed
    exit /b 1
)

echo [OK] %BUILD_DIR%\%OUT_EXE% created successfully

echo.
echo ============================================
echo Phase 15B Build Complete
echo ============================================
echo.
echo Output: %BUILD_DIR%\%OUT_EXE%
echo.
echo To test: %BUILD_DIR%\%OUT_EXE% --status
echo.

:: Copy to root for convenience
copy /Y %BUILD_DIR%\%OUT_EXE% %OUT_EXE% >nul 2>&1
echo [INFO] Copied to %OUT_EXE%

echo.
echo ============================================
echo Phase 15B Status: SUCCESS
echo ============================================
echo.
echo Components linked:
echo   [OK] Deep2Engine - Core inference
echo   [OK] Tokenizer - Text tokenization
echo   [OK] AdvancedSampler - Token sampling
echo   [OK] Deep2Provider - AIProvider implementation
echo   [OK] ContextEngine - Repository awareness
echo   [OK] CompilerAgent - Autonomous compile/fix
echo   [OK] AIServiceAdapter - Bridge layer
echo   [OK] RawrXDHost - Unified orchestration
echo.
echo Next: Run %BUILD_DIR%\%OUT_EXE% --self-test
echo.
