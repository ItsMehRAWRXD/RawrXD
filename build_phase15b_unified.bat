@echo off
::==============================================================================
:: build_phase15b_unified.bat - Phase 15B: Real Executable Build
::
:: This script builds the actual RawrXDUnified.exe with all dependencies linked.
:: Phase 15A was architecture verification - Phase 15B is the real build.
::
:: Output: RawrXDUnified.exe (fully linked, runnable)
::==============================================================================

setlocal enabledelayedexpansion

echo ============================================
echo RawrXD Phase 15B - Real Executable Build
echo ============================================
echo.

:: Configuration
set BUILD_DIR=build-phase15b
set SRC_DIR=src
set OUT_EXE=RawrXDUnified.exe

:: Detect compiler
set "COMPILER_FOUND=0"
set "CXX="

:: Try MSVC first (preferred)
if exist "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe" (
    set "CXX=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe"
    set "LINKER=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
    set "COMPILER_FOUND=1"
    echo [INFO] Using MSVC from VS2022Enterprise
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.40.33807\bin\Hostx64\x64\cl.exe" (
    set "CXX=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.40.33807\bin\Hostx64\x64\cl.exe"
    set "LINKER=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.40.33807\bin\Hostx64\x64\link.exe"
    set "COMPILER_FOUND=1"
    echo [INFO] Using MSVC from Program Files
)

if "%COMPILER_FOUND%"=="0" (
    echo [ERROR] No MSVC compiler found!
    echo Please install Visual Studio 2022 with C++ workload.
    exit /b 1
)

:: Create build directory
if not exist %BUILD_DIR% mkdir %BUILD_DIR%

:: Set up environment
set "INCLUDE=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\include;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um;%SRC_DIR%;%SRC_DIR%\include"
set "LIB=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"

echo.
echo ============================================
echo Phase 15B Build Steps
echo ============================================
echo.

:: Compiler flags
set "CXXFLAGS=/std:c++17 /O2 /W2 /EHsc /DUNICODE /D_UNICODE /DPHASE15_UNIFIED /DPHASE15B_REAL_BUILD /I%SRC_DIR% /I%SRC_DIR%\include /I%SRC_DIR%\3rdparty\ggml\include"
set "LDFLAGS=/SUBSYSTEM:CONSOLE /MACHINE:X64 /NODEFAULTLIB:libcmt.lib"

echo [1/8] Building Deep2Engine...
echo        - Core inference engine wrapper
"%CXX%" %CXXFLAGS% /c /Fo%BUILD_DIR%\Deep2Engine.obj %SRC_DIR%\deep2\Deep2Engine.cpp 2>&1
if errorlevel 1 (
    echo [FAIL] Deep2Engine compilation failed
    exit /b 1
)
echo        [OK] Deep2Engine.obj

echo [2/8] Building Tokenizer...
echo        - GGUF tokenizer wrapper
"%CXX%" %CXXFLAGS% /c /Fo%BUILD_DIR%\Tokenizer.obj %SRC_DIR%\deep2\Tokenizer.cpp 2>&1
if errorlevel 1 (
    echo [FAIL] Tokenizer compilation failed
    exit /b 1
)
echo        [OK] Tokenizer.obj

echo [3/8] Building AdvancedSampler...
echo        - Token sampling engine
"%CXX%" %CXXFLAGS% /c /Fo%BUILD_DIR%\advanced_sampler.obj %SRC_DIR%\deep2\advanced_sampler.cpp 2>&1
if errorlevel 1 (
    echo [FAIL] AdvancedSampler compilation failed
    exit /b 1
)
echo        [OK] advanced_sampler.obj

echo [4/8] Building Deep2Provider...
echo        - AIProvider implementation
"%CXX%" %CXXFLAGS% /c /Fo%BUILD_DIR%\Deep2Provider.obj %SRC_DIR%\deep2\Deep2Provider.cpp 2>&1
if errorlevel 1 (
    echo [FAIL] Deep2Provider compilation failed
    exit /b 1
)
echo        [OK] Deep2Provider.obj

echo [5/8] Building ContextEngine...
echo        - Repository context indexer
"%CXX%" %CXXFLAGS% /c /Fo%BUILD_DIR%\ContextEngine.obj %SRC_DIR%\context\ContextEngine.cpp 2>&1
if errorlevel 1 (
    echo [FAIL] ContextEngine compilation failed
    exit /b 1
)
echo        [OK] ContextEngine.obj

echo [6/8] Building CompilerAgent...
echo        - Autonomous compile/fix agent
"%CXX%" %CXXFLAGS% /c /Fo%BUILD_DIR%\CompilerAgent.obj %SRC_DIR%\agent\CompilerAgent.cpp 2>&1
if errorlevel 1 (
    echo [FAIL] CompilerAgent compilation failed
    exit /b 1
)
echo        [OK] CompilerAgent.obj

echo [7/8] Building AIServiceAdapter...
echo        - Bridge to unified host
"%CXX%" %CXXFLAGS% /c /Fo%BUILD_DIR%\AIServiceAdapter.obj %SRC_DIR%\unified\AIServiceAdapter.cpp 2>&1
if errorlevel 1 (
    echo [FAIL] AIServiceAdapter compilation failed
    exit /b 1
)
echo        [OK] AIServiceAdapter.obj

echo [8/8] Building RawrXDHost and main...
echo        - Unified host orchestration
"%CXX%" %CXXFLAGS% /c /Fo%BUILD_DIR%\RawrXDHost.obj %SRC_DIR%\unified\RawrXDHost.cpp 2>&1
if errorlevel 1 (
    echo [FAIL] RawrXDHost compilation failed
    exit /b 1
)
echo        [OK] RawrXDHost.obj

"%CXX%" %CXXFLAGS% /c /Fo%BUILD_DIR%\main_unified.obj %SRC_DIR%\unified\main_unified.cpp 2>&1
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
"%LINKER%" %LDFLAGS% /OUT:%BUILD_DIR%\%OUT_EXE% ^
    %BUILD_DIR%\main_unified.obj ^
    %BUILD_DIR%\RawrXDHost.obj ^
    %BUILD_DIR%\AIServiceAdapter.obj ^
    %BUILD_DIR%\Deep2Provider.obj ^
    %BUILD_DIR%\Deep2Engine.obj ^
    %BUILD_DIR%\Tokenizer.obj ^
    %BUILD_DIR%\advanced_sampler.obj ^
    %BUILD_DIR%\ContextEngine.obj ^
    %BUILD_DIR%\CompilerAgent.obj ^
    kernel32.lib user32.lib shell32.lib advapi32.lib ^
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
