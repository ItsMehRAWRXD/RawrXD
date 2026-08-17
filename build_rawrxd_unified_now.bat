@echo off
::==============================================================================
:: build_rawrxd_unified_now.bat - ACTUAL BUILD - RawrXD Unified Executable
:: Phase 15B: REAL COMPILATION - Not verification, ACTUAL LINKING
::
:: This script ACTUALLY BUILDS RawrXDUnified.exe - no more verification games
::==============================================================================

setlocal enabledelayedexpansion

echo ============================================
echo RawrXD Unified - ACTUAL BUILD
echo Phase 15B: Real Executable Creation
echo ============================================
echo.

:: Configuration
set BUILD_DIR=build-unified-final
set SRC_DIR=src
set OUT_EXE=RawrXDUnified.exe

:: Find MinGW
set GCC=C:\ProgramData\mingw64\mingw64\bin\g++.exe
set GPP=C:\ProgramData\mingw64\mingw64\bin\g++.exe
set WINDRES=C:\ProgramData\mingw64\mingw64\bin\windres.exe

if not exist "%GCC%" (
    echo ERROR: MinGW not found at %GCC%
    echo Trying alternative paths...
    set GCC=C:\mingw64\bin\g++.exe
    set GPP=C:\mingw64\bin\g++.exe
    set WINDRES=C:\mingw64\bin\windres.exe
)

if not exist "%GCC%" (
    echo ERROR: Cannot find MinGW compiler
    exit /b 1
)

echo Using compiler: %GCC%

:: Create build directory
if not exist %BUILD_DIR% mkdir %BUILD_DIR%

:: Compiler flags - optimized for speed
set CFLAGS=-std=c++17 -O2 -Wall -Wextra -I%SRC_DIR% -I%SRC_DIR%\include -I%SRC_DIR%\deep2 -I%SRC_DIR%\core -I%SRC_DIR%\unified -I%SRC_DIR%\context -I%SRC_DIR%\agent -I%SRC_DIR%\inference -I%SRC_DIR%\tokenizer -DUNICODE -D_UNICODE -DPHASE15_UNIFIED -DNDEBUG

:: Linker flags
set LDFLAGS=-static-libgcc -static-libstdc++ -Wl,--subsystem,console

echo.
echo ============================================
echo [1/8] Building Deep2 Engine...
echo ============================================
%GPP% %CFLAGS% -c -o %BUILD_DIR%\Deep2Engine.obj %SRC_DIR%\deep2\Deep2Engine.cpp 2>&1
if errorlevel 1 (
    echo FAILED: Deep2Engine.cpp
    goto :error
)
echo OK: Deep2Engine.obj

%GPP% %CFLAGS% -c -o %BUILD_DIR%\Tokenizer.obj %SRC_DIR%\deep2\Tokenizer.cpp 2>&1
if errorlevel 1 (
    echo FAILED: Tokenizer.cpp
    goto :error
)
echo OK: Tokenizer.obj

%GPP% %CFLAGS% -c -o %BUILD_DIR%\advanced_sampler.obj %SRC_DIR%\deep2\advanced_sampler.cpp 2>&1
if errorlevel 1 (
    echo FAILED: advanced_sampler.cpp
    goto :error
)
echo OK: advanced_sampler.obj

echo.
echo ============================================
echo [2/8] Building Deep2 Provider...
echo ============================================
%GPP% %CFLAGS% -c -o %BUILD_DIR%\Deep2Provider.obj %SRC_DIR%\deep2\Deep2Provider.cpp 2>&1
if errorlevel 1 (
    echo FAILED: Deep2Provider.cpp
    goto :error
)
echo OK: Deep2Provider.obj

echo.
echo ============================================
echo [3/8] Building Context Engine...
echo ============================================
%GPP% %CFLAGS% -c -o %BUILD_DIR%\ContextEngine.obj %SRC_DIR%\context\ContextEngine.cpp 2>&1
if errorlevel 1 (
    echo FAILED: ContextEngine.cpp
    goto :error
)
echo OK: ContextEngine.obj

echo.
echo ============================================
echo [4/8] Building Compiler Agent...
echo ============================================
%GPP% %CFLAGS% -c -o %BUILD_DIR%\CompilerAgent.obj %SRC_DIR%\agent\CompilerAgent.cpp 2>&1
if errorlevel 1 (
    echo FAILED: CompilerAgent.cpp
    goto :error
)
echo OK: CompilerAgent.obj

echo.
echo ============================================
echo [5/8] Building AI Service Adapter...
echo ============================================
%GPP% %CFLAGS% -c -o %BUILD_DIR%\AIServiceAdapter.obj %SRC_DIR%\unified\AIServiceAdapter.cpp 2>&1
if errorlevel 1 (
    echo FAILED: AIServiceAdapter.cpp
    goto :error
)
echo OK: AIServiceAdapter.obj

echo.
echo ============================================
echo [6/8] Building RawrXD Host...
echo ============================================
%GPP% %CFLAGS% -c -o %BUILD_DIR%\RawrXDHost.obj %SRC_DIR%\unified\RawrXDHost.cpp 2>&1
if errorlevel 1 (
    echo FAILED: RawrXDHost.cpp
    goto :error
)
echo OK: RawrXDHost.obj

echo.
echo ============================================
echo [7/8] Building Main Entry Point...
echo ============================================
%GPP% %CFLAGS% -c -o %BUILD_DIR%\main_unified.obj %SRC_DIR%\unified\main_unified.cpp 2>&1
if errorlevel 1 (
    echo FAILED: main_unified.cpp
    goto :error
)
echo OK: main_unified.obj

echo.
echo ============================================
echo [8/8] LINKING RawrXDUnified.exe...
echo ============================================
%GPP% %LDFLAGS% -o %BUILD_DIR%\%OUT_EXE% ^
    %BUILD_DIR%\main_unified.obj ^
    %BUILD_DIR%\RawrXDHost.obj ^
    %BUILD_DIR%\AIServiceAdapter.obj ^
    %BUILD_DIR%\CompilerAgent.obj ^
    %BUILD_DIR%\ContextEngine.obj ^
    %BUILD_DIR%\Deep2Provider.obj ^
    %BUILD_DIR%\Deep2Engine.obj ^
    %BUILD_DIR%\Tokenizer.obj ^
    %BUILD_DIR%\advanced_sampler.obj ^
    -lws2_32 -lwinmm 2>&1

if errorlevel 1 (
    echo FAILED: Linking %OUT_EXE%
    goto :error
)

echo.
echo ============================================
echo BUILD SUCCESSFUL!
echo ============================================
echo.
echo Output: %BUILD_DIR%\%OUT_EXE%
echo.

:: Verify the executable was created
if exist "%BUILD_DIR%\%OUT_EXE%" (
    echo Executable size:
    dir "%BUILD_DIR%\%OUT_EXE%" | findstr /C:"%OUT_EXE%"
    echo.
    echo Testing executable...
    "%BUILD_DIR%\%OUT_EXE%" --version 2>nul || echo Version check skipped (expected)
    echo.
    echo ============================================
    echo RawrXDUnified.exe IS READY!
    echo ============================================
) else (
    echo ERROR: Executable not found after build!
    goto :error
)

goto :end

:error
echo.
echo ============================================
echo BUILD FAILED!
echo ============================================
exit /b 1

:end
echo.
echo Done.
