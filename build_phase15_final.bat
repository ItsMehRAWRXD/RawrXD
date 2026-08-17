@echo off
::==============================================================================
:: build_phase15_final.bat - COMPLETE BUILD SCRIPT
:: Builds RawrXDUnified.exe from scratch in one command
:: Phase 15B: Real Executable Build
::==============================================================================

setlocal enabledelayedexpansion

set BUILD_DIR=build-unified-final
set SRC_DIR=src
set GCC=C:\ProgramData\mingw64\mingw64\bin\g++.exe
set CFLAGS=-std=c++20 -O2 -Wall -Isrc -Isrc\include -Isrc\deep2 -Isrc\core -Isrc\unified -Isrc\context -Isrc\agent -Isrc\inference -Isrc\tokenizer -DUNICODE -D_UNICODE -DPHASE15_UNIFIED -DNDEBUG

if not exist %BUILD_DIR% mkdir %BUILD_DIR%

echo Building RawrXDUnified.exe - Phase 15 Complete
echo ================================================

:: Step 1: Deep2 Engine
echo [1/8] Deep2 Engine...
%GCC% %CFLAGS% -c -o %BUILD_DIR%\Deep2Engine.obj %SRC_DIR%\deep2\Deep2Engine.cpp
%GCC% %CFLAGS% -c -o %BUILD_DIR%\Tokenizer.obj %SRC_DIR%\deep2\Tokenizer.cpp
%GCC% %CFLAGS% -c -o %BUILD_DIR%\advanced_sampler.obj %SRC_DIR%\deep2\advanced_sampler.cpp
%GCC% %CFLAGS% -c -o %BUILD_DIR%\Deep2InferenceGateway.obj %SRC_DIR%\deep2\Deep2InferenceGateway.cpp

:: Step 2: Deep2 Provider
echo [2/8] Deep2 Provider...
%GCC% %CFLAGS% -c -o %BUILD_DIR%\Deep2Provider.obj %SRC_DIR%\deep2\Deep2Provider.cpp

:: Step 3: Context Engine
echo [3/8] Context Engine...
%GCC% %CFLAGS% -c -o %BUILD_DIR%\ContextEngine.obj %SRC_DIR%\context\ContextEngine.cpp

:: Step 4: Compiler Agent
echo [4/8] Compiler Agent...
%GCC% %CFLAGS% -c -o %BUILD_DIR%\CompilerAgent.obj %SRC_DIR%\agent\CompilerAgent.cpp

:: Step 5: AI Service Adapter
echo [5/8] AI Service Adapter...
%GCC% %CFLAGS% -c -o %BUILD_DIR%\AIServiceAdapter.obj %SRC_DIR%\unified\AIServiceAdapter.cpp

:: Step 6: RawrXD Host
echo [6/8] RawrXD Host...
%GCC% %CFLAGS% -c -o %BUILD_DIR%\RawrXDHost.obj %SRC_DIR%\unified\RawrXDHost.cpp

:: Step 7: Main Entry Point
echo [7/8] Main Entry Point...
%GCC% %CFLAGS% -c -o %BUILD_DIR%\main_unified.obj %SRC_DIR%\unified\main_unified.cpp

:: Step 8: Inference Engine + Sampling
echo [8/8] Inference Engine...
%GCC% %CFLAGS% -c -o %BUILD_DIR%\InferenceEngine.obj %SRC_DIR%\inference\InferenceEngine.cpp
%GCC% %CFLAGS% -c -o %BUILD_DIR%\sampling.obj %SRC_DIR%\inference\sampling.cpp
%GCC% %CFLAGS% -c -o %BUILD_DIR%\LegacyAdapterStub.obj %SRC_DIR%\inference\LegacyAdapterStub.cpp

:: Link
echo.
echo Linking RawrXDUnified.exe...
%GCC% -static-libgcc -static-libstdc++ -Wl,--subsystem,console -o %BUILD_DIR%\RawrXDUnified.exe ^
    %BUILD_DIR%\main_unified.obj ^
    %BUILD_DIR%\RawrXDHost.obj ^
    %BUILD_DIR%\AIServiceAdapter.obj ^
    %BUILD_DIR%\CompilerAgent.obj ^
    %BUILD_DIR%\ContextEngine.obj ^
    %BUILD_DIR%\Deep2Provider.obj ^
    %BUILD_DIR%\Deep2Engine.obj ^
    %BUILD_DIR%\Deep2InferenceGateway.obj ^
    %BUILD_DIR%\InferenceEngine.obj ^
    %BUILD_DIR%\LegacyAdapterStub.obj ^
    %BUILD_DIR%\sampling.obj ^
    %BUILD_DIR%\Tokenizer.obj ^
    %BUILD_DIR%\advanced_sampler.obj ^
    -lws2_32 -lwinmm

if errorlevel 1 (
    echo FAILED
    exit /b 1
)

echo.
echo ================================================
echo BUILD SUCCESSFUL!
echo ================================================
echo Output: %BUILD_DIR%\RawrXDUnified.exe
dir %BUILD_DIR%\RawrXDUnified.exe
echo.
echo Test with: %BUILD_DIR%\RawrXDUnified.exe --help
echo.
