@echo off
REM Build script for Fix #5B Phase 2: Page-Based Async KV Cache Residency Validation
REM This compiles the residency validation tests before implementing quantization kernels

setlocal EnableDelayedExpansion

echo ============================================
echo Fix #5B Phase 2 Residency Validation Build
echo ============================================
echo.

REM Set up paths
set "SOURCE_DIR=%~dp0"
set "BUILD_DIR=%SOURCE_DIR%build-fix5b-residency"
set "SRC_MEMORY=%SOURCE_DIR%src\memory"
set "TESTS_DIR=%SOURCE_DIR%tests"

REM MSVC is known to be at this location
set "MSVC_ROOT=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717"

if not exist "%MSVC_ROOT%\bin\Hostx64\x64\cl.exe" (
    echo ERROR: Could not find MSVC compiler at %MSVC_ROOT%
    exit /b 1
)

echo Found MSVC at: %MSVC_ROOT%

REM Find Windows SDK
set "SDK_ROOT="
for %%p in (
    "D:\Program Files (x86)\Windows Kits\10"
    "C:\Program Files (x86)\Windows Kits\10"
) do (
    if exist "%%~p\Include\10.0.22621.0\ucrt" (
        set "SDK_ROOT=%%~p"
        set "SDK_VER=10.0.22621.0"
        goto :found_sdk
    )
)
:found_sdk

if "%SDK_ROOT%"=="" (
    echo ERROR: Could not find Windows SDK
    exit /b 1
)

echo Found Windows SDK at: %SDK_ROOT%

REM Set up environment
set "PATH=%MSVC_ROOT%\bin\Hostx64\x64;%PATH%"
set "INCLUDE=%MSVC_ROOT%\include;%SDK_ROOT%\Include\%SDK_VER%\ucrt;%SDK_ROOT%\Include\%SDK_VER%\shared;%SDK_ROOT%\Include\%SDK_VER%\um"
set "LIB=%MSVC_ROOT%\lib\x64;%MSVC_ROOT%\lib\onecore\x64;%SDK_ROOT%\Lib\%SDK_VER%\ucrt\x64;%SDK_ROOT%\Lib\%SDK_VER%\um\x64"

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo.
echo ============================================
echo Compiling Fix #5B Residency Tests
echo ============================================
echo.

REM Compiler flags
set "CXXFLAGS=/std:c++17 /EHsc /W4 /O2 /MD /I"%SOURCE_DIR%src" /I"%SOURCE_DIR%include" /I"%SOURCE_DIR%src\memory" /D_CRT_SECURE_NO_WARNINGS /DNOMINMAX"

REM Source files for the test
set "SOURCES="
set "SOURCES=%SOURCES% "%TESTS_DIR%\test_fix5b_residency_v2.cpp""
set "SOURCES=%SOURCES% "%SRC_MEMORY%\RawrXD_KVCache_Residency_v2.cpp""

REM Output executable
set "OUTPUT=%BUILD_DIR%\test_fix5b_residency_v2.exe"

echo Compiling...
echo Sources: %SOURCES%
echo Output: %OUTPUT%
echo.

cl.exe %CXXFLAGS% %SOURCES% /Fe"%OUTPUT%" /link /SUBSYSTEM:CONSOLE

if %ERRORLEVEL% neq 0 (
    echo.
    echo ============================================
    echo BUILD FAILED
    echo ============================================
    exit /b 1
)

echo.
echo ============================================
echo BUILD SUCCESSFUL
echo ============================================
echo.
echo Executable: %OUTPUT%
echo.
echo Running validation tests...
echo.

"%OUTPUT%"

set "TEST_RESULT=%ERRORLEVEL%"

if %TEST_RESULT% equ 0 (
    echo.
    echo ============================================
    echo ALL VALIDATION TESTS PASSED
    echo ============================================
    echo.
    echo Ready to proceed with quantization kernel implementation.
) else (
    echo.
    echo ============================================
    echo VALIDATION TESTS FAILED (exit code: %TEST_RESULT%)
    echo ============================================
    echo.
    echo Please review the errors above.
)

exit /b %TEST_RESULT%
