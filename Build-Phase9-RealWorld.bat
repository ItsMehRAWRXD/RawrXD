@echo off
REM =============================================================================
REM Build-Phase9-RealWorld.bat
REM Build script for RawRamXD Phase 9: Real-World Integration
REM =============================================================================

setlocal enabledelayedexpansion

echo =================================================================
echo RawRamXD Phase 9: Real-World Integration Build
echo =================================================================
echo.

REM Set up Visual Studio 2022 environment
set "VS_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717"
set "WINSDK_PATH=C:\Program Files (x86)\Windows Kits\10"
set "WINSDK_VER=10.0.22621.0"

set "PATH=%VS_PATH%\bin\Hostx64\x64;%PATH%"
set "INCLUDE=%VS_PATH%\include;%WINSDK_PATH%\Include\%WINSDK_VER%\ucrt;%WINSDK_PATH%\Include\%WINSDK_VER%\um;%WINSDK_PATH%\Include\%WINSDK_VER%\shared"
set "LIB=%VS_PATH%\lib\x64;%WINSDK_PATH%\Lib\%WINSDK_VER%\ucrt\x64;%WINSDK_PATH%\Lib\%WINSDK_VER%\um\x64"

set "PROJECT_ROOT=D:\rawrxd"
set "BUILD_DIR=%PROJECT_ROOT%\build_phase9"

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo Build Configuration:
echo   Compiler: Visual Studio 2022 (v14.51.36231)
echo   Platform: x64
echo   Build Dir: %BUILD_DIR%
echo.

REM Compiler flags
set "COMMON_FLAGS=/std:c++17 /EHsc /W4 /nologo /MP /O2 /MD /DNDEBUG /DUNICODE /D_UNICODE"
set "COMMON_FLAGS=%COMMON_FLAGS% /D_CRT_SECURE_NO_WARNINGS /DNOMINMAX"

REM Include paths
set "INCLUDES=/I"%PROJECT_ROOT%""

REM Source files
set "SOURCES=%PROJECT_ROOT%\RawRamXD_Phase9_RealWorldIntegration.cpp"
set "TEST_SOURCES=%PROJECT_ROOT%\RawRamXD_Phase9_RealWorldTest.cpp"

REM Output files
set "OUTPUT_LIB=%BUILD_DIR%\RawRamXD_Phase9.lib"
set "OUTPUT_DLL=%BUILD_DIR%\RawRamXD_Phase9.dll"
set "OUTPUT_TEST=%BUILD_DIR%\Phase9_Test.exe"

REM =============================================================================
REM Build Library (Object File)
REM =============================================================================
echo [1/3] Compiling Phase 9 Library...
cl.exe %COMMON_FLAGS% %INCLUDES% /c /Fo"%BUILD_DIR%\Phase9.obj" %SOURCES%
if errorlevel 1 (
    echo ERROR: Library compilation failed
    exit /b 1
)
echo   - Phase9.obj created
echo.

REM =============================================================================
REM Build Static Library
REM =============================================================================
echo [2/3] Creating Static Library...
lib.exe /nologo /out:"%OUTPUT_LIB%" "%BUILD_DIR%\Phase9.obj"
if errorlevel 1 (
    echo ERROR: Static library creation failed
    exit /b 1
)
echo   - RawRamXD_Phase9.lib created
echo.

REM =============================================================================
REM Build Test Executable
REM =============================================================================
echo [3/3] Compiling Test Executable...
cl.exe %COMMON_FLAGS% %INCLUDES% /Fe"%OUTPUT_TEST%" %TEST_SOURCES% "%BUILD_DIR%\Phase9.obj"
if errorlevel 1 (
    echo ERROR: Test executable compilation failed
    exit /b 1
)
echo   - Phase9_Test.exe created
echo.

REM =============================================================================
REM Summary
REM =============================================================================
echo =================================================================
echo Build Complete
echo =================================================================
echo Output files:
echo   - %OUTPUT_LIB%
echo   - %OUTPUT_DLL%
echo   - %OUTPUT_TEST%
echo.
echo To run tests:
echo   cd /d %BUILD_DIR%
echo   Phase9_Test.exe
echo.
echo To run individual gates:
echo   Phase9_Test.exe --j1  (LLM Integration)
echo   Phase9_Test.exe --j2  (Multi-Model Execution)
echo   Phase9_Test.exe --j3  (Dataset Validation)
echo   Phase9_Test.exe --j4  (Benchmarking)
echo   Phase9_Test.exe --j5  (Latency Profiling)
echo   Phase9_Test.exe --full (Full Integration)
echo   Phase9_Test.exe --capi (C API Test)
echo =================================================================

endlocal