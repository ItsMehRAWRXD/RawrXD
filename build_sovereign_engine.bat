@echo off
REM =============================================================================
REM build_sovereign_engine.bat
REM Phase 22: Build script for Sovereign Engine Controller
REM Links Phase 11 (ASM Loader) with Phase 22/23 (C++ Engine + Swarm)
REM =============================================================================

setlocal EnableDelayedExpansion

REM Configuration
set "PROJECT_ROOT=D:\RawrXD"
set "BUILD_DIR=%PROJECT_ROOT%\build"
set "SRC_DIR=%PROJECT_ROOT%\src"
set "ASM_DIR=%PROJECT_ROOT%\asm"
set "THIRD_PARTY=%PROJECT_ROOT%\third_party"

REM Toolchain
set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "CL=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe"
set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "LIB=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\lib.exe"

REM Include paths
set "INCLUDES=/I"%SRC_DIR%" /I"%SRC_DIR%\core" /I"%SRC_DIR%\swarm" /I"%THIRD_PARTY%\include""

REM Compiler flags
set "CFLAGS=/std:c++17 /O2 /EHsc /W3 /MP /MD /DNDEBUG /DWIN32_LEAN_AND_MEAN"
set "DEBUG_CFLAGS=/std:c++17 /Od /EHsc /W3 /MP /MDd /Zi /D_DEBUG /DWIN32_LEAN_AND_MEAN"

REM Linker flags
set "LDFLAGS=/MACHINE:X64 /OPT:REF /OPT:ICF /LARGEADDRESSAWARE"
set "DEBUG_LDFLAGS=/MACHINE:X64 /DEBUG /LARGEADDRESSAWARE"

REM Libraries
set "LIBS=kernel32.lib user32.lib advapi32.lib ws2_32.lib"

REM ZeroMQ (if available)
if exist "%THIRD_PARTY%\lib\libzmq.lib" (
    set "LIBS=!LIBS! %THIRD_PARTY%\lib\libzmq.lib"
    set "CFLAGS=!CFLAGS! /DSOVEREIGN_SWARM_ENABLED"
)

REM =============================================================================
REM Create build directory
REM =============================================================================

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%BUILD_DIR%\obj" mkdir "%BUILD_DIR%\obj"

REM =============================================================================
REM Phase 11: Assemble ASM files
REM =============================================================================

echo.
echo =============================================================================
echo Phase 11: Assembling x64 ASM Loader
echo =============================================================================

if not exist "%ASM_DIR%\RawrXD_120B_Loader.asm" (
    echo ERROR: RawrXD_120B_Loader.asm not found!
    exit /b 1
)

REM Assemble the Phase 11 loader
echo Assembling RawrXD_120B_Loader.asm...
"%ML64%" /c /Fo"%BUILD_DIR%\obj\RawrXD_120B_Loader.obj" "%ASM_DIR%\RawrXD_120B_Loader.asm"
if errorlevel 1 (
    echo ERROR: Assembly failed!
    exit /b 1
)

echo Phase 11 assembly complete.

REM =============================================================================
REM Phase 22: Compile C++ Core
REM =============================================================================

echo.
echo =============================================================================
echo Phase 22: Compiling C++ Engine Core
echo =============================================================================

REM Core files to compile
set "CORE_FILES=^"
set "CORE_FILES=%CORE_FILES% %SRC_DIR%\core\sovereign_thread_pool.cpp"
set "CORE_FILES=%CORE_FILES% %SRC_DIR%\core\sovereign_memory_pool.cpp"
set "CORE_FILES=%CORE_FILES% %SRC_DIR%\core\sovereign_kv_cache_manager.cpp"
set "CORE_FILES=%CORE_FILES% %SRC_DIR%\core\sovereign_engine_controller_integration.cpp"

REM Compile each core file
for %%f in (%CORE_FILES%) do (
    if exist "%%f" (
        echo Compiling %%~nxf...
        "%CL%" %CFLAGS% %INCLUDES% /c /Fo"%BUILD_DIR%\obj\%%~nf.obj" "%%f"
        if errorlevel 1 (
            echo ERROR: Compilation failed for %%~nxf
            exit /b 1
        )
    ) else (
        echo WARNING: %%f not found, skipping...
    )
)

echo Phase 22 core compilation complete.

REM =============================================================================
REM Phase 23: Compile Swarm (if enabled)
REM =============================================================================

echo.
echo =============================================================================
echo Phase 23: Compiling Swarm Components
echo =============================================================================

set "SWARM_FILES=^"
set "SWARM_FILES=%SWARM_FILES% %SRC_DIR%\swarm\sovereign_swarm_head.cpp"
set "SWARM_FILES=%SWARM_FILES% %SRC_DIR%\swarm\sovereign_swarm_worker.cpp"

for %%f in (%SWARM_FILES%) do (
    if exist "%%f" (
        echo Compiling %%~nxf...
        "%CL%" %CFLAGS% %INCLUDES% /c /Fo"%BUILD_DIR%\obj\%%~nf.obj" "%%f"
        if errorlevel 1 (
            echo WARNING: Swarm compilation failed for %%~nxf
        )
    ) else (
        echo WARNING: %%f not found, skipping...
    )
)

echo Phase 23 swarm compilation complete.

REM =============================================================================
REM Link: Create Static Library
REM =============================================================================

echo.
echo =============================================================================
echo Linking: Creating Sovereign Engine Library
echo =============================================================================

REM Collect all object files
set "OBJ_FILES="
for %%f in (%BUILD_DIR%\obj\*.obj) do (
    set "OBJ_FILES=!OBJ_FILES! "%%f""
)

REM Create static library
echo Creating sovereign_engine.lib...
"%LIB%" /OUT:"%BUILD_DIR%\sovereign_engine.lib" %OBJ_FILES%
if errorlevel 1 (
    echo ERROR: Library creation failed!
    exit /b 1
)

echo Static library created: %BUILD_DIR%\sovereign_engine.lib

REM =============================================================================
REM Link: Create DLL (for Python bindings)
REM =============================================================================

echo.
echo =============================================================================
echo Linking: Creating Sovereign Engine DLL
echo =============================================================================

REM Create DLL with exports
echo Creating sovereign_engine.dll...
"%LINK%" /DLL %LDFLAGS% /OUT:"%BUILD_DIR%\sovereign_engine.dll" /IMPLIB:"%BUILD_DIR%\sovereign_engine_dll.lib" %OBJ_FILES% %LIBS%
if errorlevel 1 (
    echo ERROR: DLL creation failed!
    exit /b 1
)

echo DLL created: %BUILD_DIR%\sovereign_engine.dll

REM =============================================================================
REM Build Tests
REM =============================================================================

echo.
echo =============================================================================
echo Building Tests
echo =============================================================================

set "TEST_FILES=^"
set "TEST_FILES=%TEST_FILES% %SRC_DIR%\tests\test_engine_controller.cpp"
set "TEST_FILES=%TEST_FILES% %SRC_DIR%\tests\test_integration.cpp"

for %%f in (%TEST_FILES%) do (
    if exist "%%f" (
        echo Compiling test: %%~nxf...
        "%CL%" %CFLAGS% %INCLUDES% /Fe"%BUILD_DIR%\%%~nf.exe" "%%f" "%BUILD_DIR%\sovereign_engine.lib" %LIBS%
        if errorlevel 1 (
            echo WARNING: Test compilation failed for %%~nxf
        ) else (
            echo Test executable: %BUILD_DIR%\%%~nf.exe
        )
    )
)

REM =============================================================================
REM Build Benchmark
REM =============================================================================

echo.
echo =============================================================================
echo Building Benchmark
echo =============================================================================

if exist "%SRC_DIR%\tests\swarm_benchmark_optimized.cpp" (
    echo Compiling swarm benchmark...
    "%CL%" %CFLAGS% %INCLUDES% /Fe"%BUILD_DIR%\swarm_benchmark.exe" "%SRC_DIR%\tests\swarm_benchmark_optimized.cpp" "%BUILD_DIR%\sovereign_engine.lib" %LIBS%
    if errorlevel 1 (
        echo WARNING: Benchmark compilation failed
    ) else (
        echo Benchmark executable: %BUILD_DIR%\swarm_benchmark.exe
    )
)

REM =============================================================================
REM Summary
REM =============================================================================

echo.
echo =============================================================================
echo Build Complete!
echo =============================================================================
echo.
echo Output files:
echo   - %BUILD_DIR%\sovereign_engine.lib   (Static library)
echo   - %BUILD_DIR%\sovereign_engine.dll   (Dynamic library)
echo   - %BUILD_DIR%\sovereign_engine_dll.lib (Import library)
echo.
echo To run tests:
echo   cd %BUILD_DIR%
echo   test_engine_controller.exe
echo   test_integration.exe
echo.
echo To run benchmark:
echo   swarm_benchmark.exe
echo.

endlocal
