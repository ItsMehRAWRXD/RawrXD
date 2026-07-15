@echo off
REM =============================================================================
REM build_sovereign_engine_integrated.bat
REM Phase 22/23: Complete Integrated Build
REM Builds Phase 11 (ASM) + Phase 22 (Controller) + Phase 23 (Ring Attention)
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
set "INCLUDES=/I"%SRC_DIR%" /I"%SRC_DIR%\core" /I"%SRC_DIR%\swarm" /I"%ASM_DIR%" /I"%THIRD_PARTY%\include""

REM Compiler flags
set "CFLAGS=/std:c++17 /O2 /EHsc /W3 /MP /MD /DNDEBUG /DWIN32_LEAN_AND_MEAN /DSOVEREIGN_RING_ATTENTION_ENABLED"
set "DEBUG_CFLAGS=/std:c++17 /Od /EHsc /W3 /MP /MDd /Zi /D_DEBUG /DWIN32_LEAN_AND_MEAN /DSOVEREIGN_RING_ATTENTION_ENABLED"

REM Linker flags
set "LDFLAGS=/MACHINE:X64 /OPT:REF /OPT:ICF /LARGEADDRESSAWARE"
set "DEBUG_LDFLAGS=/MACHINE:X64 /DEBUG /LARGEADDRESSAWARE"

REM Libraries
set "LIBS=kernel32.lib user32.lib advapi32.lib ws2_32.lib"

REM =============================================================================
REM Create build directory
REM =============================================================================

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%BUILD_DIR%\obj" mkdir "%BUILD_DIR%\obj"
if not exist "%BUILD_DIR%\bin" mkdir "%BUILD_DIR%\bin"

echo.
echo =============================================================================
echo Sovereign Engine - Integrated Build
echo Phase 11 (ASM) + Phase 22 (Controller) + Phase 23 (Ring Attention)
echo =============================================================================

REM =============================================================================
REM Phase 11: Assemble ASM Files
REM =============================================================================

echo.
echo [Phase 11] Assembling x64 ASM Components...
echo -----------------------------------------------------------------------------

set "ASM_FILES=RawrXD_120B_Loader RawrXD_Ring_Attention_Simple RawrXD_Error_Recovery RawrXD_Recovery_Telemetry"

for %%f in (%ASM_FILES%) do (
    if exist "%ASM_DIR%\%%f.asm" (
        echo   Assembling %%f.asm...
        "%ML64%" /c /W3 /nologo /Fo"%BUILD_DIR%\obj\%%f.obj" "%ASM_DIR%\%%f.asm"
        if errorlevel 1 (
            echo   ERROR: Failed to assemble %%f.asm
            exit /b 1
        )
        echo   OK: %%f.obj
    ) else (
        echo   WARNING: %%f.asm not found, skipping
    )
)

REM =============================================================================
REM Phase 22/23: Compile C++ Components
REM =============================================================================

echo.
echo [Phase 22/23] Compiling C++ Components...
echo -----------------------------------------------------------------------------

set "CPP_FILES=sovereign_thread_pool sovereign_memory_pool sovereign_kv_cache_manager"
set "CPP_FILES=%CPP_FILES% sovereign_engine_controller_integration"
set "CPP_FILES=%CPP_FILES% sovereign_ring_attention_integration"
set "CPP_FILES=%CPP_FILES% sovereign_engine_controller_ring_extension"

for %%f in (%CPP_FILES%) do (
    if exist "%SRC_DIR%\core\%%f.cpp" (
        echo   Compiling %%f.cpp...
        "%CL%" %CFLAGS% %INCLUDES% /c /Fo"%BUILD_DIR%\obj\%%f.obj" "%SRC_DIR%\core\%%f.cpp"
        if errorlevel 1 (
            echo   ERROR: Failed to compile %%f.cpp
            exit /b 1
        )
        echo   OK: %%f.obj
    ) else (
        echo   WARNING: %%f.cpp not found, skipping
    )
)

REM =============================================================================
REM Phase 23: Compile Swarm Components
REM =============================================================================

echo.
echo [Phase 23] Compiling Swarm Components...
echo -----------------------------------------------------------------------------

set "SWARM_FILES=sovereign_swarm_head sovereign_swarm_worker"

for %%f in (%SWARM_FILES%) do (
    if exist "%SRC_DIR%\swarm\%%f.cpp" (
        echo   Compiling %%f.cpp...
        "%CL%" %CFLAGS% %INCLUDES% /c /Fo"%BUILD_DIR%\obj\%%f.obj" "%SRC_DIR%\swarm\%%f.cpp"
        if errorlevel 1 (
            echo   WARNING: Failed to compile %%f.cpp
        ) else (
            echo   OK: %%f.obj
        )
    ) else (
        echo   WARNING: %%f.cpp not found, skipping
    )
)

REM =============================================================================
REM Link: Create Static Library
REM =============================================================================

echo.
echo [Link] Creating Static Library...
echo -----------------------------------------------------------------------------

set "OBJ_FILES="
for %%f in (%BUILD_DIR%\obj\*.obj) do (
    set "OBJ_FILES=!OBJ_FILES! "%%f""
)

echo   Creating sovereign_engine.lib...
"%LIB%" /OUT:"%BUILD_DIR%\sovereign_engine.lib" %OBJ_FILES%
if errorlevel 1 (
    echo   ERROR: Failed to create library
    exit /b 1
)
echo   OK: sovereign_engine.lib

REM =============================================================================
REM Link: Create DLL
REM =============================================================================

echo.
echo [Link] Creating DLL...
echo -----------------------------------------------------------------------------

echo   Creating sovereign_engine.dll...
"%LINK%" /DLL %LDFLAGS% /OUT:"%BUILD_DIR%\bin\sovereign_engine.dll" /IMPLIB:"%BUILD_DIR%\sovereign_engine_dll.lib" %OBJ_FILES% %LIBS%
if errorlevel 1 (
    echo   ERROR: Failed to create DLL
    exit /b 1
)
echo   OK: sovereign_engine.dll

REM =============================================================================
REM Build Integration Tests
REM =============================================================================

echo.
echo [Tests] Building Integration Tests...
echo -----------------------------------------------------------------------------

set "TEST_FILES=test_engine_controller test_engine_controller_integration test_ring_integration"

for %%f in (%TEST_FILES%) do (
    if exist "%SRC_DIR%\tests\%%f.cpp" (
        echo   Building %%f.exe...
        "%CL%" %CFLAGS% %INCLUDES% /Fe"%BUILD_DIR%\bin\%%f.exe" "%SRC_DIR%\tests\%%f.cpp" "%BUILD_DIR%\sovereign_engine.lib" %LIBS%
        if errorlevel 1 (
            echo   WARNING: Failed to build %%f.exe
        ) else (
            echo   OK: %%f.exe
        )
    ) else (
        echo   WARNING: %%f.cpp not found, skipping
    )
)

REM =============================================================================
REM Build Benchmarks
REM =============================================================================

echo.
echo [Benchmarks] Building Performance Tests...
echo -----------------------------------------------------------------------------

if exist "%SRC_DIR%\tests\swarm_benchmark_optimized.cpp" (
    echo   Building swarm_benchmark.exe...
    "%CL%" %CFLAGS% %INCLUDES% /Fe"%BUILD_DIR%\bin\swarm_benchmark.exe" "%SRC_DIR%\tests\swarm_benchmark_optimized.cpp" "%BUILD_DIR%\sovereign_engine.lib" %LIBS%
    if errorlevel 1 (
        echo   WARNING: Failed to build swarm_benchmark.exe
    ) else (
        echo   OK: swarm_benchmark.exe
    )
)

REM =============================================================================
REM Summary
REM =============================================================================

echo.
echo =============================================================================
echo BUILD COMPLETE
echo =============================================================================
echo.
echo Output Files:
echo   Library: %BUILD_DIR%\sovereign_engine.lib
echo   DLL:     %BUILD_DIR%\bin\sovereign_engine.dll
echo.
echo Test Executables:
for %%f in (%BUILD_DIR%\bin\test_*.exe) do (
    echo   - %%f
)
echo.
echo Benchmarks:
for %%f in (%BUILD_DIR%\bin\*benchmark*.exe) do (
    echo   - %%f
)
echo.
echo Next Steps:
echo   1. Run tests: cd %BUILD_DIR%\bin ^&^& test_engine_controller_integration.exe
echo   2. Run benchmark: swarm_benchmark.exe
echo   3. Deploy to staging for 24-hour soak test
echo.
echo =============================================================================

endlocal
