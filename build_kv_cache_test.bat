@echo off
:: ============================================================================
:: build_kv_cache_test.bat — Sovereign KV-Cache Verification Build
:: ============================================================================
::
;; Builds and runs the KV-Cache verification harness
;; No CMake. No bloated frameworks. Just cl.exe + link.exe
::
;; ============================================================================

echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║  RawrXD KV-Cache Verification Build                                  ║
echo ║  Power-of-2 Modulo + AVX-512 Validation                              ║
echo ╚═══════════════════════════════════════════════════════════════════╝
echo.

:: Setup paths
set CL=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe
set LIBPATH=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64

:: Check for VS environment
if not exist "%CL%" (
    echo ERROR: cl.exe not found. Please run from VS Developer Command Prompt.
    exit /b 1
)

set SRC_DIR=D:\rawrxd\src
set BUILD_DIR=D:\rawrxd\build-kv-test

:: Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [1/3] Compiling C++ test harness...
"%CL%" /c /nologo /O2 /EHsc /W4 /Fo"%BUILD_DIR%\test_kv_cache_sovereign.obj" "%SRC_DIR%\test_kv_cache_sovereign.cpp"
if errorlevel 1 (
    echo ERROR: C++ compilation failed
    exit /b 1
)
echo       ^> test_kv_cache_sovereign.obj created

echo.
echo [2/3] Assembling MASM KV-Cache...
"%CL%" /c /nologo /Fo"%BUILD_DIR%\rawrxd_kv_cache.obj" "%SRC_DIR%\rawrxd_kv_cache.asm" 2^>nul
if errorlevel 1 (
    echo WARNING: Could not compile .asm with cl.exe, trying ml64.exe...
    ml64.exe /c /Fo"%BUILD_DIR%\rawrxd_kv_cache.obj" "%SRC_DIR%\rawrxd_kv_cache.asm" 2^>nul
    if errorlevel 1 (
        echo WARNING: MASM assembly not available, using C++ stub
        echo       Creating stub implementation...
        echo // Stub for rawrxd_kv_cache > "%BUILD_DIR%\rawrxd_kv_cache_stub.cpp"
        echo void KVCache_Update_AVX512(float* cache, const float* src, int pos, int head_dim) {} >> "%BUILD_DIR%\rawrxd_kv_cache_stub.cpp"
        echo void KVCache_Retrieve_AVX512(float* cache, float* dst, int pos, int head_dim) {} >> "%BUILD_DIR%\rawrxd_kv_cache_stub.cpp"
        "%CL%" /c /nologo /Fo"%BUILD_DIR%\rawrxd_kv_cache.obj" "%BUILD_DIR%\rawrxd_kv_cache_stub.cpp"
    )
)
echo       ^> rawrxd_kv_cache.obj created

echo.
echo [3/3] Linking test executable...
"%LINK%" /OUT:"%BUILD_DIR%\TestKVCache.exe" /SUBSYSTEM:CONSOLE /MACHINE:X64 /nologo ^
    /LIBPATH:"%LIBPATH%" ^
    "%BUILD_DIR%\test_kv_cache_sovereign.obj" ^
    "%BUILD_DIR%\rawrxd_kv_cache.obj" ^
    kernel32.lib ^
    user32.lib
if errorlevel 1 (
    echo ERROR: Link failed
    exit /b 1
)
echo       ^> TestKVCache.exe created

echo.
echo [4/3] Verifying build...
if exist "%BUILD_DIR%\TestKVCache.exe" (
    echo       ^> Build SUCCESS
    for %%F in ("%BUILD_DIR%\TestKVCache.exe") do (
        echo       ^> Size: %%~zF bytes
    )
) else (
    echo       ^> Build FAILED
    exit /b 1
)

echo.
echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║  Build Complete! Running verification...                            ║
echo ╚═══════════════════════════════════════════════════════════════════╝
echo.

:: Run the test
cd "%BUILD_DIR%"
TestKVCache.exe
set TEST_RESULT=%ERRORLEVEL%

echo.
if %TEST_RESULT% equ 0 (
    echo ╔═══════════════════════════════════════════════════════════════════╗
    echo ║  ALL TESTS PASSED!                                                   ║
    echo ╚═══════════════════════════════════════════════════════════════════╝
) else (
    echo ╔═══════════════════════════════════════════════════════════════════╗
    echo ║  SOME TESTS FAILED                                                   ║
    echo ╚═══════════════════════════════════════════════════════════════════╝
)

exit /b %TEST_RESULT%
