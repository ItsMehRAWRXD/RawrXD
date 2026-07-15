@echo off
:: ============================================================================
:: build_kv_cache_masm.bat — Pure MASM KV-Cache Verification Build
:: ============================================================================
::
;; No C++. No CRT. Just MASM + Windows API.
::
;; ============================================================================

echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║  RawrXD KV-Cache Verification (Pure MASM)                            ║
echo ║  Power-of-2 Modulo + AVX-512 Validation                              ║
echo ╚═══════════════════════════════════════════════════════════════════╝
echo.

set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe
set LIBPATH=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64

if not exist "%ML64%" (
    echo ERROR: ml64.exe not found
    exit /b 1
)

set SRC_DIR=D:\rawrxd\src
set BUILD_DIR=D:\rawrxd\build-kv-masm

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [1/3] Assembling test harness...
"%ML64%" /c /Fo"%BUILD_DIR%\test_kv_cache_masm.obj" /W3 /Zd /Zi "%SRC_DIR%\test_kv_cache_masm.asm"
if errorlevel 1 (
    echo ERROR: Test harness assembly failed
    exit /b 1
)
echo       ^> test_kv_cache_masm.obj

echo.
echo [2/3] Assembling KV-Cache implementation...
"%ML64%" /c /Fo"%BUILD_DIR%\kv_cache_standalone.obj" /W3 /Zd /Zi "%SRC_DIR%\kv_cache_standalone.asm"
if errorlevel 1 (
    echo ERROR: KV-Cache assembly failed
    exit /b 1
)
echo       ^> kv_cache_standalone.obj created

echo.
echo [3/3] Linking executable...
"%LINK%" /OUT:"%BUILD_DIR%\TestKVCache.exe" /SUBSYSTEM:CONSOLE /ENTRY:TestKVCacheMain /MACHINE:X64 /nologo /LIBPATH:"%LIBPATH%" "%BUILD_DIR%\test_kv_cache_masm.obj" "%BUILD_DIR%\kv_cache_standalone.obj" kernel32.lib user32.lib
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

cd "%BUILD_DIR%"
TestKVCache.exe

echo.
echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║  Verification Complete!                                              ║
echo ╚═══════════════════════════════════════════════════════════════════╝

exit /b 0
