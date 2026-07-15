@echo off
:: ============================================================================
:: build_unified_orchestrator.bat — Build the Unified Orchestrator
:: ============================================================================
::
;; Links all verified components into AgenticUnified.exe
::
;; ============================================================================

echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║  RawrXD Unified Orchestrator Build                                   ║
echo ║  GGUF Loader + KV-Cache + Aperture + Agentic Core                    ║
echo ╚═══════════════════════════════════════════════════════════════════╝
echo.

set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe
set LIBPATH=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64

if not exist "%ML64%" (
    echo ERROR: ml64.exe not found
    exit /b 1
)

set SRC_DIR=D:\rawrxd\src\core
set BUILD_DIR=D:\rawrxd\build-unified-orchestrator

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [1/4] Assembling Orchestrator...
"%ML64%" /c /Fo"%BUILD_DIR%\agentic_orchestrator.obj" /W3 /Zd /Zi "%SRC_DIR%\agentic_orchestrator.asm"
if errorlevel 1 (
    echo ERROR: Orchestrator assembly failed
    exit /b 1
)
echo       ^> agentic_orchestrator.obj

echo.
echo [2/4] Assembling KV-Cache...
"%ML64%" /c /Fo"%BUILD_DIR%\kv_cache_standalone.obj" /W3 /Zd /Zi "D:\rawrxd\src\kv_cache_standalone.asm"
if errorlevel 1 (
    echo ERROR: KV-Cache assembly failed
    exit /b 1
)
echo       ^> kv_cache_standalone.obj

echo.
echo [3/4] Assembling Aperture Kernel...
"%ML64%" /c /Fo"%BUILD_DIR%\aperture_q4_0_avx512_v2.obj" /W3 /Zd /Zi "%SRC_DIR%\aperture_q4_0_avx512_v2.asm"
if errorlevel 1 (
    echo ERROR: Aperture kernel assembly failed
    exit /b 1
)
echo       ^> aperture_q4_0_avx512_v2.obj

echo.
echo [4/4] Linking Unified Executable...
"%LINK%" /OUT:"%BUILD_DIR%\AgenticUnified.exe" /SUBSYSTEM:CONSOLE /ENTRY:AgenticUnifiedMain /MACHINE:X64 /nologo /LIBPATH:"%LIBPATH%" "%BUILD_DIR%\agentic_orchestrator.obj" "%BUILD_DIR%\kv_cache_standalone.obj" "%BUILD_DIR%\aperture_q4_0_avx512_v2.obj" kernel32.lib user32.lib
if errorlevel 1 (
    echo ERROR: Link failed
    exit /b 1
)
echo       ^> AgenticUnified.exe created

echo.
echo [5/4] Verifying build...
if exist "%BUILD_DIR%\AgenticUnified.exe" (
    echo       ^> Build SUCCESS
    for %%F in ("%BUILD_DIR%\AgenticUnified.exe") do (
        echo       ^> Size: %%~zF bytes
    )
) else (
    echo       ^> Build FAILED
    exit /b 1
)

echo.
echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║  Build Complete! Running orchestrator...                            ║
echo ╚═══════════════════════════════════════════════════════════════════╝
echo.

cd "%BUILD_DIR%"
AgenticUnified.exe

echo.
echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║  Orchestration Complete!                                             ║
echo ╚═══════════════════════════════════════════════════════════════════╝

exit /b 0
