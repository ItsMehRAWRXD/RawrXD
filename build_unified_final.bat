@echo off
:: ============================================================================
:: build_unified_final.bat — FINAL Unified Build with LIVE AVX-512
:: ============================================================================

echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║  RawrXD UNIFIED — FINAL LIVE Integration                            ║
echo ║  AVX-512 Kernel + Sovereign Core + Zero CRT                         ║
echo ╚═══════════════════════════════════════════════════════════════════╝
echo.

set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe
set LIBPATH=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64

set SRC=D:\rawrxd\src\core
set BUILD=D:\rawrxd\build-unified-final

if not exist "%BUILD%" mkdir "%BUILD%"

echo [1/3] Assembling Unified Entry Point...
"%ML64%" /c /Fo"%BUILD%\agentic_unified_entry.obj" /W3 /Zd /Zi "%SRC%\agentic_unified_entry.asm"
if errorlevel 1 exit /b 1
echo       ^> agentic_unified_entry.obj

echo.
echo [2/3] Assembling LIVE Aperture Bridge...
"%ML64%" /c /Fo"%BUILD%\agentic_aperture_live.obj" /W3 /Zd /Zi "%SRC%\agentic_aperture_live.asm"
if errorlevel 1 exit /b 1
echo       ^> agentic_aperture_live.obj

echo.
echo [3/3] Assembling AVX-512 Kernel...
"%ML64%" /c /Fo"%BUILD%\aperture_q4_0_avx512_v2.obj" /W3 /Zd /Zi "%SRC%\aperture_q4_0_avx512_v2.asm"
if errorlevel 1 exit /b 1
echo       ^> aperture_q4_0_avx512_v2.obj

echo.
echo [4/3] Linking FINAL Executable...
"%LINK%" /OUT:"%BUILD%\AgenticUnified.exe" /SUBSYSTEM:CONSOLE /ENTRY:AgenticUnifiedMain /MACHINE:X64 /LIBPATH:"%LIBPATH%" "%BUILD%\agentic_unified_entry.obj" "%BUILD%\agentic_aperture_live.obj" "%BUILD%\aperture_q4_0_avx512_v2.obj" kernel32.lib user32.lib
if errorlevel 1 exit /b 1
echo       ^> AgenticUnified.exe created

echo.
if exist "%BUILD%\AgenticUnified.exe" (
    for %%F in ("%BUILD%\AgenticUnified.exe") do (
        echo       ^> Size: %%~zF bytes
    )
    echo.
    echo ╔═══════════════════════════════════════════════════════════════════╗
    echo ║  FINAL Build SUCCESS!                                                ║
    echo ║  LIVE AVX-512 Kernel Connected!                                      ║
    echo ╚═══════════════════════════════════════════════════════════════════╝
)

exit /b 0
