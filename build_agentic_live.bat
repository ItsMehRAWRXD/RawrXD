@echo off
:: ============================================================================
:: build_agentic_live.bat — Build LIVE Aperture Integration
:: ============================================================================
::
;; This builds the LIVE version with actual AVX-512 kernel calls
;;
;; ============================================================================

echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║  RawrXD Agentic + Aperture LIVE Integration                         ║
echo ║  AVX-512 Kernel Hot Path Connection                                 ║
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
set BUILD_DIR=D:\rawrxd\build-agentic-live

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [1/4] Assembling Sovereign Agentic Core...
"%ML64%" /c /Fo"%BUILD_DIR%\agentic_sovereign_entry.obj" /W3 /Zd /Zi "%SRC_DIR%\agentic_sovereign_entry.asm"
if errorlevel 1 (
    echo ERROR: Agentic core assembly failed
    exit /b 1
)
echo       ^> agentic_sovereign_entry.obj

echo.
echo [2/4] Assembling LIVE Aperture Bridge...
"%ML64%" /c /Fo"%BUILD_DIR%\agentic_aperture_live.obj" /W3 /Zd /Zi "%SRC_DIR%\agentic_aperture_live.asm"
if errorlevel 1 (
    echo ERROR: LIVE bridge assembly failed
    exit /b 1
)
echo       ^> agentic_aperture_live.obj

echo.
echo [3/4] Assembling AVX-512 Kernel...
"%ML64%" /c /Fo"%BUILD_DIR%\aperture_q4_0_avx512_v2.obj" /W3 /Zd /Zi "%SRC_DIR%\aperture_q4_0_avx512_v2.asm"
if errorlevel 1 (
    echo ERROR: Kernel assembly failed
    exit /b 1
)
echo       ^> aperture_q4_0_avx512_v2.obj

echo.
echo [4/4] Linking LIVE Executable...
echo       Entry: AgenticMain
"%LINK%" /OUT:"%BUILD_DIR%\AgenticLive.exe" ^
    /SUBSYSTEM:CONSOLE ^
    /ENTRY:AgenticMain ^
    /DEBUG ^
    /PDB:"%BUILD_DIR%\AgenticLive.pdb" ^
    /MACHINE:X64 /nologo ^
    /LIBPATH:"%LIBPATH%" ^
    "%BUILD_DIR%\agentic_sovereign_entry.obj" ^
    "%BUILD_DIR%\agentic_aperture_live.obj" ^
    "%BUILD_DIR%\aperture_q4_0_avx512_v2.obj" ^
    kernel32.lib ^
    user32.lib
if errorlevel 1 (
    echo ERROR: Link failed
    exit /b 1
)
echo       ^> AgenticLive.exe created

echo.
echo [5/4] Verifying build...
if exist "%BUILD_DIR%\AgenticLive.exe" (
    echo       ^> Build SUCCESS
    for %%F in ("%BUILD_DIR%\AgenticLive.exe") do (
        echo       ^> Size: %%~zF bytes
    )
) else (
    echo       ^> Build FAILED
    exit /b 1
)

echo.
echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║  LIVE Build Complete!                                                ║
echo ║                                                                    ║
echo ║  Output: %BUILD_DIR%\AgenticLive.exe               ║
echo ║                                                                    ║
echo ║  Features:                                                         ║
echo ║    ✓ Sovereign Agentic Core (MASM)                                  ║
echo ║    ✓ LIVE AVX-512 Kernel Integration                                ║
echo ║    ✓ vzeroupper state management                                    ║
echo ║    ✓ Register preservation (RBX, R12-R15)                             ║
echo ║    ✓ Aligned buffers (64-byte)                                      ║
echo ║                                                                    ║
echo ║  To run:                                                           ║
echo ║    %BUILD_DIR%\AgenticLive.exe                     ║
echo ╚═══════════════════════════════════════════════════════════════════╝

exit /b 0
