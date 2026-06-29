@echo off
:: ============================================================================
:: build_agentic_aperture.bat — Build Agentic + Aperture Integration
:: ============================================================================
::
;; Links the Sovereign Agentic Core with Aperture AVX-512 Kernels
;;
;; ============================================================================

echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║  RawrXD Agentic + Aperture Integration                              ║
echo ║  Sovereign Core + AVX-512 Inference                                 ║
echo ╚═══════════════════════════════════════════════════════════════════╝
echo.

:: Setup paths
set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe
set LIBPATH=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64

:: Check for tools
if not exist "%ML64%" (
    echo ERROR: ml64.exe not found
    exit /b 1
)

if not exist "%LINK%" (
    echo ERROR: link.exe not found
    exit /b 1
)

set SRC_DIR=D:\rawrxd\src\core
set BUILD_DIR=D:\rawrxd\build-agentic-aperture

:: Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [1/4] Assembling Sovereign Agentic Core...
"%ML64%" /c /Fo"%BUILD_DIR%\agentic_sovereign_entry.obj" /W3 /Zd /Zi "%SRC_DIR%\agentic_sovereign_entry.asm"
if errorlevel 1 (
    echo ERROR: Agentic core assembly failed
    exit /b 1
)
echo       ^> agentic_sovereign_entry.obj created

echo.
echo [2/4] Assembling Aperture Bridge...
"%ML64%" /c /Fo"%BUILD_DIR%\agentic_aperture_bridge.obj" /W3 /Zd /Zi "%SRC_DIR%\agentic_aperture_bridge.asm"
if errorlevel 1 (
    echo ERROR: Aperture bridge assembly failed
    exit /b 1
)
echo       ^> agentic_aperture_bridge.obj created

echo.
echo [3/4] Assembling Aperture AVX-512 Kernel...
if exist "%SRC_DIR%\aperture_q4_0_avx512_v2.asm" (
    "%ML64%" /c /Fo"%BUILD_DIR%\aperture_q4_0_avx512_v2.obj" /W3 /Zd /Zi "%SRC_DIR%\aperture_q4_0_avx512_v2.asm"
    if errorlevel 1 (
        echo WARNING: Aperture kernel assembly failed (continuing with stub)
        set APERTURE_OBJ=
    ) else (
        echo       ^> aperture_q4_0_avx512_v2.obj created
        set APERTURE_OBJ="%BUILD_DIR%\aperture_q4_0_avx512_v2.obj"
    )
) else (
    echo WARNING: Aperture kernel not found (using stub inference)
    set APERTURE_OBJ=
)

echo.
echo [4/4] Linking Integrated Executable...
echo       Entry: AgenticMain
"%LINK%" /OUT:"%BUILD_DIR%\AgenticAperture.exe" ^
    /SUBSYSTEM:CONSOLE ^
    /ENTRY:AgenticMain ^
    /DEBUG ^
    /PDB:"%BUILD_DIR%\AgenticAperture.pdb" ^
    /MACHINE:X64 /nologo ^
    /LIBPATH:"%LIBPATH%" ^
    "%BUILD_DIR%\agentic_sovereign_entry.obj" ^
    "%BUILD_DIR%\agentic_aperture_bridge.obj" ^
    %APERTURE_OBJ% ^
    kernel32.lib ^
    user32.lib
if errorlevel 1 (
    echo ERROR: Link failed
    exit /b 1
)
echo       ^> AgenticAperture.exe created

echo.
echo [5/4] Verifying build...
if exist "%BUILD_DIR%\AgenticAperture.exe" (
    echo       ^> Build SUCCESS
    for %%F in ("%BUILD_DIR%\AgenticAperture.exe") do (
        echo       ^> Size: %%~zF bytes
    )
) else (
    echo       ^> Build FAILED
    exit /b 1
)

echo.
echo ╔═══════════════════════════════════════════════════════════════════╗
echo ║  Integration Build Complete!                                         ║
echo ║                                                                    ║
echo ║  Output: %BUILD_DIR%\AgenticAperture.exe           ║
echo ║                                                                    ║
echo ║  Features:                                                         ║
echo ║    ✓ Sovereign Agentic Core (MASM)                                  ║
echo ║    ✓ Aperture Inference Bridge                                      ║
echo ║    ✓ Prompt-to-Tool Parser                                          ║
echo ║    ✓ [THINK]/[ACT]/[DONE] State Machine                             ║
echo ║    ✓ Tool Dispatch                                                  ║
echo ║                                                                    ║
echo ║  To run:                                                           ║
echo ║    %BUILD_DIR%\AgenticAperture.exe                ║
echo ╚═══════════════════════════════════════════════════════════════════╝

exit /b 0
