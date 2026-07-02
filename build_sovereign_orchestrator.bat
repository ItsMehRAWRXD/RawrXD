@echo off
setlocal

echo ================================================================
echo Sovereign Orchestrator Build - Non-Blocking Inference Worker
echo ================================================================

set ML64_EXE=C:\Program Files\Microsoft Visual Studio\18\Enterprise\SDK\ScopeCppSDK\vc15\VC\bin\ml64.exe
set LINK_EXE=C:\Program Files\Microsoft Visual Studio\18\Enterprise\SDK\ScopeCppSDK\vc15\VC\bin\link.exe
set KERNEL32_LIB=D:\rawrxd\scripts\kernel32.lib

if not exist "%ML64_EXE%" (
    echo [ERROR] ml64.exe not found at %ML64_EXE%
    echo [INFO] Searching for ml64.exe...
    for /f "tokens=*" %%i in ('dir /b /s "C:\Program Files\Microsoft Visual Studio\*ml64.exe" 2^>nul') do set ML64_EXE=%%i
    if not exist "%ML64_EXE%" (
        echo [ERROR] ml64.exe not found in Visual Studio installation
        exit /b 1
    )
)

if not exist "%LINK_EXE%" (
    echo [ERROR] link.exe not found at %LINK_EXE%
    echo [INFO] Searching for link.exe...
    for /f "tokens=*" %%i in ('dir /b /s "C:\Program Files\Microsoft Visual Studio\*link.exe" 2^>nul') do set LINK_EXE=%%i
    if not exist "%LINK_EXE%" (
        echo [ERROR] link.exe not found in Visual Studio installation
        exit /b 1
    )
)

echo [BUILD] Using ml64.exe: %ML64_EXE%
echo [BUILD] Using link.exe: %LINK_EXE%
echo.

echo [BUILD] Step 1: Assembling SovereignOrchestrator_Hardened.asm
"%ML64_EXE%" /c /W3 /nologo /Zi /Fo SovereignOrchestrator_Hardened.obj SovereignOrchestrator_Hardened.asm
if errorlevel 1 (
    echo [ERROR] Assembly failed for SovereignOrchestrator_Hardened.asm
    exit /b 1
)
echo [PASS] SovereignOrchestrator_Hardened.obj created
echo.

echo [BUILD] Step 2: Assembling Sovereign_Model_Streamer.asm
"%ML64_EXE%" /c /W3 /nologo /Zi /Fo Sovereign_Model_Streamer.obj Sovereign_Model_Streamer.asm
if errorlevel 1 (
    echo [ERROR] Assembly failed for Sovereign_Model_Streamer.asm
    exit /b 1
)
echo [PASS] Sovereign_Model_Streamer.obj created
echo.

echo [BUILD] Step 3: Assembling Sovereign_GGUF_Loader.asm
"%ML64_EXE%" /c /W3 /nologo /Zi /Fo Sovereign_GGUF_Loader.obj Sovereign_GGUF_Loader.asm
if errorlevel 1 (
    echo [ERROR] Assembly failed for Sovereign_GGUF_Loader.asm
    exit /b 1
)
echo [PASS] Sovereign_GGUF_Loader.obj created
echo.

echo [BUILD] Step 4: Assembling Sovereign_Inference_Worker.asm
"%ML64_EXE%" /c /W3 /nologo /Zi /Fo Sovereign_Inference_Worker.obj Sovereign_Inference_Worker.asm
if errorlevel 1 (
    echo [ERROR] Assembly failed for Sovereign_Inference_Worker.asm
    exit /b 1
)
echo [PASS] Sovereign_Inference_Worker.obj created
echo.

echo [BUILD] Step 5: Assembling Sovereign_IDE_Bridge_RingTrapdoor.asm
"%ML64_EXE%" /c /W3 /nologo /Zi /Fo Sovereign_IDE_Bridge_RingTrapdoor.obj Sovereign_IDE_Bridge_RingTrapdoor.asm
if errorlevel 1 (
    echo [ERROR] Assembly failed for Sovereign_IDE_Bridge_RingTrapdoor.asm
    exit /b 1
)
echo [PASS] Sovereign_IDE_Bridge_RingTrapdoor.obj created
echo.

echo [BUILD] Step 6: Linking all components
"%LINK_EXE%" /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:SovereignOrchestrator.exe ^
    SovereignOrchestrator_Hardened.obj ^
    Sovereign_Model_Streamer.obj ^
    Sovereign_GGUF_Loader.obj ^
    Sovereign_Inference_Worker.obj ^
    Sovereign_IDE_Bridge_RingTrapdoor.obj ^
    "%KERNEL32_LIB%"

if errorlevel 1 (
    echo [ERROR] Linking failed
    exit /b 1
)

echo [PASS] SovereignOrchestrator.exe created
echo.

echo ================================================================
echo BUILD SUCCESS
echo ================================================================
echo Output: SovereignOrchestrator.exe
echo Components linked:
echo   - SovereignOrchestrator_Hardened.obj (Main orchestrator)
echo   - Sovereign_Model_Streamer.obj (Token streaming)
echo   - Sovereign_GGUF_Loader.obj (Model loading)
echo   - Sovereign_Inference_Worker.obj (Background worker thread)
echo   - Sovereign_IDE_Bridge_RingTrapdoor.obj (IDE bridge ring + trapdoor)
echo.
echo Architecture: Non-blocking handoff with worker thread
echo Protocol: SOVEREIGN_MMF_PROTOCOL_V1.md
echo ================================================================

exit /b 0