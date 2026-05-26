@echo off
cd /d "%~dp0"
set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "K32PATH=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"

echo [BUILD] ASSEMBLE CORE MODULES...

"%ML64%" /c /Fo Sovereign_IPC.obj Sovereign_IPC.asm
"%ML64%" /c /Fo Sovereign_Binary.obj Sovereign_Binary.asm
"%ML64%" /c /Fo Sovereign_Resilience.obj Sovereign_Resilience.asm
"%ML64%" /c /Fo Sovereign_Wire.obj Sovereign_Wire.asm
"%ML64%" /c /Fo Sovereign_Alpha.obj Sovereign_Alpha.asm
"%ML64%" /c /Fo Sovereign_Ticker.obj Sovereign_Ticker.asm
"%ML64%" /c /Fo Sovereign_GGUF.obj Sovereign_GGUF.asm
"%ML64%" /c /Fo Sovereign_Watchdog.obj Sovereign_Watchdog.asm
"%ML64%" /c /Fo Sovereign_Governor.obj Sovereign_Governor.asm
"%ML64%" /c /Fo Sovereign_Telemetry.obj Sovereign_Telemetry.asm
"%ML64%" /c /Fo Sovereign_Log.obj Sovereign_Log.asm
"%ML64%" /c /Fo Sovereign_Finisher.obj Sovereign_Finisher.asm
"%ML64%" /c /Fo RawrXD_Titan_Master_GodSource.obj RawrXD_Titan_Master_GodSource.asm

echo [LINK] MONOLITHIC SOVEREIGN ENGINE...

"%LINK%" /ENTRY:main /SUBSYSTEM:CONSOLE /NODEFAULTLIB /OUT:SovereignEngine.exe ^
    RawrXD_Titan_Master_GodSource.obj ^
    Sovereign_IPC.obj ^
    Sovereign_Binary.obj ^
    Sovereign_Resilience.obj ^
    Sovereign_Wire.obj ^
    Sovereign_Alpha.obj ^
    Sovereign_Ticker.obj ^
    Sovereign_GGUF.obj ^
    Sovereign_Watchdog.obj ^
    Sovereign_Governor.obj ^
    Sovereign_Telemetry.obj ^
    Sovereign_Log.obj ^
    Sovereign_Finisher.obj ^
    "%K32PATH%\kernel32.lib" ^
    "%K32PATH%\user32.lib"

if errorlevel 1 (
    echo [FAIL] SOVEREIGN ENGINE BUILD FAILED.
    exit /b 1
)

echo [SUCCESS] SOVEREIGN ENGINE DEPLOYED.
