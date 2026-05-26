@echo off
cd /d "%~dp0"
set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "K32PATH=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"

echo [BUILD] Sovereign Engine v24.0.0 ? Production Monolith
echo.

echo [ASM] Sovereign_Alpha.asm
"%ML64%" /c /Fo Sovereign_Alpha.obj /DSOVEREIGN_ALPHA_MODULE Sovereign_Alpha.asm
if errorlevel 1 exit /b 1

echo [ASM] Sovereign_Binary.asm
"%ML64%" /c /Fo Sovereign_Binary.obj /DSOVEREIGN_BINARY_MODULE Sovereign_Binary.asm
if errorlevel 1 exit /b 1

echo [ASM] Sovereign_Finisher.asm
"%ML64%" /c /Fo Sovereign_Finisher.obj /DSOVEREIGN_FINISHER_MODULE Sovereign_Finisher.asm
if errorlevel 1 exit /b 1

echo [ASM] Sovereign_GGUF.asm
"%ML64%" /c /Fo Sovereign_GGUF.obj /DSOVEREIGN_GGUF_MODULE Sovereign_GGUF.asm
if errorlevel 1 exit /b 1

echo [ASM] Sovereign_Governor.asm
"%ML64%" /c /Fo Sovereign_Governor.obj /DSOVEREIGN_GOVERNOR_MODULE Sovereign_Governor.asm
if errorlevel 1 exit /b 1

echo [ASM] Sovereign_IPC.asm
"%ML64%" /c /Fo Sovereign_IPC.obj /DSOVEREIGN_IPC_MODULE Sovereign_IPC.asm
if errorlevel 1 exit /b 1

echo [ASM] Sovereign_Log.asm
"%ML64%" /c /Fo Sovereign_Log.obj /DSOVEREIGN_LOG_MODULE Sovereign_Log.asm
if errorlevel 1 exit /b 1

echo [ASM] Sovereign_Monitor.asm
"%ML64%" /c /Fo Sovereign_Monitor.obj /DSOVEREIGN_MONITOR_MODULE Sovereign_Monitor.asm
if errorlevel 1 exit /b 1

echo [ASM] Sovereign_Resilience.asm
"%ML64%" /c /Fo Sovereign_Resilience.obj /DSOVEREIGN_RESILIENCE_MODULE Sovereign_Resilience.asm
if errorlevel 1 exit /b 1

echo [ASM] Sovereign_Telemetry.asm
"%ML64%" /c /Fo Sovereign_Telemetry.obj /DSOVEREIGN_TELEMETRY_MODULE Sovereign_Telemetry.asm
if errorlevel 1 exit /b 1

echo [ASM] Sovereign_Ticker.asm
"%ML64%" /c /Fo Sovereign_Ticker.obj /DSOVEREIGN_TICKER_MODULE Sovereign_Ticker.asm
if errorlevel 1 exit /b 1

echo [ASM] Sovereign_Watchdog.asm
"%ML64%" /c /Fo Sovereign_Watchdog.obj /DSOVEREIGN_WATCHDOG_MODULE Sovereign_Watchdog.asm
if errorlevel 1 exit /b 1

echo [ASM] Sovereign_Wire.asm
"%ML64%" /c /Fo Sovereign_Wire.obj /DSOVEREIGN_WIRE_MODULE Sovereign_Wire.asm
if errorlevel 1 exit /b 1

echo [ASM] RawrXD_Titan_Master_GodSource.asm
"%ML64%" /c /Fo RawrXD_Titan_Master_GodSource.obj RawrXD_Titan_Master_GodSource.asm
if errorlevel 1 exit /b 1

echo [LINK] Titan_Sovereign_Engine.exe
"%LINK%" /ENTRY:main /SUBSYSTEM:CONSOLE /NODEFAULTLIB /OUT:Titan_Sovereign_Engine.exe ^
    RawrXD_Titan_Master_GodSource.obj ^
    Sovereign_Alpha.obj ^
    Sovereign_Binary.obj ^
    Sovereign_Finisher.obj ^
    Sovereign_GGUF.obj ^
    Sovereign_Governor.obj ^
    Sovereign_IPC.obj ^
    Sovereign_Log.obj ^
    Sovereign_Monitor.obj ^
    Sovereign_Resilience.obj ^
    Sovereign_Telemetry.obj ^
    Sovereign_Ticker.obj ^
    Sovereign_Watchdog.obj ^
    Sovereign_Wire.obj ^
    "%K32PATH%\kernel32.lib" ^
    "%K32PATH%\user32.lib"

if errorlevel 1 (
    echo [FAIL] Production Link Failure.
    exit /b 1
)

echo.
echo [SUCCESS] Titan_Sovereign_Engine.exe is ready for GGUF Ingestion.
