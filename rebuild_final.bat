@echo off
cd /d D:\rawrxd-ci-bootstrap

echo Building streamer implementation...

"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /W3 /nologo /Fo StreamerImpl.obj StreamerImpl.asm
if errorlevel 1 (
    echo Failed to compile streamer
    exit /b 1
)

echo Relinking orchestrator with streamer...

"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe" ^
    /SUBSYSTEM:CONSOLE /ENTRY:main /NODEFAULTLIB /LARGEADDRESSAWARE:NO ^
    /OUT:SovereignOrchestrator.exe ^
    SovereignOrchestrator_Hardened.obj ^
    Sovereign_Inference_Worker.obj ^
    StreamerImpl.obj ^
    Sovereign_SDK.lib ^
    kernel32.lib

if errorlevel 1 (
    echo Link failed!
    exit /b 1
)

echo Success!
dir SovereignOrchestrator.exe
