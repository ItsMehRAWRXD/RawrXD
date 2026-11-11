@echo off
cd /d D:\rawrxd-ci-bootstrap

echo Stopping orchestrator...
taskkill /F /IM SovereignOrchestrator.exe 2>nul
timeout /t 2 > nul

echo Compiling updated worker...
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /W3 /nologo /Fo Sovereign_Inference_Worker.obj Sovereign_Inference_Worker.asm
if errorlevel 1 (
    echo Worker compilation failed!
    exit /b 1
)

echo Compiling streamer...
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /W3 /nologo /Fo StreamerImpl_v2.obj StreamerImpl_v2.asm
if errorlevel 1 (
    echo Streamer compilation failed!
    exit /b 1
)

echo Relinking orchestrator...
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe" ^
    /SUBSYSTEM:CONSOLE /ENTRY:main /NODEFAULTLIB /LARGEADDRESSAWARE:NO ^
    /OUT:SovereignOrchestrator.exe ^
    SovereignOrchestrator_Hardened.obj ^
    Sovereign_Inference_Worker.obj ^
    StreamerImpl_v2.obj ^
    Sovereign_SDK.lib ^
    kernel32.lib

if errorlevel 1 (
    echo Link failed!
    exit /b 1
)

echo Success!
dir SovereignOrchestrator.exe
