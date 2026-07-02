@echo off
cd /d D:\rawrxd-ci-bootstrap

echo ========================================
echo   BUILDING FIXED VERSIONS
echo ========================================
echo.

set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe

echo [1/4] Assembling SovereignOrchestrator_Fixed...
"%ML64%" /c /W3 /nologo /Zi /Fo SovereignOrchestrator_Fixed.obj SovereignOrchestrator_Fixed.asm
if errorlevel 1 (
    echo FAILED!
    exit /b 1
)

echo [2/4] Assembling Sovereign_Inference_Worker...
"%ML64%" /c /W3 /nologo /Zi /Fo Sovereign_Inference_Worker.obj Sovereign_Inference_Worker.asm
if errorlevel 1 (
    echo FAILED!
    exit /b 1
)

echo [3/4] Assembling SovereignChatClient_Fixed...
"%ML64%" /c /W3 /nologo /Zi /Fo SovereignChatClient_Fixed.obj SovereignChatClient_Fixed.asm
if errorlevel 1 (
    echo FAILED!
    exit /b 1
)

echo [4/4] Linking executables...

"%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:main /NODEFAULTLIB /OUT:SovereignOrchestrator_Fixed.exe SovereignOrchestrator_Fixed.obj Sovereign_Inference_Worker.obj StreamerImpl.obj Sovereign_SDK.lib kernel32.lib
if errorlevel 1 (
    echo Link FAILED for orchestrator!
    exit /b 1
)

"%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:main /NODEFAULTLIB /OUT:SovereignChatClient_Fixed.exe SovereignChatClient_Fixed.obj kernel32.lib
if errorlevel 1 (
    echo Link FAILED for client!
    exit /b 1
)

echo.
echo ========================================
echo   BUILD SUCCESSFUL
echo ========================================
echo.
dir SovereignOrchestrator_Fixed.exe SovereignChatClient_Fixed.exe
