@echo off
REM build_orchestrator.bat — Build the Hardened Sovereign Orchestrator
REM Links: SovereignOrchestrator_Hardened + Sovereign_GGUF_Loader + Sovereign_Model_Streamer

set ML64_EXE="C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\ml64.exe"
set LINK_EXE="C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe"
set KERNEL32_LIB="D:\rawrxd\scripts\kernel32.lib"

echo [BUILD] ================================================
echo [BUILD] Sovereign Orchestrator Hardened Build
echo [BUILD] ================================================

REM --- Assemble Orchestrator ---
echo [BUILD] Assembling SovereignOrchestrator_Hardened.asm...
%ML64_EXE% /c /W3 /nologo /Zi /Fo SovereignOrchestrator_Hardened.obj SovereignOrchestrator_Hardened.asm
if errorlevel 1 goto :fail

REM --- Assemble GGUF Loader ---
echo [BUILD] Assembling Sovereign_GGUF_Loader.asm...
%ML64_EXE% /c /W3 /nologo /Zi /Fo Sovereign_GGUF_Loader.obj Sovereign_GGUF_Loader.asm
if errorlevel 1 goto :fail

REM --- Assemble Model Streamer ---
echo [BUILD] Assembling Sovereign_Model_Streamer.asm...
%ML64_EXE% /c /W3 /nologo /Zi /Fo Sovereign_Model_Streamer.obj Sovereign_Model_Streamer.asm
if errorlevel 1 goto :fail

REM --- Link ---
echo [BUILD] Linking SovereignOrchestrator.exe...
%LINK_EXE% /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:SovereignOrchestrator.exe ^
    /NXCOMPAT /DYNAMICBASE ^
    SovereignOrchestrator_Hardened.obj ^
    Sovereign_GGUF_Loader.obj ^
    Sovereign_Model_Streamer.obj ^
    %KERNEL32_LIB%
if errorlevel 1 goto :fail

echo [BUILD] ================================================
echo [BUILD] SUCCESS: SovereignOrchestrator.exe built.
echo [BUILD] Symbols wired: SOVEREIGN_LOAD_MODEL, STREAMER_INIT
echo [BUILD] Security: ASLR + DEP enabled (/NXCOMPAT /DYNAMICBASE)
echo [BUILD] ================================================
goto :eof

:fail
echo [BUILD] FAILED. Check error messages above.
exit /b 1
