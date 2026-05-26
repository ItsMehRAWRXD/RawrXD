@echo off
set ML64_PATH="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set LINK_PATH="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"

if not exist build mkdir build

echo [ASSEMBLING] Globals...
%ML64_PATH% /c /I . /I asm /Fo build\Sovereign_Globals.obj asm\Sovereign_Globals.asm
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo [ASSEMBLING] PEB Loader...
%ML64_PATH% /c /I . /I asm /Fo build\Sovereign_PEB_Loader.obj Sovereign_PEB_Loader.asm
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo [ASSEMBLING] Heap...
%ML64_PATH% /c /I . /I asm /Fo build\Sovereign_Heap.obj Sovereign_Heap.asm
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo [ASSEMBLING] Elite Scanner (Masked)...
%ML64_PATH% /c /I . /I asm /Fo build\Sovereign_Elite_Scanner.obj asm\Sovereign_Elite_Scanner.asm
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo [ASSEMBLING] Hardware Lite (Audit + ScanPattern)...
%ML64_PATH% /c /I . /I asm /Fo build\Sovereign_Hardware_Lite.obj Sovereign_Hardware_Lite.asm
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo [ASSEMBLING] Ring Bridge...
%ML64_PATH% /c /I . /I asm /Fo build\Sovereign_Ring_Bridge.obj asm\Sovereign_Ring_Bridge.asm
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo [ASSEMBLING] Model Loader...
%ML64_PATH% /c /I . /I asm /Fo build\Sovereign_Model_Loader.obj Sovereign_Model_Loader.asm
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo [ASSEMBLING] Action Dispatcher...
%ML64_PATH% /c /I . /I asm /Fo build\Sovereign_Action_Dispatcher.obj Sovereign_Action_Dispatcher.asm
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo [ASSEMBLING] Elite Stubs...
%ML64_PATH% /c /I . /I asm /Fo build\Sovereign_Elite_Stubs.obj Sovereign_Elite_Stubs.asm
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo [ASSEMBLING] Bootstrap Core...
%ML64_PATH% /c /I . /I asm /Fo build\Sovereign_Bootstrap_Core.obj asm\Sovereign_Bootstrap_Core.asm
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo [ASSEMBLING] Registry Manager...
%ML64_PATH% /c /I . /I asm /Fo build\Sovereign_Registry_Manager.obj asm\Sovereign_Registry_Manager.asm
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo [ASSEMBLING] Cache Pulse...
%ML64_PATH% /c /I . /I asm /Fo build\Sovereign_AES_Cache_Pulse.obj asm\Sovereign_AES_Cache_Pulse.asm
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo [ASSEMBLING] Jitter Probe...
%ML64_PATH% /c /I . /I asm /Fo build\Sovereign_Jitter_Probe.obj asm\Sovereign_Jitter_Probe.asm
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo [ASSEMBLING] Compiler Pass...
%ML64_PATH% /c /I . /I asm /Fo build\Sovereign_Compiler_Pass.obj asm\Sovereign_Compiler_Pass.asm
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo [ASSEMBLING] Watchdog...
%ML64_PATH% /c /I . /I asm /Fo build\Sovereign_Watchdog_Lean.obj asm\Sovereign_Watchdog_Lean.asm
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo [ASSEMBLING] Execution Graph Logic...
%ML64_PATH% /c /I . /I asm /Fo build\Sovereign_Execution_Graph_Logic.obj asm\Sovereign_Execution_Graph_Logic.asm
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo [ASSEMBLING] Main Orchestrator...
%ML64_PATH% /c /I . /I asm /Fo build\Sovereign_Main.obj Sovereign_Main.asm
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo [LINKING] Sovereign_Elite_Production.exe...
%LINK_PATH% /ENTRY:mainCRTStartup /SUBSYSTEM:CONSOLE /NODEFAULTLIB /LARGEADDRESSAWARE ^
    /OUT:Sovereign_Elite_Production.exe ^
    build\Sovereign_Main.obj ^
    build\Sovereign_Globals.obj ^
    build\Sovereign_PEB_Loader.obj ^
    build\Sovereign_Heap.obj ^
    build\Sovereign_Elite_Scanner.obj ^
    build\Sovereign_Hardware_Lite.obj ^
    build\Sovereign_Ring_Bridge.obj ^
    build\Sovereign_Model_Loader.obj ^
    build\Sovereign_Action_Dispatcher.obj ^
    build\Sovereign_Elite_Stubs.obj ^
    build\Sovereign_Bootstrap_Core.obj ^
    build\Sovereign_Registry_Manager.obj ^
    build\Sovereign_AES_Cache_Pulse.obj ^
    build\Sovereign_Jitter_Probe.obj ^
    build\Sovereign_Compiler_Pass.obj ^
    build\Sovereign_Watchdog_Lean.obj ^
    build\Sovereign_Execution_Graph_Logic.obj

if %ERRORLEVEL% EQU 0 echo [SUCCESS] Sovereign_Elite_Production.exe is ready.
