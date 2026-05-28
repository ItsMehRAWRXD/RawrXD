@echo off
set LINK_PATH="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
%LINK_PATH% /ENTRY:mainCRTStartup /SUBSYSTEM:CONSOLE /NODEFAULTLIB /LARGEADDRESSAWARE ^
    /OUT:Sovereign_Elite_Test.exe ^
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
    build\Sovereign_Execution_Graph_Logic.obj ^
    build\Sovereign_GEMM_Q4_F32.obj ^
    build\Sovereign_GEMM_Q4_F32_Pipelined.obj > link_raw.txt 2>&1

echo UNIQUE UNRESOLVED SYMBOLS:
powershell -Command "Get-Content link_raw.txt | Select-String 'unresolved external symbol' | ForEach-Object { $_.ToString().Split(' ')[-1] } | Select-Object -Unique"
