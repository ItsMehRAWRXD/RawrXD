@echo off
set "VCDIR=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "VCLIB=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64"
set "SDK=C:\Program Files (x86)\Windows Kits\10"
set "SDKVER=10.0.22621.0"
set "LIB=%VCLIB%;%SDK%\Lib\%SDKVER%\um\x64;%SDK%\Lib\%SDKVER%\ucrt\x64"
set "PATH=%VCDIR%;%PATH%"

echo [SOVEREIGN] Building Drive Monitor (Thermal Source)...
ml64.exe /c /nologo /FoD:\rawrxd\src\Sovereign_Drive_Monitor.obj D:\rawrxd\src\Sovereign_Drive_Monitor.asm
link.exe /nologo /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:D:\rawrxd\Sovereign_Drive_Monitor.exe D:\rawrxd\src\Sovereign_Drive_Monitor.obj kernel32.lib advapi32.lib

echo [SOVEREIGN] Building Main Monitor (Governor)...
ml64.exe /c /nologo /FoD:\rawrxd\src\Sovereign_Monitor.obj D:\rawrxd\src\Sovereign_Monitor.asm
link.exe /nologo /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:D:\rawrxd\Sovereign_Monitor.exe D:\rawrxd\src\Sovereign_Monitor.obj kernel32.lib advapi32.lib

echo [SOVEREIGN] Building Consumer (Unified Diagnostics)...
ml64.exe /c /nologo /FoD:\rawrxd\src\Sovereign_Consumer_Atomic.obj D:\rawrxd\src\Sovereign_Consumer_Atomic.asm
link.exe /nologo /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:D:\rawrxd\Sovereign_Consumer.exe D:\rawrxd\src\Sovereign_Consumer_Atomic.obj kernel32.lib advapi32.lib

echo [SOVEREIGN] Building IPC Kernel (Shared Symbols)...
ml64.exe /c /nologo /FoD:\rawrxd\src\Sovereign_IPC.obj D:\rawrxd\src\Sovereign_IPC.asm

echo [SOVEREIGN] Building Strategy_Alpha (Core Logic)...
ml64.exe /c /nologo /FoD:\rawrxd\src\Strategy_Alpha.obj D:\rawrxd\src\Strategy_Alpha.asm
link.exe /nologo /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:D:\rawrxd\Strategy_Alpha.exe D:\rawrxd\src\Strategy_Alpha.obj D:\rawrxd\src\Sovereign_IPC.obj kernel32.lib advapi32.lib

echo [SOVEREIGN] Building Sequencer (Atomicity Engine)...
ml64.exe /c /nologo /FoD:\rawrxd\src\Sovereign_Sequencer.obj D:\rawrxd\src\Sovereign_Sequencer.asm
link.exe /nologo /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:D:\rawrxd\Sovereign_Sequencer.exe D:\rawrxd\src\Sovereign_Sequencer.obj kernel32.lib advapi32.lib

echo [SOVEREIGN] Building Alpha Engine (Production Gate)...
ml64.exe /c /nologo /FoD:\rawrxd\src\Sovereign_Alpha_Engine.obj D:\rawrxd\src\Sovereign_Alpha_Engine.asm
ml64.exe /c /nologo /FoD:\rawrxd\src\Sovereign_Burst_Emitter.obj D:\rawrxd\src\Sovereign_Burst_Emitter.asm
link.exe /nologo /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:D:\rawrxd\Sovereign_Alpha_Engine.exe D:\rawrxd\src\Sovereign_Alpha_Engine.obj D:\rawrxd\src\Sovereign_Burst_Emitter.obj kernel32.lib advapi32.lib

echo [SOVEREIGN] Unified Build Complete.
