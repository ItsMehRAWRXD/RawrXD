@echo off
setlocal
set "VCDIR=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "VCLIB=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64"
set "SDK=C:\Program Files (x86)\Windows Kits\10"
set "SDKVER=10.0.22621.0"
set "LIB=%VCLIB%;%SDK%\Lib\%SDKVER%\um\x64;%SDK%\Lib\%SDKVER%\ucrt\x64"
set "PATH=%VCDIR%;%PATH%"

echo [SOVEREIGN] Building Hardened Suite (Telemetry-Enabled)...
ml64 /c /nologo /FoD:\rawrxd\src\Sovereign_Agent_Finisher.obj D:\rawrxd\src\Sovereign_Agent_Finisher.asm
ml64 /c /nologo /FoD:\rawrxd\src\Sovereign_Telemetry.obj D:\rawrxd\src\Sovereign_Telemetry.asm
ml64 /c /nologo /FoD:\rawrxd\src\Sovereign_IPC.obj D:\rawrxd\src\Sovereign_IPC.asm
ml64 /c /nologo /FoD:\rawrxd\src\Sovereign_Monitor.obj D:\rawrxd\src\Sovereign_Monitor.asm
ml64 /c /nologo /FoD:\rawrxd\src\Sovereign_SwarmLink.obj D:\rawrxd\src\Sovereign_SwarmLink.asm

echo [SOVEREIGN] Final Link (Hardened/Optimized)...
link /NOLOGO /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:D:\rawrxd\Sovereign_Agent_Final.exe ^
    D:\rawrxd\src\Sovereign_Agent_Finisher.obj ^
    D:\rawrxd\src\Sovereign_Telemetry.obj ^
    D:\rawrxd\src\Sovereign_IPC.obj ^
    D:\rawrxd\src\Sovereign_Monitor.obj ^
    D:\rawrxd\src\Sovereign_SwarmLink.obj ^
    kernel32.lib advapi32.lib /OPT:REF /OPT:ICF

if %ERRORLEVEL% EQU 0 (
    echo [SOVEREIGN] Final Production Binary Ready: Sovereign_Agent_Final.exe
) else (
    echo [SOVEREIGN] Build FAILED.
)
endlocal
