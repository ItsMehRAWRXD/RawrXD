@echo off
set "VCDIR=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "VCLIB=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64"
set "SDK=C:\Program Files (x86)\Windows Kits\10"
set "SDKVER=10.0.22621.0"
set "LIB=%VCLIB%;%SDK%\Lib\%SDKVER%\um\x64;%SDK%\Lib\%SDKVER%\ucrt\x64"
set "PATH=%VCDIR%;%PATH%"

ml64.exe /c /nologo /FoD:\rawrxd\src\Sovereign_Drive_Monitor.obj D:\rawrxd\src\Sovereign_Drive_Monitor.asm
link.exe /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:D:\rawrxd\Sovereign_Drive_Monitor.exe D:\rawrxd\src\Sovereign_Drive_Monitor.obj kernel32.lib user32.lib advapi32.lib
