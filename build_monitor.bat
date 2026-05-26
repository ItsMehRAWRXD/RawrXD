@echo off
set "VCDIR=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "VCINCLUDE=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\include"
set "VCLIB=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64"
set "SDK=C:\Program Files (x86)\Windows Kits\10"
set "SDKVER=10.0.22621.0"
set "INCLUDE=%VCINCLUDE%;%SDK%\Include\%SDKVER%\shared;%SDK%\Include\%SDKVER%\um;%SDK%\Include\%SDKVER%\ucrt;D:\rawrxd\src"
set "LIB=%VCLIB%;%SDK%\Lib\%SDKVER%\um\x64;%SDK%\Lib\%SDKVER%\ucrt\x64"
set "PATH=%VCDIR%;%PATH%"

set ML64=ml64.exe
set CC=cl.exe
set LD=link.exe

%ML64% /c /nologo /FoD:\rawrxd\src\Sovereign_Monitor.obj D:\rawrxd\src\Sovereign_Monitor.asm
%LD% /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:D:\rawrxd\Sovereign_Monitor.exe D:\rawrxd\src\Sovereign_Monitor.obj kernel32.lib user32.lib advapi32.lib

if %ERRORLEVEL% NEQ 0 (
    echo [FATAL] Build failed.
    exit /b 1
)

echo [OK] Sovereign_Monitor.exe built successfully.
