@echo off
set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set "K32LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"
set "NTLIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\ntdll.lib"

del d:\rawrxd\build\*.obj

%ML64% /c /Fo d:\rawrxd\build\m.obj d:\rawrxd\src\asm\Sovereign_Monolith.asm
%ML64% /c /Fo d:\rawrxd\build\c.obj d:\rawrxd\src\asm\Sovereign_Cyclic_Dispatch.asm
%ML64% /c /Fo d:\rawrxd\build\p.obj d:\rawrxd\src\asm\Sovereign_PEB_Loader.asm

%LINK% /VERBOSE /SUBSYSTEM:CONSOLE /ENTRY:Sovereign_Entry /NODEFAULTLIB /OUT:d:\rawrxd\build\Sovereign_Elite.exe d:\rawrxd\build\m.obj d:\rawrxd\build\c.obj d:\rawrxd\build\p.obj "%K32LIB%" "%NTLIB%"
