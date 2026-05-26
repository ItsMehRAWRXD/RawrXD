@echo off
set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
cd /d d:\rawrxd\src\asm
%ML64% /c Sovereign_Single.asm
%LINK% /SUBSYSTEM:CONSOLE /ENTRY:Sovereign_Entry /NODEFAULTLIB /OUT:Sovereign_Elite.exe Sovereign_Single.obj
