@echo off  
set AS=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe  
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe  
set "LIB=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64"
cd /d d:\rawrxd\src\asm  
%AS% /c /Zi /nologo RawrXD_DynamicPromptEngine.asm RawrXD_DynamicPromptEngine_Templates.asm
cd /d d:\rawrxd\src
%AS% /c /Zi /nologo RawrXD_Titan_Master_GodSource.asm Sovereign_IPC.asm Sovereign_Wire.asm Sovereign_PEB_Loader.asm Sovereign_Finisher.asm Sovereign_Telemetry_Engine.asm Sovereign_Bridge.asm Sovereign_Log.asm  
%LINK% /SUBSYSTEM:CONSOLE /NODEFAULTLIB /ENTRY:main /OUT:..\Titan_Sovereign_Engine_Final.exe RawrXD_Titan_Master_GodSource.obj Sovereign_IPC.obj Sovereign_Wire.obj Sovereign_PEB_Loader.obj Sovereign_Finisher.obj Sovereign_Telemetry_Engine.obj Sovereign_Bridge.obj Sovereign_Log.obj asm\RawrXD_DynamicPromptEngine.obj asm\RawrXD_DynamicPromptEngine_Templates.obj kernel32.lib user32.lib 
