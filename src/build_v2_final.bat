@echo off
cd /d d:\rawrxd\src

:: Define Tools
set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe

:: Clean objects
del *.obj

:: Assemble modules
%ML64% /c /nologo Sovereign_Globals.asm
%ML64% /c /nologo Sovereign_PEB_Loader.asm
%ML64% /c /nologo Sovereign_IPC.asm
%ML64% /c /nologo Sovereign_Model_Loader.asm
%ML64% /c /nologo Sovereign_Finisher.asm
%ML64% /c /nologo Sovereign_GGUF_Parser.asm
%ML64% /c /nologo Sovereign_Compute_Kernel.asm
%ML64% /c /nologo Sovereign_Inference_Dispatcher.asm
%ML64% /c /nologo Sovereign_Action_Dispatcher.asm
%ML64% /c /nologo Sovereign_KV_Cache.asm
%ML64% /c /nologo RawrXD_Titan_Master_GodSource.asm

:: Link Monolith (Strict symbol control)
%LINK% /SUBSYSTEM:CONSOLE /NODEFAULTLIB /ENTRY:main /OUT:..\Titan_Sovereign_Agent_Final_v24.exe ^
    RawrXD_Titan_Master_GodSource.obj ^
    Sovereign_IPC.obj ^
    Sovereign_PEB_Loader.obj ^
    Sovereign_Model_Loader.obj ^
    Sovereign_Finisher.obj ^
    Sovereign_Globals.obj ^
    Sovereign_GGUF_Parser.obj ^
    Sovereign_Compute_Kernel.obj ^
    Sovereign_Inference_Dispatcher.obj ^
    Sovereign_Action_Dispatcher.obj ^
    Sovereign_KV_Cache.obj

echo Build complete.
