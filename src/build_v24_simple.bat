@echo off
cd /d d:\rawrxd\src

echo Assembling modules...
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo Sovereign_Globals.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo Sovereign_PEB_Loader.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo Sovereign_IPC.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo Sovereign_Model_Loader.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo Sovereign_Finisher.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo Sovereign_GGUF_Parser.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo Sovereign_Compute_Kernel.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo Sovereign_Inference_Dispatcher.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo Sovereign_Action_Dispatcher.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo Sovereign_KV_Cache.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo Sovereign_Sampler.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo Sovereign_Compute_RoPE.asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /nologo Sovereign_Main.asm

echo Linking...
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe" /SUBSYSTEM:CONSOLE /NODEFAULTLIB /ENTRY:main /OUT:..\Titan_Sovereign_Agent_Final_v24.exe ^
Sovereign_Main.obj ^
Sovereign_IPC.obj ^
Sovereign_PEB_Loader.obj ^
Sovereign_Model_Loader.obj ^
Sovereign_Finisher.obj ^
Sovereign_Globals.obj ^
Sovereign_GGUF_Parser.obj ^
Sovereign_Compute_Kernel.obj ^
Sovereign_Inference_Dispatcher.obj ^
Sovereign_Action_Dispatcher.obj ^
Sovereign_KV_Cache.obj ^
Sovereign_Sampler.obj ^
Sovereign_Compute_RoPE.obj

echo Done.
