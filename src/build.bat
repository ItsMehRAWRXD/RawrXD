set ML64="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set LINK_TOOL="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set LINK=

set LINK_EXE="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"

cd /d d:\rawrxd\src
del *.obj

%ML64% /c /nologo Sovereign_IPC.asm Sovereign_Inference_Dispatcher.asm Sovereign_Action_Dispatcher.asm Sovereign_Finisher.asm Sovereign_Model_Loader.asm Sovereign_Compute_Kernel.asm Sovereign_Sampler.asm Sovereign_Tokenizer.asm Sovereign_Syscall_Hooks.asm RawrXD_Titan_Master_GodSource.asm Sovereign_Globals.asm Sovereign_PEB_Loader.asm Sovereign_Integrator.asm

%LINK_EXE% /SUBSYSTEM:CONSOLE /NODEFAULTLIB /ENTRY:main /LARGEADDRESSAWARE:NO /OUT:..\Titan_Sovereign_Agent_Final_v24.exe ^
RawrXD_Titan_Master_GodSource.obj ^
Sovereign_PEB_Loader.obj ^
Sovereign_Model_Loader.obj ^
Sovereign_Compute_Kernel.obj ^
Sovereign_Sampler.obj ^
Sovereign_Tokenizer.obj ^
Sovereign_Syscall_Hooks.obj ^
Sovereign_IPC.obj ^
Sovereign_Inference_Dispatcher.obj ^
Sovereign_Action_Dispatcher.obj ^
Sovereign_Finisher.obj ^
Sovereign_Globals.obj ^
Sovereign_Integrator.obj
