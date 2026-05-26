@echo off
set ML64="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set OBJ_DIR=d:\rawrxd\obj
set SRC_DIR=d:\rawrxd\src\asm

if not exist %OBJ_DIR% mkdir %OBJ_DIR%

echo [1/4] Assembling Core Engine...
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_Main.obj %SRC_DIR%\Sovereign_Main.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_Globals.obj d:\rawrxd\src\Sovereign_Globals.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_PEB_Loader.obj d:\rawrxd\src\Sovereign_PEB_Loader.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_Init_Pipeline.obj %SRC_DIR%\Sovereign_Init_Pipeline.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_Syscall_Gateway.obj %SRC_DIR%\Sovereign_Syscall_Gateway.asm

echo [2/4] Assembling Subsystems...
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_Cyclic_Dispatch.obj %SRC_DIR%\Sovereign_Cyclic_Dispatch.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_Welford_Governor.obj %SRC_DIR%\Sovereign_Welford_Governor.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_Vehicle_Engine.obj %SRC_DIR%\Sovereign_Vehicle_Engine.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_Ballistics_Engine.obj %SRC_DIR%\Sovereign_Ballistics_Engine.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_UI_Hud.obj %SRC_DIR%\Sovereign_UI_Hud.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_Persistence.obj %SRC_DIR%\Sovereign_Persistence.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_Audit_Circular_Buffer.obj %SRC_DIR%\Sovereign_Audit_Circular_Buffer.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_Entropy_Engine.obj %SRC_DIR%\Sovereign_Entropy_Engine.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_GeoMapper_Pipeline.obj %SRC_DIR%\Sovereign_GeoMapper_Pipeline.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_Network_Sync.obj %SRC_DIR%\Sovereign_Network_Sync.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_World_Generator.obj %SRC_DIR%\Sovereign_World_Generator.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_WFC_Generator.obj %SRC_DIR%\Sovereign_WFC_Generator.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_Protagonist_Switch.obj %SRC_DIR%\Sovereign_Protagonist_Switch.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_Mission_Director.obj %SRC_DIR%\Sovereign_Mission_Director.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_RP_Activities_Store.obj %SRC_DIR%\Sovereign_RP_Activities_Store.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_Wanted_System.obj %SRC_DIR%\Sovereign_Wanted_System.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_World_Net_Gen.obj %SRC_DIR%\Sovereign_World_Net_Gen.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_Role_Generator.obj %SRC_DIR%\Sovereign_Role_Generator.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_RP_Job_Assigner.obj %SRC_DIR%\Sovereign_RP_Job_Assigner.asm

echo [3/4] Assembling Advanced Kernels...
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\mxcsr_determinism.obj %SRC_DIR%\mxcsr_determinism.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\ums_micro_scheduler.obj %SRC_DIR%\ums_micro_scheduler.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_Ring_Bridge.obj %SRC_DIR%\Sovereign_Ring_Bridge.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\SovereignInferenceLoop.obj %SRC_DIR%\SovereignInferenceLoop.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_GGUF_Parser.obj %SRC_DIR%\Sovereign_GGUF_Parser.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_AES_Cache_Pulse.obj %SRC_DIR%\Sovereign_AES_Cache_Pulse.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\vram_pressure_monitor.obj %SRC_DIR%\vram_pressure_monitor.asm

echo [4/4] Assembling OS Support...
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_OS_Core.obj %SRC_DIR%\Sovereign_OS_Core.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_OS_DAG_Compiler.obj %SRC_DIR%\Sovereign_OS_DAG_Compiler.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_Execution_Graph_Logic.obj %SRC_DIR%\Sovereign_Execution_Graph_Logic.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_OS_FaultHandler.obj %SRC_DIR%\Sovereign_OS_FaultHandler.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_OS_MemoryGuard.obj %SRC_DIR%\Sovereign_OS_MemoryGuard.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_JIT_Elite_Core.obj %SRC_DIR%\Sovereign_JIT_Elite_Core.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_Elite_Syscall_Core.obj %SRC_DIR%\Sovereign_Elite_Syscall_Core.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_Syscall_Gatekeeper.obj %SRC_DIR%\Sovereign_Syscall_Gatekeeper.asm
%ML64% /c /nologo /Zi /Id:\rawrxd\src /Fo %OBJ_DIR%\Sovereign_Final_Linkage.obj %SRC_DIR%\Sovereign_Final_Linkage.asm

echo Assembly Complete.
