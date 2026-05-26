@echo off 
setlocal 
set " MASM_FLAGS=/c /nologo "/Zi 
set " LINK_FLAGS=/NOLOGO /NODEFAULTLIB /ENTRY:XR_Production_Entry /SUBSYSTEM:CONSOLE "/DEBUG 
ml64 %%MASM_FLAGS%% /Fo Sovereign_OS_Core.obj src\asm\Sovereign_OS_Core.asm 
ml64 %%MASM_FLAGS%% /Fo Sovereign_Runtime.obj src\asm\Sovereign_Runtime_Bootstrap.asm 
ml64 %%MASM_FLAGS%% /Fo Sovereign_Final.obj src\asm\Sovereign_Final_Linkage.asm 
ml64 %%MASM_FLAGS%% /Fo Sovereign_Stability.obj src\asm\Sovereign_Stability_Baseline.asm 
ml64 %%MASM_FLAGS%% /Fo Sovereign_Memory.obj src\asm\Sovereign_OS_MemoryGuard.asm 
ml64 %%MASM_FLAGS%% /Fo Sovereign_SHA256NI.obj src\asm\Sovereign_AppendLog_SHA256NI.asm 
ml64 %%MASM_FLAGS%% /Fo Sovereign_DAG_Compiler.obj src\asm\Sovereign_OS_DAG_Compiler.asm 
ml64 %%MASM_FLAGS%% /Fo Sovereign_FaultHandler.obj src\asm\Sovereign_Fault_Handler.asm 
ml64 %%MASM_FLAGS%% /Fo Sovereign_TestBench.obj src\asm\Sovereign_TestBench_Harness.asm 
ml64 %%MASM_FLAGS%% /Fo Sovereign_Runtime_Run.obj src\asm\Sovereign_Runtime_Run.asm 
ml64 %%MASM_FLAGS%% /Fo Sovereign_Execution_Graph_ABI.obj src\asm\Sovereign_Execution_Graph_ABI.asm 
ml64 %%MASM_FLAGS%% /Fo Sovereign_Manifest_Generator.obj src\asm\Sovereign_Manifest_Generator.asm 
if %0% neq 0 exit /b 1 
RawrXD_Engine_Sovereign.exe --gate-verify 
if %0% neq 0 exit /b 1 
echo [SUCCESS] Sovereign Engine verified. 
endlocal 
