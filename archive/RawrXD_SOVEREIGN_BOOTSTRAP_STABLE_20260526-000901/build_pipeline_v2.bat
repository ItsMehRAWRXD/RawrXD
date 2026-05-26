@echo off
setlocal
pushd "%~dp0"
call "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat" x64 >nul 2>&1
set "MASM_FLAGS=/c /nologo /Zi"
set "LINK_FLAGS=/NOLOGO /NODEFAULTLIB /ENTRY:XR_Production_Entry /SUBSYSTEM:CONSOLE /DEBUG /MAP:RawrXD_Engine_Sovereign.map /MAPINFO:EXPORTS"

echo [1/3] Assembling Sovereign Kernels...
ml64 %MASM_FLAGS% /Fo Sovereign_OS_Core.obj src\asm\Sovereign_OS_Core.asm
ml64 %MASM_FLAGS% /Fo Sovereign_Runtime.obj src\asm\Sovereign_Runtime_Bootstrap.asm
ml64 %MASM_FLAGS% /Fo Sovereign_Final.obj src\asm\Sovereign_Final_Linkage.asm
ml64 %MASM_FLAGS% /Fo Sovereign_Stability.obj src\asm\Sovereign_Stability_Baseline.asm
ml64 %MASM_FLAGS% /Fo Sovereign_Memory.obj src\asm\Sovereign_OS_MemoryGuard.asm
ml64 %MASM_FLAGS% /Fo Sovereign_SHA256NI.obj src\asm\Sovereign_AppendLog_SHA256NI.asm
ml64 %MASM_FLAGS% /Fo Sovereign_DAG_Compiler.obj src\asm\Sovereign_OS_DAG_Compiler.asm
ml64 %MASM_FLAGS% /Fo Sovereign_FaultHandler.obj src\asm\Sovereign_Fault_Handler.asm
ml64 %MASM_FLAGS% /Fo Sovereign_TestBench.obj src\asm\Sovereign_TestBench_Harness.asm
ml64 %MASM_FLAGS% /Fo Sovereign_Runtime_Run.obj src\asm\Sovereign_Runtime_Run.asm
ml64 %MASM_FLAGS% /Fo Sovereign_Execution_Graph_ABI.obj src\asm\Sovereign_Execution_Graph_ABI.asm
ml64 %MASM_FLAGS% /Fo Sovereign_Manifest_Generator.obj src\asm\Sovereign_Manifest_Generator.asm
ml64 %MASM_FLAGS% /Fo Sovereign_Stream_Ingest.obj src\asm\Sovereign_Stream_Ingest.asm
ml64 %MASM_FLAGS% /Fo Sovereign_FaultLog.obj src\asm\Sovereign_FaultLog.asm

echo [2/3] Linking Production Monolith...

echo [pre-link] Verifying and enforcing SEC_LARGE_PAGES alignment for phi3-mini-Q2_K.gguf...
powershell -ExecutionPolicy Bypass -File "D:\rawrxd\Ingestion_Aligner.ps1" -FilePath "D:\rawrxd\phi3-mini-Q2_K.gguf"
if %errorlevel% neq 0 (
    echo [FATAL] Tensor alignment failed. Pipeline aborted.
    exit /b 1
)

link %LINK_FLAGS% /OUT:RawrXD_Engine_Sovereign.exe Sovereign_OS_Core.obj Sovereign_Runtime.obj Sovereign_Final.obj Sovereign_Stability.obj Sovereign_Memory.obj Sovereign_SHA256NI.obj Sovereign_DAG_Compiler.obj Sovereign_FaultHandler.obj Sovereign_TestBench.obj Sovereign_Runtime_Run.obj Sovereign_Execution_Graph_ABI.obj Sovereign_Manifest_Generator.obj Sovereign_Stream_Ingest.obj Sovereign_FaultLog.obj "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.Lib" "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\Advapi32.Lib"
if %errorlevel% neq 0 (
    echo [FATAL] Linkage Failed.
    exit /b 1
)

echo [3/3] Executing Atomic Integrity Gate...
RawrXD_Engine_Sovereign.exe --gate-verify
set "GATE_RC=%errorlevel%"
if /I "%GATE_RC%" == "-889275714" goto :gate_ok
if /I "%GATE_RC%" == "3405691582" goto :gate_ok
echo [FATAL] Integrity failure (exit=%GATE_RC%). Build halted.
exit /b 1
:gate_ok
echo [SUCCESS] Sovereign Engine verified. Gate=0xCAFEBABE
endlocal
