@echo off
set ML64="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set LINK="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set SRC_DIR=d:\rawrxd\src
set ASM_DIR=d:\rawrxd\src\asm
set OUT_DIR=d:\rawrxd\obj

if not exist %OUT_DIR% mkdir %OUT_DIR%

set ASM_OPTS=/c /nologo /Zi /I %SRC_DIR%

echo Building Sovereign Modules...

%ML64% %ASM_OPTS% /Fo %OUT_DIR%\Sovereign_Main.obj %SRC_DIR%\Sovereign_Main.asm
%ML64% %ASM_OPTS% /Fo %OUT_DIR%\Sovereign_PEB_Loader.obj %SRC_DIR%\Sovereign_PEB_Loader.asm
%ML64% %ASM_OPTS% /Fo %OUT_DIR%\Sovereign_IPC.obj %SRC_DIR%\Sovereign_IPC.asm
%ML64% %ASM_OPTS% /Fo %OUT_DIR%\Sovereign_Model_Loader_NEW.obj %SRC_DIR%\Sovereign_Model_Loader_NEW.asm
%ML64% %ASM_OPTS% /Fo %OUT_DIR%\Sovereign_Action_Dispatcher.obj %SRC_DIR%\Sovereign_Action_Dispatcher.asm
%ML64% %ASM_OPTS% /Fo %OUT_DIR%\Sovereign_GGUF_Parser.obj %SRC_DIR%\Sovereign_GGUF_Parser.asm
%ML64% %ASM_OPTS% /Fo %OUT_DIR%\Sovereign_Finisher.obj %SRC_DIR%\Sovereign_Finisher.asm
%ML64% %ASM_OPTS% /Fo %OUT_DIR%\Sovereign_Compute_Kernel.obj %SRC_DIR%\Sovereign_Compute_Kernel.asm
%ML64% %ASM_OPTS% /Fo %OUT_DIR%\Sovereign_Inference_Dispatcher.obj %SRC_DIR%\Sovereign_Inference_Dispatcher.asm
%ML64% %ASM_OPTS% /Fo %OUT_DIR%\Sovereign_Sampler_NEW.obj %SRC_DIR%\Sovereign_Sampler_NEW.asm
%ML64% %ASM_OPTS% /Fo %OUT_DIR%\Sovereign_Gameplay_Manager.obj %ASM_DIR%\Sovereign_Gameplay_Manager.asm
%ML64% %ASM_OPTS% /Fo %OUT_DIR%\Sovereign_OS_Core.obj %ASM_DIR%\Sovereign_OS_Core.asm
%ML64% %ASM_OPTS% /Fo %OUT_DIR%\Sovereign_OS_FaultHandler.obj %ASM_DIR%\Sovereign_OS_FaultHandler.asm
%ML64% %ASM_OPTS% /Fo %OUT_DIR%\Sovereign_JIT_Engine.obj %ASM_DIR%\Sovereign_JIT_Engine.asm
%ML64% %ASM_OPTS% /Fo %OUT_DIR%\Sovereign_Kernel_Registry.obj %ASM_DIR%\Sovereign_Kernel_Registry.asm
%ML64% %ASM_OPTS% /Fo %OUT_DIR%\Sovereign_OS_MemoryGuard.obj %ASM_DIR%\Sovereign_OS_MemoryGuard.asm
%ML64% %ASM_OPTS% /Fo %OUT_DIR%\Sovereign_Globals.obj %SRC_DIR%\Sovereign_Globals.asm
%ML64% %ASM_OPTS% /Fo %OUT_DIR%\Sovereign_Stubs.obj %SRC_DIR%\Sovereign_Stubs.asm
%ML64% %ASM_OPTS% /Fo %OUT_DIR%\Sovereign_KV_Cache.obj %SRC_DIR%\Sovereign_KV_Cache.asm
%ML64% %ASM_OPTS% /Fo %OUT_DIR%\Sovereign_AppendLog_SHA256NI.obj %ASM_DIR%\Sovereign_AppendLog_SHA256NI.asm
%ML64% %ASM_OPTS% /Fo %OUT_DIR%\Sovereign_Execution_Graph_Logic.obj %ASM_DIR%\Sovereign_Execution_Graph_Logic.asm
%ML64% %ASM_OPTS% /Fo %OUT_DIR%\Sovereign_Stream_Ingest.obj %ASM_DIR%\Sovereign_Stream_Ingest.asm

echo Linking Monolith: Sovereign_Engine.exe...
%LINK% /nologo @d:\rawrxd\Sovereign_Engine.rsp

if %ERRORLEVEL% NEQ 0 (
    echo LINK FAILED
    exit /b %ERRORLEVEL%
)

echo BUILD COMPLETE: Sovereign_Engine.exe
