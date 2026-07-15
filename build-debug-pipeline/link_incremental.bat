@echo off
setlocal enabledelayedexpansion

echo [LINK] RawrXD Incremental Build
echo ================================

set "MASM_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "WINSDK_PATH=C:\Program Files (x86)\Windows Kits\10"
set "WINSDK_VER=10.0.22621.0"

set "LINK=%MASM_PATH%\link.exe"

set "BUILD_DIR=d:\rawrxd\build-master"
set "OUT_DIR=%BUILD_DIR%\bin"

set "LIB_PATH=%MASM_PATH%\lib\x64"
set "LIB_PATH=%LIB_PATH%;%WINSDK_PATH%\Lib\%WINSDK_VER%\um\x64"
set "LIB_PATH=%LIB_PATH%;%WINSDK_PATH%\Lib\%WINSDK_VER%\ucrt\x64"

cd /d d:\rawrxd\build-debug-pipeline

REM Step 1: Core 7 objects (known working)
echo [Step 1] Linking core 7 objects...
"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain /LIBPATH:"%LIB_PATH%" /OUT:"%OUT_DIR%\RawrXD_Step1.dll" "%BUILD_DIR%\input_handler.obj" "%BUILD_DIR%\wndproc_input_bridge.obj" "%BUILD_DIR%\memory.obj" "%BUILD_DIR%\debug_event_ring.obj" "%BUILD_DIR%\ide_debug_bridge.obj" "%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" "%BUILD_DIR%\syntax_highlight.obj" kernel32.lib user32.lib gdi32.lib /SUBSYSTEM:WINDOWS /MACHINE:X64
echo Exit: %ERRORLEVEL%
if not exist "%OUT_DIR%\RawrXD_Step1.dll" (echo FAILED at step 1 & goto :end)

REM Step 2: Add main + inference + agent + lsp + dap
echo.
echo [Step 2] Adding main, inference, agent, lsp, dap...
"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain /LIBPATH:"%LIB_PATH%" /OUT:"%OUT_DIR%\RawrXD_Step2.dll" "%BUILD_DIR%\input_handler.obj" "%BUILD_DIR%\wndproc_input_bridge.obj" "%BUILD_DIR%\memory.obj" "%BUILD_DIR%\debug_event_ring.obj" "%BUILD_DIR%\ide_debug_bridge.obj" "%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" "%BUILD_DIR%\syntax_highlight.obj" "%BUILD_DIR%\main.obj" "%BUILD_DIR%\inference.obj" "%BUILD_DIR%\agent.obj" "%BUILD_DIR%\lsp.obj" "%BUILD_DIR%\dap.obj" kernel32.lib user32.lib gdi32.lib /SUBSYSTEM:WINDOWS /MACHINE:X64
echo Exit: %ERRORLEVEL%
if not exist "%OUT_DIR%\RawrXD_Step2.dll" (echo FAILED at step 2 & goto :end)

REM Step 3: Add swarm + ui + model_loader + simd_kernels + slot_ring
echo.
echo [Step 3] Adding swarm, ui, model_loader, simd_kernels, slot_ring...
"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain /LIBPATH:"%LIB_PATH%" /OUT:"%OUT_DIR%\RawrXD_Step3.dll" "%BUILD_DIR%\input_handler.obj" "%BUILD_DIR%\wndproc_input_bridge.obj" "%BUILD_DIR%\memory.obj" "%BUILD_DIR%\debug_event_ring.obj" "%BUILD_DIR%\ide_debug_bridge.obj" "%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" "%BUILD_DIR%\syntax_highlight.obj" "%BUILD_DIR%\main.obj" "%BUILD_DIR%\inference.obj" "%BUILD_DIR%\agent.obj" "%BUILD_DIR%\lsp.obj" "%BUILD_DIR%\dap.obj" "%BUILD_DIR%\swarm.obj" "%BUILD_DIR%\ui.obj" "%BUILD_DIR%\model_loader.obj" "%BUILD_DIR%\simd_kernels.obj" "%BUILD_DIR%\slot_ring.obj" kernel32.lib user32.lib gdi32.lib /SUBSYSTEM:WINDOWS /MACHINE:X64
echo Exit: %ERRORLEVEL%
if not exist "%OUT_DIR%\RawrXD_Step3.dll" (echo FAILED at step 3 & goto :end)

REM Step 4: Add remaining core modules
echo.
echo [Step 4] Adding beacon, tasks, mesh, bridge, exthost, pe_writer...
"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain /LIBPATH:"%LIB_PATH%" /OUT:"%OUT_DIR%\RawrXD_Step4.dll" "%BUILD_DIR%\input_handler.obj" "%BUILD_DIR%\wndproc_input_bridge.obj" "%BUILD_DIR%\memory.obj" "%BUILD_DIR%\debug_event_ring.obj" "%BUILD_DIR%\ide_debug_bridge.obj" "%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" "%BUILD_DIR%\syntax_highlight.obj" "%BUILD_DIR%\main.obj" "%BUILD_DIR%\inference.obj" "%BUILD_DIR%\agent.obj" "%BUILD_DIR%\lsp.obj" "%BUILD_DIR%\dap.obj" "%BUILD_DIR%\swarm.obj" "%BUILD_DIR%\ui.obj" "%BUILD_DIR%\model_loader.obj" "%BUILD_DIR%\simd_kernels.obj" "%BUILD_DIR%\slot_ring.obj" "%BUILD_DIR%\beacon.obj" "%BUILD_DIR%\tasks.obj" "%BUILD_DIR%\mesh.obj" "%BUILD_DIR%\bridge.obj" "%BUILD_DIR%\exthost.obj" "%BUILD_DIR%\pe_writer.obj" kernel32.lib user32.lib gdi32.lib /SUBSYSTEM:WINDOWS /MACHINE:X64
echo Exit: %ERRORLEVEL%
if not exist "%OUT_DIR%\RawrXD_Step4.dll" (echo FAILED at step 4 & goto :end)

REM Step 5: Add all remaining objects
echo.
echo [Step 5] Adding all remaining objects...
"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain /LIBPATH:"%LIB_PATH%" /OUT:"%OUT_DIR%\RawrXD_Full.dll" "%BUILD_DIR%\input_handler.obj" "%BUILD_DIR%\wndproc_input_bridge.obj" "%BUILD_DIR%\memory.obj" "%BUILD_DIR%\debug_event_ring.obj" "%BUILD_DIR%\ide_debug_bridge.obj" "%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" "%BUILD_DIR%\syntax_highlight.obj" "%BUILD_DIR%\main.obj" "%BUILD_DIR%\inference.obj" "%BUILD_DIR%\agent.obj" "%BUILD_DIR%\lsp.obj" "%BUILD_DIR%\dap.obj" "%BUILD_DIR%\swarm.obj" "%BUILD_DIR%\ui.obj" "%BUILD_DIR%\model_loader.obj" "%BUILD_DIR%\simd_kernels.obj" "%BUILD_DIR%\slot_ring.obj" "%BUILD_DIR%\beacon.obj" "%BUILD_DIR%\tasks.obj" "%BUILD_DIR%\mesh.obj" "%BUILD_DIR%\bridge.obj" "%BUILD_DIR%\exthost.obj" "%BUILD_DIR%\pe_writer.obj" "%BUILD_DIR%\ast_indexer.obj" "%BUILD_DIR%\async_pager.obj" "%BUILD_DIR%\batch_decoder.obj" "%BUILD_DIR%\ollama_client.obj" "%BUILD_DIR%\ollama_sovereign_proxy.obj" "%BUILD_DIR%\stream_loader.obj" "%BUILD_DIR%\stream_token.obj" "%BUILD_DIR%\react_loop.obj" "%BUILD_DIR%\rtp_agent_loop.obj" "%BUILD_DIR%\rtp_protocol.obj" "%BUILD_DIR%\rtp_result_encoder.obj" "%BUILD_DIR%\rtp_stream_parser.obj" "%BUILD_DIR%\rtp_tool_handlers.obj" "%BUILD_DIR%\ui_bridge.obj" "%BUILD_DIR%\webview2.obj" "%BUILD_DIR%\work_steal.obj" "%BUILD_DIR%\editor_stubs.obj" kernel32.lib user32.lib gdi32.lib advapi32.lib shell32.lib ole32.lib /SUBSYSTEM:WINDOWS /MACHINE:X64
echo Exit: %ERRORLEVEL%
if not exist "%OUT_DIR%\RawrXD_Full.dll" (echo FAILED at step 5 & goto :end)

echo.
echo [SUCCESS] All steps completed!
if exist "%OUT_DIR%\RawrXD_Full.dll" (
    for %%F in ("%OUT_DIR%\RawrXD_Full.dll") do echo [SIZE] %%~zF bytes
)

:end
endlocal
