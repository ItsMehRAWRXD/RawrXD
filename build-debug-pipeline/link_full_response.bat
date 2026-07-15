@echo off
setlocal enabledelayedexpansion

echo [LINK] RawrXD Full Build - Response File
echo =======================================

set "MASM_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "WINSDK_PATH=C:\Program Files (x86)\Windows Kits\10"
set "WINSDK_VER=10.0.22621.0"

set "LINK=%MASM_PATH%\link.exe"

set "BUILD_DIR=d:\rawrxd\build-master"
set "OUT_DIR=%BUILD_DIR%\bin"

set "LIB_PATH=%MASM_PATH%\lib\x64"
set "LIB_PATH=%LIB_PATH%;%WINSDK_PATH%\Lib\%WINSDK_VER%\um\x64"
set "LIB_PATH=%LIB_PATH%;%WINSDK_PATH%\Lib\%WINSDK_VER%\ucrt\x64"

echo Creating response file...

echo /DLL > link_full.rsp
echo /DEBUG >> link_full.rsp
echo /INCREMENTAL:NO >> link_full.rsp
echo /ENTRY:DllMain >> link_full.rsp
echo /OUT:"%OUT_DIR%\RawrXD_Full.dll" >> link_full.rsp
echo /PDB:"%OUT_DIR%\RawrXD_Full.pdb" >> link_full.rsp
echo "%BUILD_DIR%\agent.obj" >> link_full.rsp
echo "%BUILD_DIR%\ast_indexer.obj" >> link_full.rsp
echo "%BUILD_DIR%\async_pager.obj" >> link_full.rsp
echo "%BUILD_DIR%\batch_decoder.obj" >> link_full.rsp
echo "%BUILD_DIR%\beacon.obj" >> link_full.rsp
echo "%BUILD_DIR%\bridge.obj" >> link_full.rsp
echo "%BUILD_DIR%\dap.obj" >> link_full.rsp
echo "%BUILD_DIR%\debug_event_ring.obj" >> link_full.rsp
echo "%BUILD_DIR%\editor_stubs.obj" >> link_full.rsp
echo "%BUILD_DIR%\exthost.obj" >> link_full.rsp
echo "%BUILD_DIR%\ide_debug_bridge.obj" >> link_full.rsp
echo "%BUILD_DIR%\inference.obj" >> link_full.rsp
echo "%BUILD_DIR%\input_handler.obj" >> link_full.rsp
echo "%BUILD_DIR%\lsp.obj" >> link_full.rsp
echo "%BUILD_DIR%\main.obj" >> link_full.rsp
echo "%BUILD_DIR%\memory.obj" >> link_full.rsp
echo "%BUILD_DIR%\mesh.obj" >> link_full.rsp
echo "%BUILD_DIR%\model_loader.obj" >> link_full.rsp
echo "%BUILD_DIR%\ollama_client.obj" >> link_full.rsp
echo "%BUILD_DIR%\ollama_sovereign_proxy.obj" >> link_full.rsp
echo "%BUILD_DIR%\pe_writer.obj" >> link_full.rsp
echo "%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" >> link_full.rsp
echo "%BUILD_DIR%\react_loop.obj" >> link_full.rsp
echo "%BUILD_DIR%\rtp_agent_loop.obj" >> link_full.rsp
echo "%BUILD_DIR%\rtp_protocol.obj" >> link_full.rsp
echo "%BUILD_DIR%\rtp_result_encoder.obj" >> link_full.rsp
echo "%BUILD_DIR%\rtp_stream_parser.obj" >> link_full.rsp
echo "%BUILD_DIR%\rtp_tool_handlers.obj" >> link_full.rsp
echo "%BUILD_DIR%\simd_kernels.obj" >> link_full.rsp
echo "%BUILD_DIR%\slot_ring.obj" >> link_full.rsp
echo "%BUILD_DIR%\stream_loader.obj" >> link_full.rsp
echo "%BUILD_DIR%\stream_token.obj" >> link_full.rsp
echo "%BUILD_DIR%\swarm.obj" >> link_full.rsp
echo "%BUILD_DIR%\syntax_highlight.obj" >> link_full.rsp
echo "%BUILD_DIR%\tasks.obj" >> link_full.rsp
echo "%BUILD_DIR%\ui.obj" >> link_full.rsp
echo "%BUILD_DIR%\ui_bridge.obj" >> link_full.rsp
echo "%BUILD_DIR%\webview2.obj" >> link_full.rsp
echo "%BUILD_DIR%\wndproc_input_bridge.obj" >> link_full.rsp
echo "%BUILD_DIR%\work_steal.obj" >> link_full.rsp
echo kernel32.lib >> link_full.rsp

echo Response file created.
echo.
echo [LINK] Linking with response file...

"%LINK%" @link_full.rsp /LIBPATH:"%LIB_PATH%"

echo Exit code: %ERRORLEVEL%

if exist "%OUT_DIR%\RawrXD_Full.dll" (
    echo [SUCCESS] Built: %OUT_DIR%\RawrXD_Full.dll
    for %%F in ("%OUT_DIR%\RawrXD_Full.dll") do echo [SIZE] %%~zF bytes
) else (
    echo [ERROR] DLL not created
)

REM Cleanup
del link_full.rsp 2>nul

endlocal
