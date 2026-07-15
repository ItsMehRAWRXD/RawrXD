@echo off
setlocal enabledelayedexpansion

echo [LINK] RawrXD Full Build - Matching Working Script
echo =================================================

set "MASM_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "WINSDK_PATH=C:\Program Files (x86)\Windows Kits\10"
set "WINSDK_VER=10.0.22621.0"

set "LINK=%MASM_PATH%\link.exe"

set "BUILD_DIR=d:\rawrxd\build-master"
set "OUT_DIR=%BUILD_DIR%\bin"

set "LIB_PATH=%MASM_PATH%\lib\x64"
set "LIB_PATH=%LIB_PATH%;%WINSDK_PATH%\Lib\%WINSDK_VER%\um\x64"
set "LIB_PATH=%LIB_PATH%;%WINSDK_PATH%\Lib\%WINSDK_VER%\ucrt\x64"

echo [LINK] Linking RawrXD_Full.dll...

"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain ^
    /LIBPATH:"%LIB_PATH%" ^
    /OUT:"%OUT_DIR%\RawrXD_Full.dll" ^
    /PDB:"%OUT_DIR%\RawrXD_Full.pdb" ^
    "%BUILD_DIR%\agent.obj" ^
    "%BUILD_DIR%\ast_indexer.obj" ^
    "%BUILD_DIR%\async_pager.obj" ^
    "%BUILD_DIR%\batch_decoder.obj" ^
    "%BUILD_DIR%\beacon.obj" ^
    "%BUILD_DIR%\bridge.obj" ^
    "%BUILD_DIR%\dap.obj" ^
    "%BUILD_DIR%\debug_event_ring.obj" ^
    "%BUILD_DIR%\editor_stubs.obj" ^
    "%BUILD_DIR%\exthost.obj" ^
    "%BUILD_DIR%\ide_debug_bridge.obj" ^
    "%BUILD_DIR%\inference.obj" ^
    "%BUILD_DIR%\input_handler.obj" ^
    "%BUILD_DIR%\lsp.obj" ^
    "%BUILD_DIR%\main.obj" ^
    "%BUILD_DIR%\memory.obj" ^
    "%BUILD_DIR%\mesh.obj" ^
    "%BUILD_DIR%\model_loader.obj" ^
    "%BUILD_DIR%\ollama_client.obj" ^
    "%BUILD_DIR%\ollama_sovereign_proxy.obj" ^
    "%BUILD_DIR%\pe_writer.obj" ^
    "%BUILD_DIR%\RawrXD_UnifiedDebugger.obj" ^
    "%BUILD_DIR%\react_loop.obj" ^
    "%BUILD_DIR%\rtp_agent_loop.obj" ^
    "%BUILD_DIR%\rtp_protocol.obj" ^
    "%BUILD_DIR%\rtp_result_encoder.obj" ^
    "%BUILD_DIR%\rtp_stream_parser.obj" ^
    "%BUILD_DIR%\rtp_tool_handlers.obj" ^
    "%BUILD_DIR%\simd_kernels.obj" ^
    "%BUILD_DIR%\slot_ring.obj" ^
    "%BUILD_DIR%\stream_loader.obj" ^
    "%BUILD_DIR%\stream_token.obj" ^
    "%BUILD_DIR%\swarm.obj" ^
    "%BUILD_DIR%\syntax_highlight.obj" ^
    "%BUILD_DIR%\tasks.obj" ^
    "%BUILD_DIR%\ui.obj" ^
    "%BUILD_DIR%\ui_bridge.obj" ^
    "%BUILD_DIR%\webview2.obj" ^
    "%BUILD_DIR%\wndproc_input_bridge.obj" ^
    "%BUILD_DIR%\work_steal.obj" ^
    kernel32.lib

echo Exit code: %ERRORLEVEL%

if exist "%OUT_DIR%\RawrXD_Full.dll" (
    echo [SUCCESS] Built: %OUT_DIR%\RawrXD_Full.dll
    for %%F in ("%OUT_DIR%\RawrXD_Full.dll") do echo [SIZE] %%~zF bytes
) else (
    echo [ERROR] DLL not created
)

endlocal
