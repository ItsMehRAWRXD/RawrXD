@echo off
setlocal enabledelayedexpansion

echo [LINK] RawrXD Full Monolithic Link - Staged
echo ===========================================

set "MASM_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "WINSDK_PATH=C:\Program Files (x86)\Windows Kits\10"
set "WINSDK_VER=10.0.22621.0"

set "LINK=%MASM_PATH%\link.exe"

set "BUILD_DIR=d:\rawrxd\build-master"
set "OUT_DIR=%BUILD_DIR%\bin"

set "LIB_PATH=%MASM_PATH%\lib\x64"

REM Core objects (original 7)
set "CORE_OBJS="
for %%f in (debug_event_ring.obj editor_stubs.obj ide_debug_bridge.obj input_handler.obj memory.obj RawrXD_UnifiedDebugger.obj syntax_highlight.obj wndproc_input_bridge.obj) do (
    set "CORE_OBJS=!CORE_OBJS! "%BUILD_DIR%\%%f""
)

echo.
echo Linking RawrXD_Core.dll (7 objects)...

"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /NOENTRY ^
    /LIBPATH:"%LIB_PATH%" ^
    /LIBPATH:"%WINSDK_PATH%\Lib\%WINSDK_VER%\um\x64" ^
    /LIBPATH:"%WINSDK_PATH%\Lib\%WINSDK_VER%\ucrt\x64" ^
    /OUT:"%OUT_DIR%\RawrXD_Core.dll" ^
    /PDB:"%OUT_DIR%\RawrXD_Core.pdb" ^
    !CORE_OBJS! ^
    kernel32.lib user32.lib gdi32.lib ^
    /SUBSYSTEM:WINDOWS /MACHINE:X64 /LARGEADDRESSAWARE

echo Core Exit: %ERRORLEVEL%

if exist "%OUT_DIR%\RawrXD_Core.dll" (
    echo [SUCCESS] Core: %OUT_DIR%\RawrXD_Core.dll
) else (
    echo [ERROR] Core failed
    goto :end
)

REM Monolithic objects (33 more)
set "MONO_OBJS="
for %%f in (main.obj inference.obj agent.obj lsp.obj dap.obj swarm.obj ui.obj model_loader.obj simd_kernels.obj slot_ring.obj beacon.obj tasks.obj mesh.obj bridge.obj exthost.obj pe_writer.obj ast_indexer.obj async_pager.obj batch_decoder.obj ollama_client.obj ollama_sovereign_proxy.obj stream_loader.obj stream_token.obj react_loop.obj rtp_agent_loop.obj rtp_protocol.obj rtp_result_encoder.obj rtp_stream_parser.obj rtp_tool_handlers.obj ui_bridge.obj webview2.obj work_steal.obj) do (
    set "MONO_OBJS=!MONO_OBJS! "%BUILD_DIR%\%%f""
)

echo.
echo Linking RawrXD_Monolithic.dll (33 objects)...

"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /NOENTRY ^
    /LIBPATH:"%LIB_PATH%" ^
    /LIBPATH:"%WINSDK_PATH%\Lib\%WINSDK_VER%\um\x64" ^
    /LIBPATH:"%WINSDK_PATH%\Lib\%WINSDK_VER%\ucrt\x64" ^
    /OUT:"%OUT_DIR%\RawrXD_Monolithic.dll" ^
    /PDB:"%OUT_DIR%\RawrXD_Monolithic.pdb" ^
    !MONO_OBJS! ^
    kernel32.lib user32.lib gdi32.lib advapi32.lib shell32.lib ole32.lib ^
    /SUBSYSTEM:WINDOWS /MACHINE:X64 /LARGEADDRESSAWARE

echo Monolithic Exit: %ERRORLEVEL%

if exist "%OUT_DIR%\RawrXD_Monolithic.dll" (
    echo [SUCCESS] Monolithic: %OUT_DIR%\RawrXD_Monolithic.dll
    for %%F in ("%OUT_DIR%\RawrXD_Monolithic.dll") do echo [SIZE] %%~zF bytes
) else (
    echo [ERROR] Monolithic failed
)

:end
endlocal
