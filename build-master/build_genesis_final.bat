@echo off
setlocal enabledelayedexpansion

echo [BUILD] RawrXD Complete - Genesis MASM64
echo =========================================

set "MASM_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "WINSDK_PATH=C:\Program Files (x86)\Windows Kits\10"
set "WINSDK_VER=10.0.22621.0"

set "ML64=%MASM_PATH%\ml64.exe"
set "LINK=%MASM_PATH%\link.exe"

set "BUILD_DIR=d:\rawrxd\build-master"
set "BIN_DIR=%BUILD_DIR%\bin"
set "SRC_ASM=d:\rawrxd\src\asm"
set "SRC_MONO=%SRC_ASM%\monolithic"
set "DEBUG_PIPE=d:\rawrxd\build-debug-pipeline"

REM Library paths
set "LIBPATH1=%MASM_PATH%\lib\x64"
set "LIBPATH2=%WINSDK_PATH%\Lib\%WINSDK_VER%\um\x64"
set "LIBPATH3=%WINSDK_PATH%\Lib\%WINSDK_VER%\ucrt\x64"

REM Ensure output directory exists
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"

echo.
echo [1/3] Assembling core modules...
cd /d "%SRC_ASM%"

for %%f in (debug_event_ring.asm editor_stubs.asm ide_debug_bridge.asm input_handler.asm memory.asm RawrXD_UnifiedDebugger.asm syntax_highlight.asm wndproc_input_bridge.asm) do (
    if exist "%%f" (
        echo   - %%f
        "%ML64%" /c /W3 /nologo /Zi /Fo "%BUILD_DIR%\%%~nf.obj" "%%f" 2>nul
    )
)

echo.
echo [2/3] Assembling monolithic modules...
cd /d "%SRC_MONO%"

for %%f in (main.asm inference.asm agent.asm lsp.asm dap.asm swarm.asm ui.asm model_loader.asm simd_kernels.asm slot_ring.asm beacon.asm tasks.asm mesh.asm bridge.asm exthost.asm pe_writer.asm ast_indexer.asm async_pager.asm batch_decoder.asm ollama_client.asm ollama_sovereign_proxy.asm stream_loader.asm stream_token.asm react_loop.asm rtp_agent_loop.asm rtp_protocol.asm rtp_result_encoder.asm rtp_stream_parser.asm rtp_tool_handlers.asm ui_bridge.asm webview2.asm work_steal.asm) do (
    if exist "%%f" (
        echo   - %%f
        "%ML64%" /c /W3 /nologo /Zi /Fo "%BUILD_DIR%\%%~nf.obj" "%%f" 2>nul
    )
)

echo.
echo [3/3] Linking unified DLL...

REM MUST run from debug-pipeline directory
cd /d "%DEBUG_PIPE%"

echo Running from: %CD%

REM Create response file with all objects
echo /DLL > link.rsp
echo /DEBUG >> link.rsp
echo /INCREMENTAL:NO >> link.rsp
echo /ENTRY:DllMain >> link.rsp
echo /OUT:"%BIN_DIR%\RawrXD_Unified.dll" >> link.rsp
echo /PDB:"%BIN_DIR%\RawrXD_Unified.pdb" >> link.rsp

REM Add all objects from build-master
cd /d "%BUILD_DIR%"
for %%f in (*.obj) do (
    echo "%BUILD_DIR%\%%f" >> "%DEBUG_PIPE%\link.rsp"
)

echo kernel32.lib >> "%DEBUG_PIPE%\link.rsp"

cd /d "%DEBUG_PIPE%"

echo.
echo Linking with response file...
"%LINK%" @link.rsp /LIBPATH:"%LIBPATH1%" /LIBPATH:"%LIBPATH2%" /LIBPATH:"%LIBPATH3%"

set "LINK_RESULT=%ERRORLEVEL%"
echo.
echo Link Exit Code: %LINK_RESULT%

if exist "%BIN_DIR%\RawrXD_Unified.dll" (
    echo SUCCESS: RawrXD_Unified.dll created
    for %%f in ("%BIN_DIR%\RawrXD_Unified.dll") do echo Size: %%~zf bytes
) else (
    echo FAILED: RawrXD_Unified.dll not created
)

REM Cleanup
del link.rsp 2>nul

cd /d "%BUILD_DIR%"
echo.
echo Build complete.

endlocal
