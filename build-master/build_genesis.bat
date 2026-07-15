@echo off
setlocal enabledelayedexpansion

echo [BUILD] RawrXD Full Unified Build - Genesis MASM64
echo =================================================

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
echo [1/3] Assembling core modules from src\asm...
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
echo [3/3] Linking unified DLL from debug-pipeline context...

REM Create response file with all objects
cd /d "%BUILD_DIR%"
echo. > "%DEBUG_PIPE%\objects.rsp"
for %%f in (*.obj) do (
    echo "%BUILD_DIR%\%%f" >> "%DEBUG_PIPE%\objects.rsp"
)

REM Create link command script in debug-pipeline directory
echo @echo off > "%DEBUG_PIPE%\do_link.bat"
echo setlocal >> "%DEBUG_PIPE%\do_link.bat"
echo "%LINK%" @objects.rsp /DLL /OUT:"%BIN_DIR%\RawrXD_Full.dll" /PDB:"%BIN_DIR%\RawrXD_Full.pdb" /LIBPATH:"%LIBPATH1%" /LIBPATH:"%LIBPATH2%" /LIBPATH:"%LIBPATH3%" kernel32.lib user32.lib gdi32.lib advapi32.lib shell32.lib ole32.lib /SUBSYSTEM:WINDOWS /MACHINE:X64 /LARGEADDRESSAWARE /DEBUG /INCREMENTAL:NO >> "%DEBUG_PIPE%\do_link.bat"
echo exit /b %%ERRORLEVEL%% >> "%DEBUG_PIPE%\do_link.bat"

REM Execute link from debug-pipeline directory (where runtime DLLs exist)
cd /d "%DEBUG_PIPE%"
call do_link.bat

set "LINK_RESULT=%ERRORLEVEL%"

echo.
echo Link Exit Code: %LINK_RESULT%

if exist "%BIN_DIR%\RawrXD_Full.dll" (
    echo SUCCESS: RawrXD_Full.dll created
    for %%f in ("%BIN_DIR%\RawrXD_Full.dll") do echo Size: %%~zf bytes
) else (
    echo FAILED: RawrXD_Full.dll not created
)

REM Cleanup
del "%DEBUG_PIPE%\objects.rsp" 2>nul
del "%DEBUG_PIPE%\do_link.bat" 2>nul

cd /d "%BUILD_DIR%"
echo.
echo Build complete.
