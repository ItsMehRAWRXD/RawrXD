@echo off
setlocal EnableDelayedExpansion

REM Build all monolithic ASM modules and link into unified DLL

set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe
set SRCDIR=d:\rawrxd\src\asm\monolithic
set OUTDIR=d:\rawrxd\build-master
set BINDIR=%OUTDIR%\bin

REM Ensure output directories exist
if not exist "%BINDIR%" mkdir "%BINDIR%"

REM Assemble all monolithic modules
cd /d "%SRCDIR%"

echo Assembling monolithic modules...

for %%f in (main.asm inference.asm agent.asm lsp.asm dap.asm swarm.asm ui.asm model_loader.asm simd_kernels.asm slot_ring.asm beacon.asm tasks.asm mesh.asm bridge.asm exthost.asm pe_writer.asm ast_indexer.asm async_pager.asm batch_decoder.asm ollama_client.asm ollama_sovereign_proxy.asm stream_loader.asm stream_token.asm react_loop.asm rtp_agent_loop.asm rtp_protocol.asm rtp_result_encoder.asm rtp_stream_parser.asm rtp_tool_handlers.asm ui_bridge.asm webview2.asm work_steal.asm) do (
    if exist "%%f" (
        echo   %%f
        "%ML64%" /c /W3 /nologo /Zi /Fo "%OUTDIR%\%%~nf.obj" "%%f" >nul 2>&1
        if errorlevel 1 echo     FAILED: %%f
    )
)

REM Also assemble core modules from parent directory
for %%f in (debug_event_ring.asm editor_stubs.asm ide_debug_bridge.asm input_handler.asm memory.asm RawrXD_UnifiedDebugger.asm syntax_highlight.asm wndproc_input_bridge.asm) do (
    if exist "..\%%f" (
        echo   %%f
        "%ML64%" /c /W3 /nologo /Zi /Fo "%OUTDIR%\%%~nf.obj" "..\%%f" >nul 2>&1
        if errorlevel 1 echo     FAILED: %%f
    )
)

echo.
echo Linking unified DLL...

REM Must run link from build-debug-pipeline to avoid STATUS_DLL_NOT_FOUND
cd /d d:\rawrxd\build-debug-pipeline

"%LINK%" /DLL /DEBUG /INCREMENTAL:NO /LIBPATH:"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\lib\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" /OUT:%BINDIR%\RawrXD_Unified.dll %OUTDIR%\*.obj kernel32.lib user32.lib gdi32.lib advapi32.lib shell32.lib ole32.lib /SUBSYSTEM:WINDOWS /MACHINE:X64 /LARGEADDRESSAWARE /NOENTRY

echo Exit: %ERRORLEVEL%

cd /d "%OUTDIR%"

echo.
echo Build complete. Output: %BINDIR%\RawrXD_Unified.dll
