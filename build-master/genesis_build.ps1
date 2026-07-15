# Genesis MASM64 Build System - PowerShell Edition
# Compiles all RawrXD ASM modules into unified DLL

$ErrorActionPreference = "Continue"

$MASM_PATH = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
$ML64 = "$MASM_PATH\ml64.exe"
$LINK = "$MASM_PATH\link.exe"

$BUILD_DIR = "d:\rawrxd\build-master"
$BIN_DIR = "$BUILD_DIR\bin"
$SRC_ASM = "d:\rawrxd\src\asm"
$SRC_MONO = "$SRC_ASM\monolithic"
$DEBUG_PIPE = "d:\rawrxd\build-debug-pipeline"

Write-Host "[GENESIS] RawrXD Full Unified Build" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan

# Ensure output directory exists
if (-not (Test-Path $BIN_DIR)) { New-Item -ItemType Directory -Path $BIN_DIR -Force | Out-Null }

# Assemble core modules
Write-Host "`n[1/3] Assembling core modules..." -ForegroundColor Yellow
$coreFiles = @(
    "debug_event_ring.asm", "editor_stubs.asm", "ide_debug_bridge.asm",
    "input_handler.asm", "memory.asm", "RawrXD_UnifiedDebugger.asm",
    "syntax_highlight.asm", "wndproc_input_bridge.asm"
)

$coreObjs = @()
Push-Location $SRC_ASM
foreach ($f in $coreFiles) {
    if (Test-Path $f) {
        Write-Host "  - $f"
        $objName = [System.IO.Path]::GetFileNameWithoutExtension($f) + ".obj"
        $objPath = Join-Path $BUILD_DIR $objName
        & $ML64 /c /W3 /nologo /Zi /Fo $objPath $f 2>$null
        if ($LASTEXITCODE -eq 0) { $coreObjs += $objPath }
    }
}
Pop-Location

# Assemble monolithic modules
Write-Host "`n[2/3] Assembling monolithic modules..." -ForegroundColor Yellow
$monoFiles = @(
    "main.asm", "inference.asm", "agent.asm", "lsp.asm", "dap.asm",
    "swarm.asm", "ui.asm", "model_loader.asm", "simd_kernels.asm",
    "slot_ring.asm", "beacon.asm", "tasks.asm", "mesh.asm", "bridge.asm",
    "exthost.asm", "pe_writer.asm", "ast_indexer.asm", "async_pager.asm",
    "batch_decoder.asm", "ollama_client.asm", "ollama_sovereign_proxy.asm",
    "stream_loader.asm", "stream_token.asm", "react_loop.asm",
    "rtp_agent_loop.asm", "rtp_protocol.asm", "rtp_result_encoder.asm",
    "rtp_stream_parser.asm", "rtp_tool_handlers.asm", "ui_bridge.asm",
    "webview2.asm", "work_steal.asm"
)

$monoObjs = @()
Push-Location $SRC_MONO
foreach ($f in $monoFiles) {
    if (Test-Path $f) {
        Write-Host "  - $f"
        $objName = [System.IO.Path]::GetFileNameWithoutExtension($f) + ".obj"
        $objPath = Join-Path $BUILD_DIR $objName
        
        & $ML64 /c /W3 /nologo /Zi /Fo $objPath $f 2>$null
        if ($LASTEXITCODE -eq 0) { $monoObjs += $objPath }
    }
}
Pop-Location

$allObjs = $coreObjs + $monoObjs
Write-Host "`nAssembled $($allObjs.Count) objects successfully" -ForegroundColor Green

# Link from debug-pipeline context
Write-Host "`n[3/3] Linking unified DLL..." -ForegroundColor Yellow

Push-Location $DEBUG_PIPE

$objList = $allObjs -join ' '
$linkArgs = @(
    "/DLL", "/DEBUG", "/INCREMENTAL:NO", "/NOENTRY",
    "/OUT:$BIN_DIR\RawrXD_Full.dll",
    "/PDB:$BIN_DIR\RawrXD_Full.pdb"
) + $allObjs + @(
    "kernel32.lib", "user32.lib", "gdi32.lib",
    "/SUBSYSTEM:WINDOWS", "/MACHINE:X64", "/LARGEADDRESSAWARE"
)

& $LINK $linkArgs
$linkExit = $LASTEXITCODE

Pop-Location

Write-Host "`nLink Exit Code: $linkExit" -ForegroundColor $(if ($linkExit -eq 0) { "Green" } else { "Red" })

if (Test-Path "$BIN_DIR\RawrXD_Full.dll") {
    $size = (Get-Item "$BIN_DIR\RawrXD_Full.dll").Length
    Write-Host "`n[SUCCESS] RawrXD_Full.dll created" -ForegroundColor Green
    Write-Host "  Size: $size bytes" -ForegroundColor Cyan
    Write-Host "  Path: $BIN_DIR\RawrXD_Full.dll" -ForegroundColor Cyan
} else {
    Write-Host "`n[ERROR] RawrXD_Full.dll not created" -ForegroundColor Red
}

Write-Host "`nBuild complete." -ForegroundColor Cyan
