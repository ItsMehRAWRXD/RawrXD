# Genesis MASM64 Build System - Complete Unified Build
# PowerShell Edition with proper working directory

$ErrorActionPreference = "Continue"

$MASM_PATH = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
$ML64 = "$MASM_PATH\ml64.exe"
$LINK = "$MASM_PATH\link.exe"

$BUILD_DIR = "d:\rawrxd\build-master"
$BIN_DIR = "$BUILD_DIR\bin"
$SRC_ASM = "d:\rawrxd\src\asm"
$SRC_MONO = "$SRC_ASM\monolithic"
$DEBUG_PIPE = "d:\rawrxd\build-debug-pipeline"

$LIBPATH1 = "$MASM_PATH\lib\x64"
$LIBPATH2 = "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"
$LIBPATH3 = "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64"

Write-Host "[GENESIS] RawrXD Complete Unified Build" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Ensure output directory exists
if (-not (Test-Path $BIN_DIR)) { New-Item -ItemType Directory -Path $BIN_DIR -Force | Out-Null }

# Assemble core modules
Write-Host "`n[1/3] Assembling core modules..." -ForegroundColor Yellow
$coreFiles = @(
    "debug_event_ring.asm", "editor_stubs.asm", "ide_debug_bridge.asm",
    "input_handler.asm", "memory.asm", "RawrXD_UnifiedDebugger.asm",
    "syntax_highlight.asm", "wndproc_input_bridge.asm"
)

Push-Location $SRC_ASM
foreach ($f in $coreFiles) {
    if (Test-Path $f) {
        Write-Host "  - $f"
        $objName = [System.IO.Path]::GetFileNameWithoutExtension($f) + ".obj"
        $objPath = Join-Path $BUILD_DIR $objName
        & $ML64 /c /W3 /nologo /Zi /Fo $objPath $f 2>$null
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

Push-Location $SRC_MONO
foreach ($f in $monoFiles) {
    if (Test-Path $f) {
        Write-Host "  - $f"
        $objName = [System.IO.Path]::GetFileNameWithoutExtension($f) + ".obj"
        $objPath = Join-Path $BUILD_DIR $objName
        & $ML64 /c /W3 /nologo /Zi /Fo $objPath $f 2>$null
    }
}
Pop-Location

# Count objects
$objCount = (Get-ChildItem "$BUILD_DIR\*.obj" -ErrorAction SilentlyContinue).Count
Write-Host "`nAssembled $objCount objects" -ForegroundColor Green

# Link from debug-pipeline context
Write-Host "`n[3/3] Linking unified DLL..." -ForegroundColor Yellow

# Build object list
$objFiles = Get-ChildItem "$BUILD_DIR\*.obj" | ForEach-Object { '"' + $_.FullName + '"' }
$objList = $objFiles -join ' '

# Create link arguments
$linkArgs = "/DLL /DEBUG /INCREMENTAL:NO /ENTRY:DllMain /LIBPATH:`"$LIBPATH1`" /LIBPATH:`"$LIBPATH2`" /LIBPATH:`"$LIBPATH3`" /OUT:`"$BIN_DIR\RawrXD_Unified.dll`" /PDB:`"$BIN_DIR\RawrXD_Unified.pdb`" $objList kernel32.lib"

Write-Host "Running linker from: $DEBUG_PIPE"
Write-Host "Link arguments length: $($linkArgs.Length)"

# Run linker from debug-pipeline directory
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $LINK
$psi.Arguments = $linkArgs
$psi.WorkingDirectory = $DEBUG_PIPE
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true

$process = [System.Diagnostics.Process]::Start($psi)
$stdout = $process.StandardOutput.ReadToEnd()
$stderr = $process.StandardError.ReadToEnd()
$process.WaitForExit()

$linkExit = $process.ExitCode

if ($stdout) { Write-Host $stdout }
if ($stderr) { Write-Host $stderr -ForegroundColor Red }

Write-Host "`nLink Exit Code: $linkExit" -ForegroundColor $(if ($linkExit -eq 0) { "Green" } else { "Red" })

if (Test-Path "$BIN_DIR\RawrXD_Unified.dll") {
    $dll = Get-Item "$BIN_DIR\RawrXD_Unified.dll"
    Write-Host "`n[SUCCESS] RawrXD_Unified.dll created" -ForegroundColor Green
    Write-Host "  Size: $($dll.Length) bytes" -ForegroundColor Cyan
    Write-Host "  Path: $($dll.FullName)" -ForegroundColor Cyan
} else {
    Write-Host "`n[ERROR] RawrXD_Unified.dll not created" -ForegroundColor Red
}

Write-Host "`nBuild complete." -ForegroundColor Cyan
