# RawrXD Pure MASM64 Build Script
# Zero C++ dependencies - Pure assembly build
# Assembles all monolithic ASM files and links into RawrXD_IDE.exe

param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    
    [switch]$Clean,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# MSVC Tool Paths
$VS2022 = "C:\VS2022Enterprise"
$MSVC = "$VS2022\VC\Tools\MSVC\14.50.35717"
$ML64 = "$MSVC\bin\Hostx64\x64\ml64.exe"
$LINK = "$MSVC\bin\Hostx64\x64\link.exe"

# Project paths
$ProjectRoot = $PSScriptRoot
$SrcDir = Join-Path $ProjectRoot "src\asm"
$MonolithicDir = Join-Path $SrcDir "monolithic"
$BuildDir = Join-Path $ProjectRoot "build\MASM64"
$OutputDir = Join-Path $ProjectRoot "build\Release"

# Output binary
$OutputExe = Join-Path $OutputDir "RawrXD_IDE.exe"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  RawrXD Pure MASM64 Build System" -ForegroundColor Cyan
Write-Host "  Zero C++ Dependencies" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# Verify toolchain
if (-not (Test-Path $ML64)) {
    Write-Host "[ERROR] ml64.exe not found at: $ML64" -ForegroundColor Red
    Write-Host "Please install Visual Studio 2022 with MASM tools" -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path $LINK)) {
    Write-Host "[ERROR] link.exe not found at: $LINK" -ForegroundColor Red
    exit 1
}

Write-Host "[OK] Toolchain verified" -ForegroundColor Green
Write-Host "  ml64: $ML64" -ForegroundColor Gray
Write-Host "  link: $LINK" -ForegroundColor Gray

# Clean if requested
if ($Clean) {
    Write-Host "`n[*] Cleaning build artifacts..." -ForegroundColor Yellow
    if (Test-Path $BuildDir) { Remove-Item $BuildDir -Recurse -Force }
    if (Test-Path $OutputDir) { Remove-Item $OutputDir -Recurse -Force }
    Write-Host "[OK] Clean complete" -ForegroundColor Green
    exit 0
}

# Create directories
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Collect all ASM files
$AsmFiles = @()

# Core monolithic files (order matters for linking)
$CoreFiles = @(
    "main.asm",
    "inference.asm",
    "ui.asm",
    "beacon.asm",
    "lsp.asm",
    "agent.asm",
    "model_loader.asm",
    "dap.asm",
    "testing.asm",
    "tasks.asm",
    "swarm.asm",
    "swarm_network.asm",
    "swarm_coordinator.asm",
    "swarm_consensus.asm",
    "work_steal.asm",
    "stream_loader.asm",
    "stream_token.asm",
    "simd_kernels.asm",
    "stress_test.asm",
    "stress_harness.asm",
    "webview2.asm",
    "ui_bridge.asm",
    "slot_ring.asm",
    "stream_bench.asm",
    "swarmlink_v2.asm",
    "swarmlink_v2_consensus.asm",
    "batch.asm",
    "rtp_tool_handlers.asm"
)

# Add core files
foreach ($file in $CoreFiles) {
    $path = Join-Path $MonolithicDir $file
    if (Test-Path $path) {
        $AsmFiles += $path
    } else {
        Write-Host "[WARN] Missing core file: $file" -ForegroundColor Yellow
    }
}

# Monolithic directory doesn't exist - skip
# All files are in src/asm directly

# Add top-level ASM files (inference, tokenizer, etc.)
$TopLevelFiles = @(
    "SovereignStandaloneEngine.asm",
    "inference_core.asm",
    "RawrXD_Tokenizer.asm",
    "kv_cache_mgr.asm",
    "RawrXD_AgenticOrchestrator.asm",
    "win32ide_main.asm",
    "agenticide_main.asm",
    "RawrXD_MonacoCore.asm",
    "RawrXD_Lexer_AVX2.asm",
    "RawrXD_SourceEdit_Kernel.asm",
    "RawrXD_VulkanBridge.asm",
    "GenesisP0_ExtensionHost.asm",
    "RawrXD_MemorySystem.asm",
    "rawr_linear_allocator.asm",
    "rawr_rbtree.asm",
    "RawrXD_PE_Writer.asm",
    "RawrXD_PE_Importer.asm",
    "RawrXD_PE_Exporter.asm",
    "RawrXD_Hotpatch_Kernel.asm",
    "RawrXD_SelfPatch_Agent.asm",
    "address_hotpatch_masm64.asm",
    "RawrXD_QuantKernels_Full.asm",
    "RawrXD_KQuant_Dequant.asm",
    "RawrXD_NanoQuant_Engine.asm",
    "quant_avx2.asm",
    "RawrXD_Camellia256_Auth.asm",
    "RawrXD_GSIHash.asm",
    "pqc_key_manager.asm",
    "SovereignMesh_PQC.asm",
    "RawrXD_Swarm_Link.asm",
    "RawrXD_MeshDiscovery.asm",
    "RawrXD_MeshBrain.asm",
    "p2p_shard_replicate.asm",
    "RawrXD_ExtensionBridge.asm",
    "RawrXD_ExtensionRuntimeBridge.asm",
    "RawrXD_Sidebar_x64.asm",
    "RawrXD_MultiWindow_Kernel.asm",
    "RawrXD_ConPTY_Renderer.asm",
    "RawrXD_TerminalPipe.asm",
    "gguf_parser.asm",
    "gguf_weight_mapping.asm",
    "model_streamer_x64.asm",
    "model_invoker.asm",
    "RawrXD_ModelMetadata_Hotpatch.asm",
    "transformer_block.asm",
    "SovereignAttention.asm",
    "SovereignForwardPass.asm",
    "SovereignFP8_Kernels.asm",
    "SovereignMatMul.asm",
    "Titan_MoE_SparseGather.asm",
    "SovereignSpeculativeEngine.asm",
    "RawrXD_DualEngine_QuantumBeacon.asm",
    "RawrXD_Streaming_QuadBuffer.asm",
    "RawrXD_StreamingWeights.asm",
    "RawrXD_Speciator.asm",
    "RawrXD_ContextBuffer.asm",
    "RawrXD_DynamicPromptEngine.asm",
    "RawrXD_JsonPlanParser.asm",
    "RawrXD_NLShell.asm",
    "RawrXD_QueryEngine.asm",
    "RawrXD_ToolEngine.asm",
    "RawrXD_AgentToolExecutor.asm",
    "RawrXD_Disasm_Kernel.asm",
    "RawrXD_PDBKernel.asm",
    "RawrXD_SymbolTable_Hash.asm",
    "RawrXD_AuditSystem_Pure.asm",
    "RawrXD_StubDetector.asm",
    "ghost_text_ranker.asm",
    "ai_completion_provider_masm.asm",
    "agentic_deep_thinking_kernels.asm",
    "FlashAttention_AVX512.asm",
    "NativeInferenceClient.asm",
    "vulkan_compute.asm",
    "genesis_masm64.asm",
    "RawrXD_UnifiedDebugger.asm"
)

foreach ($file in $TopLevelFiles) {
    $path = Join-Path $SrcDir $file
    if (Test-Path $path) {
        $AsmFiles += $path
    }
}

# Add GPU-specific files
$GpuDir = Join-Path $SrcDir "gpu"
if (Test-Path $GpuDir) {
    $GpuFiles = Get-ChildItem -Path $GpuDir -Filter "*.asm" -File
    foreach ($file in $GpuFiles) {
        $AsmFiles += $file.FullName
    }
}

Write-Host "`n[*] Assembling $($AsmFiles.Count) ASM files..." -ForegroundColor Cyan

# Assembly flags
$AsmFlags = @(
    "/c",
    "/nologo",
    "/W3",
    "/Zi",
    "/I`"$SrcDir`"",
    "/I`"$MonolithicDir`""
)

if ($Configuration -eq "Debug") {
    $AsmFlags += "/DDEBUG"
}

$ObjFiles = @()
$ErrorCount = 0

# Assemble each file
foreach ($asmFile in $AsmFiles) {
    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($asmFile)
    $objFile = Join-Path $BuildDir "$fileName.obj"
    
    if ($Verbose) {
        Write-Host "  Assembling: $fileName.asm" -ForegroundColor Gray
    }
    
    $result = & $ML64 $AsmFlags "/Fo`"$objFile`"" "`"$asmFile`"" 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        $ObjFiles += $objFile
    } else {
        Write-Host "[ERROR] Failed to assemble: $fileName.asm" -ForegroundColor Red
        Write-Host $result -ForegroundColor Red
        $ErrorCount++
    }
}

if ($ErrorCount -gt 0) {
    Write-Host "`n[FAIL] Assembly failed with $ErrorCount errors" -ForegroundColor Red
    exit 1
}

Write-Host "[OK] Assembled $($ObjFiles.Count) object files" -ForegroundColor Green

# Link
Write-Host "`n[*] Linking..." -ForegroundColor Cyan

$LinkFlags = @(
    "/SUBSYSTEM:WINDOWS",
    "/MACHINE:X64",
    "/NODEFAULTLIB",
    "/OPT:REF",
    "/OPT:ICF",
    "/LARGEADDRESSAWARE",
    "/OUT:`"$OutputExe`""
)

# Libraries
$Libs = @(
    "kernel32.lib",
    "user32.lib",
    "gdi32.lib",
    "shell32.lib",
    "ole32.lib",
    "uuid.lib",
    "advapi32.lib"
)

$LinkArgs = $ObjFiles + $LinkFlags + $Libs

if ($Verbose) {
    Write-Host "  Linking $($ObjFiles.Count) objects..." -ForegroundColor Gray
}

$result = & $LINK $LinkArgs 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] Link successful" -ForegroundColor Green
    Write-Host "`n================================================================" -ForegroundColor Cyan
    Write-Host "  Build complete: $OutputExe" -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Cyan
    
    # Show file size
    if (Test-Path $OutputExe) {
        $FileInfo = Get-Item $OutputExe
        $SizeKB = [math]::Round($FileInfo.Length / 1KB, 2)
        $SizeMB = [math]::Round($FileInfo.Length / 1MB, 2)
        Write-Host "  Size: $SizeKB KB ($SizeMB MB)" -ForegroundColor Gray
    }
} else {
    Write-Host "[FAIL] Link failed" -ForegroundColor Red
    Write-Host $result -ForegroundColor Red
    exit 1
}