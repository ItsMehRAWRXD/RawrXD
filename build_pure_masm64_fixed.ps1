# RawrXD Pure MASM64 Build Script - Fixed
# Zero C++ dependencies - Pure assembly build
# Assembles all ASM files and links into RawrXD_IDE.exe

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

# Entry point files (must be first for linker)
$EntryPoints = @(
    "win32ide_main.asm",
    "agenticide_main.asm",
    "genesis_masm64.asm"
)

# Core inference engine files
$CoreInference = @(
    "SovereignStandaloneEngine.asm",
    "inference_core.asm",
    "RawrXD_Tokenizer.asm",
    "kv_cache_mgr.asm",
    "FlashAttention_AVX512.asm",
    "NativeInferenceClient.asm",
    "SovereignAttention.asm",
    "SovereignForwardPass.asm",
    "SovereignMatMul.asm",
    "SovereignFP8_Kernels.asm",
    "SovereignKernels.asm",
    "transformer_block.asm",
    "Titan_MoE_SparseGather.asm"
)

# Agentic system files
$AgenticFiles = @(
    "RawrXD_AgenticOrchestrator.asm",
    "agentic_deep_thinking_kernels.asm",
    "ai_agent_masm_core.asm",
    "ai_completion_provider_masm.asm",
    "ghost_text_ranker.asm",
    "goal_stack.asm"
)

# Memory and data structures
$MemoryFiles = @(
    "RawrXD_MemorySystem.asm",
    "rawr_linear_allocator.asm",
    "rawr_rbtree.asm",
    "RawrXD_ContextBuffer.asm",
    "RawrXD_Streaming_QuadBuffer.asm"
)

# Model loading
$ModelFiles = @(
    "gguf_parser.asm",
    "gguf_weight_mapping.asm",
    "model_streamer_x64.asm",
    "model_invoker.asm",
    "RawrXD_ModelMetadata_Hotpatch.asm"
)

# Quantization
$QuantFiles = @(
    "RawrXD_QuantKernels_Full.asm",
    "RawrXD_KQuant_Dequant.asm",
    "RawrXD_NanoQuant_Engine.asm",
    "quant_avx2.asm",
    "dequant_simd.asm"
)

# Vulkan/GPU
$GpuFiles = @(
    "vulkan_compute.asm",
    "RawrXD_VulkanBridge.asm",
    "VulkanKernel_DispatchRaw.asm"
)

# Security/Crypto
$SecurityFiles = @(
    "RawrXD_Camellia256_Auth.asm",
    "RawrXD_GSIHash.asm",
    "pqc_key_manager.asm",
    "SovereignMesh_PQC.asm",
    "identity_gate.asm"
)

# Distributed/Mesh
$MeshFiles = @(
    "RawrXD_Swarm_Link.asm",
    "RawrXD_MeshDiscovery.asm",
    "RawrXD_MeshBrain.asm",
    "p2p_shard_replicate.asm",
    "swarm_lb_hotpath.asm",
    "swarm_tensor_stream.asm"
)

# Extension system
$ExtensionFiles = @(
    "GenesisP0_ExtensionHost.asm",
    "RawrXD_ExtensionBridge.asm",
    "RawrXD_ExtensionRuntimeBridge.asm"
)

# UI components
$UIFiles = @(
    "RawrXD_MonacoCore.asm",
    "RawrXD_Lexer_AVX2.asm",
    "RawrXD_SourceEdit_Kernel.asm",
    "RawrXD_Sidebar_x64.asm",
    "RawrXD_MultiWindow_Kernel.asm",
    "RawrXD_ConPTY_Renderer.asm",
    "RawrXD_TerminalPipe.asm"
)

# PE/Self-hosting
$PEFiles = @(
    "RawrXD_PE_Writer.asm",
    "RawrXD_PE_Importer.asm",
    "RawrXD_PE_Exporter.asm",
    "RawrXD_Hotpatch_Kernel.asm",
    "RawrXD_SelfPatch_Agent.asm",
    "address_hotpatch_masm64.asm"
)

# Tooling
$ToolFiles = @(
    "RawrXD_ToolEngine.asm",
    "RawrXD_AgentToolExecutor.asm",
    "RawrXD_Disasm_Kernel.asm",
    "RawrXD_PDBKernel.asm",
    "RawrXD_SymbolTable_Hash.asm",
    "RawrXD_AuditSystem_Pure.asm"
)

# LSP/DAP
$LSPFiles = @(
    "lsp_jsonrpc.asm",
    "RawrXD_LSP_SymbolIndex.asm"
)

# Collect all files in order
$AllFiles = @()
$AllFiles += $EntryPoints
$AllFiles += $CoreInference
$AllFiles += $AgenticFiles
$AllFiles += $MemoryFiles
$AllFiles += $ModelFiles
$AllFiles += $QuantFiles
$AllFiles += $GpuFiles
$AllFiles += $SecurityFiles
$AllFiles += $MeshFiles
$AllFiles += $ExtensionFiles
$AllFiles += $UIFiles
$AllFiles += $PEFiles
$AllFiles += $ToolFiles
$AllFiles += $LSPFiles

# Resolve full paths and filter existing
$AsmFiles = @()
foreach ($file in $AllFiles) {
    $path = Join-Path $SrcDir $file
    if (Test-Path $path) {
        $AsmFiles += $path
    } else {
        Write-Host "[WARN] Missing: $file" -ForegroundColor Yellow
    }
}

# Add remaining ASM files not in explicit list
$AllAsmInDir = Get-ChildItem -Path $SrcDir -Filter "*.asm" -File
foreach ($file in $AllAsmInDir) {
    if ($AsmFiles -notcontains $file.FullName) {
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
    "/I`"$SrcDir`""
)

if ($Configuration -eq "Debug") {
    $AsmFlags += "/DDEBUG"
}

$ObjFiles = @()
$ErrorCount = 0
$WarningCount = 0

# Assemble each file
foreach ($asmFile in $AsmFiles) {
    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($asmFile)
    $objFile = Join-Path $BuildDir "$fileName.obj"
    
    if ($Verbose) {
        Write-Host "  Assembling: $fileName.asm" -ForegroundColor Gray
    }
    
    # Build argument array for ml64
    $ml64Args = @("/c", "/nologo", "/W3", "/Zi")
    $ml64Args += "/I$SrcDir"
    if ($Configuration -eq "Debug") {
        $ml64Args += "/DDEBUG"
    }
    $ml64Args += "/Fo$objFile"
    $ml64Args += $asmFile
    
    $result = & $ML64 @ml64Args 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        $ObjFiles += $objFile
    } else {
        Write-Host "[ERROR] Failed to assemble: $fileName.asm" -ForegroundColor Red
        Write-Host $result -ForegroundColor Red
        $ErrorCount++
        if ($ErrorCount -ge 10) {
            Write-Host "[FATAL] Too many errors, aborting" -ForegroundColor Red
            exit 1
        }
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
    
    exit 0
} else {
    Write-Host "[FAIL] Link failed" -ForegroundColor Red
    Write-Host $result -ForegroundColor Red
    exit 1
}