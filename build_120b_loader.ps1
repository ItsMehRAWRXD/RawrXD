#!/usr/bin/env pwsh
# =============================================================================
# build_120b_loader.ps1
# Build script for RawrXD 120B Loader (Phase 11)
# Assembles MASM x64 and creates static library
# =============================================================================

param(
    [switch]$Clean,
    [switch]$Test,
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

# Configuration
$VS_PATH = "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231"
$MASM_PATH = "$VS_PATH\bin\Hostx64\x64\ml64.exe"
$LIB_PATH = "$VS_PATH\bin\Hostx64\x64\lib.exe"
$CL_PATH = "$VS_PATH\bin\Hostx64\x64\cl.exe"

$SRC_DIR = "d:\RawrXD\asm"
$OUTPUT_DIR = "d:\RawrXD\build\120b_loader"

Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  RawrXD 120B Loader Build (Phase 11)                           ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Clean if requested
if ($Clean -and (Test-Path $OUTPUT_DIR)) {
    Remove-Item -Recurse -Force $OUTPUT_DIR
}

New-Item -ItemType Directory -Force -Path $OUTPUT_DIR | Out-Null

# Check prerequisites
if (-not (Test-Path $MASM_PATH)) {
    Write-Host "ERROR: MASM not found at $MASM_PATH" -ForegroundColor Red
    exit 1
}

Write-Host "Building 120B Loader..." -ForegroundColor Yellow
Write-Host ""

# Assemble the loader
Write-Host "Assembling RawrXD_120B_Loader.asm..." -NoNewline

$asmFile = "$SRC_DIR\RawrXD_120B_Loader.asm"
$objFile = "$OUTPUT_DIR\RawrXD_120B_Loader.obj"

$args = @(
    "-c",                    # Assemble only
    "-nologo",               # Quiet mode
    "-Fo`"$objFile`"",       # Output object
    "-W3",                   # Warning level 3
    "-DWIN64",               # Windows 64-bit
    "-I`"$SRC_DIR`"",        # Include path
    "`"$asmFile`""
)

$proc = Start-Process -FilePath $MASM_PATH -ArgumentList $args `
    -PassThru -Wait -NoNewWindow `
    -RedirectStandardOutput "$OUTPUT_DIR\asm.log" `
    -RedirectStandardError "$OUTPUT_DIR\asm.err"

if ($proc.ExitCode -ne 0) {
    Write-Host " FAILED" -ForegroundColor Red
    Get-Content "$OUTPUT_DIR\asm.err" | Write-Host -ForegroundColor Red
    exit 1
}

Write-Host " OK" -ForegroundColor Green

# Create static library
Write-Host "Creating static library..." -NoNewline

$libFile = "$OUTPUT_DIR\RawrXD_120B_Loader.lib"

$libArgs = @(
    "/OUT:`"$libFile`"",
    "/MACHINE:X64",
    "/NOLOGO",
    "`"$objFile`""
)

$proc = Start-Process -FilePath $LIB_PATH -ArgumentList $libArgs `
    -PassThru -Wait -NoNewWindow

if ($proc.ExitCode -ne 0) {
    Write-Host " FAILED" -ForegroundColor Red
    exit 1
}

Write-Host " OK" -ForegroundColor Green

# Generate header file for C++ integration
Write-Host "Generating C++ header..." -NoNewline

$headerContent = @"
// ============================================================================
// RawrXD_120B_Loader.h — C++ Interface for Assembly Loader
// Phase 11: 120B Universal Quantization Hot-Patcher
// ============================================================================

#ifndef RAWRXD_120B_LOADER_H
#define RAWRXD_120B_LOADER_H

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

// Model handle (opaque pointer to MODEL_HANDLE_SIZE bytes)
typedef void* RawrXD_ModelHandle;

// Quantization types
enum RawrXD_QuantType {
    RAWRXD_Q8_0 = 8,   // Critical zones (embed/output): ~1% loss
    RAWRXD_Q4_K = 12,  // Middle layers: ~3% loss
    RAWRXD_Q2_K = 10,  // Tail layers: ~8% loss
};

// Quantization zones
enum RawrXD_QuantZone {
    RAWRXD_QZONE_CRITICAL = 0,  // Embedding + output head
    RAWRXD_QZONE_MIDDLE   = 1,  // Middle transformer blocks
    RAWRXD_QZONE_TAIL     = 2,  // Late attention layers
};

// API Functions (implemented in assembly)

// Load a GGUF model file via memory mapping
// Returns: Model handle or nullptr on failure
RawrXD_ModelHandle RawrXD_LoadModel(const char* filePath);

// Unload model and free all resources
void RawrXD_UnloadModel(RawrXD_ModelHandle handle);

// Get pointer to layer tensor data (on-demand from mapped file)
// Returns: Pointer to layer data or nullptr
void* RawrXD_GetLayer(RawrXD_ModelHandle handle, uint32_t layerIndex);

// Quantize a float32 tensor to target format
// Returns: Bytes written to destination
uint32_t RawrXD_Quantize(
    const float* src,
    void* dst,
    uint32_t nElements,
    RawrXD_QuantType quantType
);

// Initialize sliding window KV cache
// Returns: 1 on success, 0 on failure
int RawrXD_KVCache_Init(RawrXD_ModelHandle handle);

// Insert K/V pair at position (modular indexing)
void RawrXD_KVCache_Update(
    RawrXD_ModelHandle handle,
    uint32_t position,
    const float* kVector,  // 64 floats (SVD compressed)
    const float* vVector   // 64 floats (SVD compressed)
);

// Evict/reset entire KV cache
void RawrXD_KVCache_Evict(RawrXD_ModelHandle handle);

// Helper: Get quantization type for layer index
inline RawrXD_QuantType RawrXD_GetQuantTypeForLayer(uint32_t layerIdx, uint32_t totalLayers) {
    if (layerIdx == 0 || layerIdx == totalLayers - 1) {
        return RAWRXD_Q8_0;  // Critical: embedding + output
    } else if (layerIdx < totalLayers * 2 / 3) {
        return RAWRXD_Q4_K;  // Middle layers
    } else {
        return RAWRXD_Q2_K;  // Tail layers
    }
}

// Constants
constexpr uint32_t RAWRXD_KV_WINDOW_SIZE = 512;
constexpr uint32_t RAWRXD_KV_DIM_COMPRESSED = 64;
constexpr uint32_t RAWRXD_MAX_LAYERS = 120;

#ifdef __cplusplus
}
#endif

#endif // RAWRXD_120B_LOADER_H
"@

$headerContent | Out-File -FilePath "$OUTPUT_DIR\RawrXD_120B_Loader.h" -Encoding UTF8
Write-Host " OK" -ForegroundColor Green

# Summary
Write-Host ""
Write-Host "Build Summary:" -ForegroundColor Cyan
Write-Host "  Object: $objFile ($(Get-Item $objFile).Length bytes)"
Write-Host "  Library: $libFile ($(Get-Item $libFile).Length bytes)"
Write-Host "  Header: $OUTPUT_DIR\RawrXD_120B_Loader.h"
Write-Host ""

# Run test if requested
if ($Test) {
    Write-Host "Running integration test..." -ForegroundColor Yellow
    Write-Host ""
    
    # Create simple test
    $testCode = @"
#include <iostream>
#include <cstring>
#include "RawrXD_120B_Loader.h"

int main() {
    std::cout << "RawrXD 120B Loader Test" << std::endl;
    std::cout << "=======================" << std::endl << std::endl;
    
    // Test quantization type selection
    std::cout << "Quantization Strategy:" << std::endl;
    std::cout << "  Layer 0 (embed):     Q" << (int)RawrXD_GetQuantTypeForLayer(0, 120) << std::endl;
    std::cout << "  Layer 40 (middle):   Q" << (int)RawrXD_GetQuantTypeForLayer(40, 120) << std::endl;
    std::cout << "  Layer 100 (tail):    Q" << (int)RawrXD_GetQuantTypeForLayer(100, 120) << std::endl;
    std::cout << "  Layer 119 (output):  Q" << (int)RawrXD_GetQuantTypeForLayer(119, 120) << std::endl;
    std::cout << std::endl;
    
    std::cout << "Constants:" << std::endl;
    std::cout << "  KV Window: " << RAWRXD_KV_WINDOW_SIZE << " tokens" << std::endl;
    std::cout << "  KV Compressed: " << RAWRXD_KV_DIM_COMPRESSED << " dims" << std::endl;
    std::cout << "  Max Layers: " << RAWRXD_MAX_LAYERS << std::endl;
    std::cout << std::endl;
    
    std::cout << "✓ Header integration successful" << std::endl;
    return 0;
}
"@
    
    $testFile = "$OUTPUT_DIR\test_loader.cpp"
    $testCode | Out-File -FilePath $testFile -Encoding UTF8
    
    # Compile test
    $exeFile = "$OUTPUT_DIR\test_loader.exe"
    
    $clArgs = @(
        "/EHsc",
        "/nologo",
        "/Fe:`"$exeFile`"",
        "/I`"$OUTPUT_DIR`"",
        "`"$testFile`"",
        "`"$libFile`""
    )
    
    $proc = Start-Process -FilePath $CL_PATH -ArgumentList $clArgs `
        -PassThru -Wait -NoNewWindow
    
    if ($proc.ExitCode -eq 0 -and (Test-Path $exeFile)) {
        & $exeFile
    } else {
        Write-Host "Test compilation failed" -ForegroundColor Yellow
    }
}

Write-Host "Build complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Usage:" -ForegroundColor Yellow
Write-Host "  # Link against the library"
Write-Host "  cl your_app.cpp /link RawrXD_120B_Loader.lib"
Write-Host ""
Write-Host "  # Or include the header"
Write-Host "  #include <RawrXD_120B_Loader.h>"
