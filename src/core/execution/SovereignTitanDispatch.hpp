//==============================================================================
// SovereignTitanDispatch.hpp
// Titan GPU Execution Layer - Dispatch Interface
// 
// Provides unified kernel dispatch with automatic CPU/GPU path selection.
// Bridges Sovereign kernel IDs to Titan GPU descriptors or CPU MASM fallbacks.
//
// Date: July 10, 2026
// Phase: 7B.5 - Titan Integration
//==============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

namespace sovereign {

//==============================================================================
// Forward Declarations
//==============================================================================
struct TensorDesc;
struct KernelParams;

//==============================================================================
// Titan GPU Context
// Wraps Titan-specific state for GPU execution
//==============================================================================
struct TitanGpuContext {
    uint32_t deviceId{0};           // GPU device index
    uint32_t streamId{0};           // Async stream handle
    void*    stagingBuffer{nullptr}; // Host-visible staging memory
    size_t   stagingSize{0};         // Staging buffer size in bytes
    
    // Validation
    bool IsValid() const {
        return stagingBuffer != nullptr && stagingSize > 0;
    }
};

//==============================================================================
// Dispatch Path Selection
//==============================================================================
enum class DispatchPath {
    CPU_MASM,       // Pure CPU via MASM64 kernels
    GPU_TITAN,      // GPU via Titan execution layer
    AUTO_SELECT     // Automatic based on tensor size, device availability
};

//==============================================================================
// Kernel Identifiers
// Extensible registry of dispatchable kernels
//==============================================================================
enum class KernelId : uint32_t {
    // MatMul variants
    MatMul_Q4_Q8 = 0,
    MatMul_F32,
    MatMul_F16,
    
    // Attention variants
    FlashAttentionV2,
    FlashAttentionV1,
    StandardAttention,
    
    // Normalization
    RMSNorm,
    LayerNorm,
    
    // Embeddings
    RoPE,           // Rotary Position Embedding
    TokenEmbedding,
    
    // Activations
    SiLU,
    GELU,
    Softmax,
    
    // Quantization
    Quantize_Q4_0,
    Quantize_Q8_0,
    Dequantize_Q4,
    Dequantize_Q8,
    
    // Memory
    CopyAligned,
    CopyStreaming,
    
    // Unknown/Invalid
    Unknown = 0xFFFFFFFF
};

//==============================================================================
// Dispatch Result
//==============================================================================
struct DispatchResult {
    bool success{false};
    DispatchPath pathUsed{DispatchPath::CPU_MASM};
    uint64_t executionTimeUs{0};
    uint32_t errorCode{0};
    
    operator bool() const { return success; }
};

//==============================================================================
// Core Dispatch API
//==============================================================================

// Generic kernel dispatch with automatic path selection
DispatchResult DispatchKernel(
    KernelId id,
    const TensorDesc& input,
    const TensorDesc& output,
    const KernelParams& params,
    DispatchPath path = DispatchPath::AUTO_SELECT,
    const TitanGpuContext* gpuCtx = nullptr
);

// Specific kernel dispatches with typed parameters

// MatMul: Q4 weights × Q8 activations → F32 output
DispatchResult DispatchMatMul_Q4_Q8(
    const TensorDesc& weights,      // Q4 quantized weights
    const TensorDesc& activations, // Q8 quantized activations
    TensorDesc& output,             // F32 output
    const TitanGpuContext* gpu = nullptr
);

// FlashAttentionV2: Optimized attention for long sequences
DispatchResult DispatchFlashAttentionV2(
    const TensorDesc& query,        // [batch, heads, seq, head_dim]
    const TensorDesc& key,          // [batch, heads, seq, head_dim]
    const TensorDesc& value,        // [batch, heads, seq, head_dim]
    TensorDesc& output,             // [batch, heads, seq, head_dim]
    const TensorDesc* mask,         // Optional attention mask
    float scale,                    // Attention scale (1/sqrt(head_dim))
    const TitanGpuContext* gpu = nullptr
);

// RMSNorm: Root Mean Square Layer Normalization
DispatchResult DispatchRMSNorm(
    const TensorDesc& input,
    const TensorDesc& weight,       // Learned gamma
    TensorDesc& output,
    float epsilon,                  // Small constant for numerical stability
    const TitanGpuContext* gpu = nullptr
);

// RoPE: Rotary Position Embedding
DispatchResult DispatchRoPE(
    const TensorDesc& input,        // [batch, seq, heads, head_dim]
    TensorDesc& output,
    const float* cosTable,          // Precomputed cos values
    const float* sinTable,          // Precomputed sin values
    uint32_t seqLen,
    uint32_t headDim,
    const TitanGpuContext* gpu = nullptr
);

// SiLU: Sigmoid Linear Unit activation
DispatchResult DispatchSiLU(
    const TensorDesc& input,
    TensorDesc& output,
    const TitanGpuContext* gpu = nullptr
);

// Softmax: Numerically stable softmax
DispatchResult DispatchSoftmax(
    const TensorDesc& input,        // [..., features]
    TensorDesc& output,
    int32_t axis = -1,              // Feature axis
    const TitanGpuContext* gpu = nullptr
);

// Memory copy with automatic path selection
DispatchResult DispatchCopy(
    const TensorDesc& source,
    TensorDesc& dest,
    size_t sizeBytes,
    const TitanGpuContext* gpu = nullptr
);

//==============================================================================
// Utility Functions
//==============================================================================

// Check if GPU path is available for a given kernel
bool IsGpuPathAvailable(KernelId id);

// Get recommended dispatch path based on tensor characteristics
DispatchPath RecommendDispatchPath(
    KernelId id,
    size_t tensorSizeBytes,
    const TitanGpuContext* gpuCtx
);

// Estimate execution time for path selection (heuristic)
uint64_t EstimateExecutionTimeUs(KernelId id, size_t tensorSizeBytes, DispatchPath path);

} // namespace sovereign
