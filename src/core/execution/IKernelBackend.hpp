//==============================================================================
// IKernelBackend.hpp
// Unified Kernel Interface - Abstract Base for All Backends
//
// All kernel implementations (Reference, Intrinsics, MASM, Vulkan) implement
// this interface. The KernelRegistry selects the best backend at runtime.
//
// Date: July 10, 2026
// Phase: 7C.1 - Kernel Registry Architecture
//==============================================================================

#pragma once

#include "SovereignKernelTypes.hpp"
#include <cstdint>
#include <string>

namespace sovereign {

//==============================================================================
// Backend Capability Flags
//==============================================================================
enum class BackendCapability : uint32_t {
    NONE          = 0,
    REFERENCE     = 1 << 0,   // CPU reference implementation
    INTRINSICS    = 1 << 1,   // SIMD intrinsics (AVX2/AVX-512)
    MASM          = 1 << 2,   // Assembly implementation
    GPU_CUDA      = 1 << 3,   // NVIDIA CUDA
    GPU_VULKAN    = 1 << 4,   // Vulkan compute
    GPU_ROCM      = 1 << 5,   // AMD ROCm/HIP
    QUANTIZED     = 1 << 6,   // Supports quantized types
    ASYNC         = 1 << 7,   // Supports async execution
    DMA           = 1 << 8,   // Supports DMA transfers
};

inline BackendCapability operator|(BackendCapability a, BackendCapability b) {
    return static_cast<BackendCapability>(
        static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline bool HasCapability(BackendCapability flags, BackendCapability cap) {
    return (static_cast<uint32_t>(flags) & static_cast<uint32_t>(cap)) != 0;
}

//==============================================================================
// Backend Information
//==============================================================================
struct BackendInfo {
    std::string name;
    std::string version;
    BackendCapability capabilities;
    uint32_t maxThreads{0};
    size_t maxBufferSize{0};
    
    bool IsValid() const { return !name.empty(); }
};

//==============================================================================
// Execution Statistics
//==============================================================================
struct ExecutionStats {
    uint64_t executionTimeUs{0};
    uint64_t setupTimeUs{0};
    uint64_t totalTimeUs{0};
    double gflops{0.0};
    double throughputGBs{0.0};
    uint32_t backendId{0};
};

//==============================================================================
// Unified Kernel Backend Interface
//
// All backends (Reference, Intrinsics, MASM, Vulkan) implement this.
// The KernelRegistry selects the best backend based on:
// - Available hardware capabilities
// - Kernel size
// - Precision requirements
// - Performance history
//==============================================================================
class IKernelBackend {
public:
    virtual ~IKernelBackend() = default;
    
    // Backend identification
    virtual BackendInfo GetInfo() const = 0;
    
    // Initialization
    virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;
    virtual bool IsInitialized() const = 0;
    
    // Capabilities
    virtual bool SupportsKernel(KernelId id) const = 0;
    virtual bool SupportsDataType(TensorDesc::DataType dtype) const = 0;
    
    //======================================================================
    // Core Kernel Operations
    //======================================================================
    
    // Matrix Multiplication: C = A × B
    // Supports Q4_0, Q8_0, F32, F16 quantized types
    virtual bool MatMul(
        const TensorDesc& A,
        const TensorDesc& B,
        TensorDesc& C,
        const MatMulParams& params,
        ExecutionStats* stats = nullptr
    ) = 0;
    
    // Flash Attention V2
    // output = Softmax(Q × K^T / sqrt(d_k)) × V
    virtual bool FlashAttention(
        const TensorDesc& Q,
        const TensorDesc& K,
        const TensorDesc& V,
        TensorDesc& output,
        const AttentionParams& params,
        ExecutionStats* stats = nullptr
    ) = 0;
    
    // RMS Normalization
    // output = input / RMS(input) × weight
    virtual bool RMSNorm(
        const TensorDesc& input,
        const TensorDesc& weight,
        TensorDesc& output,
        float epsilon,
        ExecutionStats* stats = nullptr
    ) = 0;
    
    // Layer Normalization
    // output = (input - mean) / sqrt(var + epsilon) × weight + bias
    virtual bool LayerNorm(
        const TensorDesc& input,
        const TensorDesc& weight,
        const TensorDesc& bias,
        TensorDesc& output,
        float epsilon,
        ExecutionStats* stats = nullptr
    ) = 0;
    
    // Rotary Position Embedding (RoPE)
    // Applies rotary embeddings to Q/K tensors
    virtual bool RoPE(
        const TensorDesc& input,
        TensorDesc& output,
        const float* cosTable,
        const float* sinTable,
        uint32_t seqLen,
        uint32_t headDim,
        ExecutionStats* stats = nullptr
    ) = 0;
    
    // SiLU Activation
    // output = input × sigmoid(input)
    virtual bool SiLU(
        const TensorDesc& input,
        TensorDesc& output,
        ExecutionStats* stats = nullptr
    ) = 0;
    
    // Softmax
    // output = exp(input - max) / sum(exp(input - max))
    virtual bool Softmax(
        const TensorDesc& input,
        TensorDesc& output,
        int32_t axis = -1,
        ExecutionStats* stats = nullptr
    ) = 0;
    
    // Residual Add
    // output = input + residual
    virtual bool ResidualAdd(
        const TensorDesc& input,
        const TensorDesc& residual,
        TensorDesc& output,
        ExecutionStats* stats = nullptr
    ) = 0;
    
    // Quantization
    virtual bool Quantize(
        const TensorDesc& input,
        TensorDesc& output,
        const QuantParams& params,
        ExecutionStats* stats = nullptr
    ) = 0;
    
    // Dequantization
    virtual bool Dequantize(
        const TensorDesc& input,
        TensorDesc& output,
        const QuantParams& params,
        ExecutionStats* stats = nullptr
    ) = 0;
    
    // Memory copy (potentially async with DMA)
    virtual bool Copy(
        const TensorDesc& source,
        TensorDesc& dest,
        size_t sizeBytes,
        ExecutionStats* stats = nullptr
    ) = 0;
    
    // Synchronization (for async backends)
    virtual bool Synchronize() = 0;
};

//==============================================================================
// Backend Factory Functions
//==============================================================================
IKernelBackend* CreateReferenceBackend();
IKernelBackend* CreateIntrinsicsBackend();

} // namespace sovereign
