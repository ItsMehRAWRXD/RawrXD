//==============================================================================
// SovereignTitanDispatch.cpp
// Titan GPU Execution Layer - Implementation
//
// Bridges Sovereign kernel dispatch to Titan GPU execution fabric.
// Falls back to CPU MASM kernels when GPU unavailable.
//
// Date: July 10, 2026
// Phase: 7B.5 - Titan Integration
//==============================================================================

#include "SovereignTitanDispatch.hpp"
#include "SovereignKernelTypes.hpp"
#include <cstring>
#include <algorithm>

// Titan descriptor structures from Compute_Kernel_DMA_Complete.asm
extern "C" {

#pragma pack(push, 8)

struct GPU_KERNEL_DESCRIPTOR {
    uint64_t kernelName;
    uint32_t gridDimX;
    uint32_t gridDimY;
    uint32_t gridDimZ;
    uint32_t blockDimX;
    uint32_t blockDimY;
    uint32_t blockDimZ;
    uint32_t sharedMemSize;
    uint64_t stream;
    uint64_t inputBuffer;
    uint64_t inputSize;
    uint64_t outputBuffer;
    uint64_t outputSize;
    uint32_t paramCount;
    uint64_t paramData;
    uint32_t launchStatus;
    uint64_t executionTimeUs;
};

struct GPU_COPY_OPERATION {
    uint32_t operationType;
    uint64_t sourceBuffer;
    uint64_t destBuffer;
    uint64_t transferSize;
    uint64_t startTimeUs;
    uint64_t endTimeUs;
    uint32_t throughputMBps;
    uint32_t status;
    uint32_t errorCode;
    uint64_t callbackFunc;
    uint64_t callbackData;
    uint64_t pinnedMemoryId;
    uint64_t stagingBufferId;
};

#pragma pack(pop)

// Titan exports from Compute_Kernel_DMA_Complete.asm
int Titan_ExecuteComputeKernel(GPU_KERNEL_DESCRIPTOR* desc, void* result, size_t resultSize);
int Titan_PerformCopy(GPU_COPY_OPERATION* op, uint32_t flags);
uint64_t Titan_GetMicroseconds_Local();

} // extern "C"

namespace sovereign {

//==============================================================================
// Internal: CPU MASM Fallback Declarations
// These would link to your existing Sovereign_Legacy_Kernels
//==============================================================================
extern "C" {
    int Cpu_MatMul_Q4_Q8(const void* weights, const void* activations, void* output, size_t m, size_t n, size_t k);
    int Cpu_FlashAttentionV2(const void* q, const void* k, const void* v, void* out, uint32_t seqLen, uint32_t headDim);
    int Cpu_RMSNorm(const void* input, const void* weight, void* output, size_t n, float epsilon);
    int Cpu_RoPE(void* data, const float* cosTable, const float* sinTable, uint32_t seqLen, uint32_t headDim);
    int Cpu_SiLU(const void* input, void* output, size_t n);
    int Cpu_Softmax(const void* input, void* output, size_t batch, size_t features);
}

//==============================================================================
// Internal: Kernel Name Mapping
//==============================================================================
static const char* GetKernelName(KernelId id) {
    switch (id) {
        case KernelId::MatMul_Q4_Q8:      return "MatMul_Q4_Q8";
        case KernelId::MatMul_F32:        return "MatMul_F32";
        case KernelId::MatMul_F16:        return "MatMul_F16";
        case KernelId::FlashAttentionV2:  return "FlashAttentionV2";
        case KernelId::FlashAttentionV1:  return "FlashAttentionV1";
        case KernelId::StandardAttention: return "StandardAttention";
        case KernelId::RMSNorm:           return "RMSNorm";
        case KernelId::LayerNorm:         return "LayerNorm";
        case KernelId::RoPE:              return "RoPE";
        case KernelId::TokenEmbedding:    return "TokenEmbedding";
        case KernelId::SiLU:              return "SiLU";
        case KernelId::GELU:              return "GELU";
        case KernelId::Softmax:           return "Softmax";
        case KernelId::Quantize_Q4_0:     return "Quantize_Q4_0";
        case KernelId::Quantize_Q8_0:     return "Quantize_Q8_0";
        case KernelId::Dequantize_Q4:     return "Dequantize_Q4";
        case KernelId::Dequantize_Q8:     return "Dequantize_Q8";
        case KernelId::CopyAligned:       return "CopyAligned";
        case KernelId::CopyStreaming:     return "CopyStreaming";
        default:                          return "Unknown";
    }
}

//==============================================================================
// Internal: GPU Path Availability
//==============================================================================
static bool GpuPathAvailable(KernelId id) {
    // Titan supports these kernels
    switch (id) {
        case KernelId::MatMul_Q4_Q8:
        case KernelId::FlashAttentionV2:
        case KernelId::RMSNorm:
        case KernelId::RoPE:
        case KernelId::SiLU:
        case KernelId::Softmax:
        case KernelId::CopyAligned:
        case KernelId::CopyStreaming:
            return true;
        default:
            return false;
    }
}

//==============================================================================
// Public API: Path Selection
//==============================================================================
bool IsGpuPathAvailable(KernelId id) {
    return GpuPathAvailable(id);
}

DispatchPath RecommendDispatchPath(KernelId id, size_t tensorSizeBytes, const TitanGpuContext* gpuCtx) {
    // No GPU context = CPU only
    if (!gpuCtx || !gpuCtx->IsValid()) {
        return DispatchPath::CPU_MASM;
    }
    
    // Kernel not supported on GPU = CPU
    if (!GpuPathAvailable(id)) {
        return DispatchPath::CPU_MASM;
    }
    
    // Small tensors: CPU is often faster (avoid GPU overhead)
    if (tensorSizeBytes < 64 * 1024) {  // < 64KB
        return DispatchPath::CPU_MASM;
    }
    
    // Medium tensors: GPU starts winning
    if (tensorSizeBytes < 4 * 1024 * 1024) {  // < 4MB
        // Could go either way - use GPU for compute-heavy kernels
        switch (id) {
            case KernelId::FlashAttentionV2:
            case KernelId::MatMul_Q4_Q8:
                return DispatchPath::GPU_TITAN;
            default:
                return DispatchPath::CPU_MASM;
        }
    }
    
    // Large tensors: GPU definitely wins
    return DispatchPath::GPU_TITAN;
}

uint64_t EstimateExecutionTimeUs(KernelId id, size_t tensorSizeBytes, DispatchPath path) {
    // Heuristic estimates for path selection
    // These would be calibrated with actual benchmarks
    
    if (path == DispatchPath::CPU_MASM) {
        // Rough estimate: 1-10 GB/s depending on kernel
        uint64_t throughputMBps = 5000;  // Conservative
        switch (id) {
            case KernelId::FlashAttentionV2: throughputMBps = 2000; break;
            case KernelId::MatMul_Q4_Q8:     throughputMBps = 8000; break;
            default:                         throughputMBps = 5000; break;
        }
        return (tensorSizeBytes / 1024) / throughputMBps;  // microseconds
    } else {
        // GPU estimates
        uint64_t throughputMBps = 50000;  // 50 GB/s for GPU
        switch (id) {
            case KernelId::FlashAttentionV2: throughputMBps = 30000; break;
            case KernelId::MatMul_Q4_Q8:     throughputMBps = 80000; break;
            default:                         throughputMBps = 50000; break;
        }
        // Add GPU launch overhead (~50us)
        return 50 + (tensorSizeBytes / 1024) / throughputMBps;
    }
}

//==============================================================================
// Public API: Generic Dispatch
//==============================================================================
DispatchResult DispatchKernel(
    KernelId id,
    const TensorDesc& input,
    const TensorDesc& output,
    const KernelParams& params,
    DispatchPath path,
    const TitanGpuContext* gpuCtx)
{
    DispatchResult result{};
    
    // Auto-select path if requested
    if (path == DispatchPath::AUTO_SELECT) {
        path = RecommendDispatchPath(id, input.sizeBytes, gpuCtx);
    }
    
    result.pathUsed = path;
    
    // Route to appropriate implementation
    if (path == DispatchPath::GPU_TITAN && gpuCtx && GpuPathAvailable(id)) {
        // Build Titan descriptor
        GPU_KERNEL_DESCRIPTOR titanDesc{};
        titanDesc.kernelName = reinterpret_cast<uint64_t>(GetKernelName(id));
        
        // Calculate grid dimensions based on tensor size
        // Default: 256 threads per block
        titanDesc.blockDimX = 256;
        titanDesc.blockDimY = 1;
        titanDesc.blockDimZ = 1;
        
        // Grid covers all elements
        uint32_t totalElements = static_cast<uint32_t>(input.sizeBytes / sizeof(float));
        titanDesc.gridDimX = (totalElements + 255) / 256;
        titanDesc.gridDimY = 1;
        titanDesc.gridDimZ = 1;
        
        // Buffers
        titanDesc.inputBuffer = reinterpret_cast<uint64_t>(input.data);
        titanDesc.inputSize = input.sizeBytes;
        titanDesc.outputBuffer = reinterpret_cast<uint64_t>(output.data);
        titanDesc.outputSize = output.sizeBytes;
        
        // Execute via Titan
        uint64_t startTime = Titan_GetMicroseconds_Local();
        int status = Titan_ExecuteComputeKernel(&titanDesc, output.data, output.sizeBytes);
        uint64_t endTime = Titan_GetMicroseconds_Local();
        
        result.success = (status == 0);
        result.executionTimeUs = endTime - startTime;
        result.errorCode = status;
        
    } else {
        // CPU fallback - would dispatch to Cpu_* functions
        // For now, mark as not implemented
        result.success = false;
        result.errorCode = 1;  // Not implemented
    }
    
    return result;
}

//==============================================================================
// Public API: Specific Kernel Dispatches
//==============================================================================

DispatchResult DispatchMatMul_Q4_Q8(
    const TensorDesc& weights,
    const TensorDesc& activations,
    TensorDesc& output,
    const TitanGpuContext* gpu)
{
    DispatchPath path = RecommendDispatchPath(KernelId::MatMul_Q4_Q8, 
                                               weights.sizeBytes + activations.sizeBytes, gpu);
    
    if (path == DispatchPath::GPU_TITAN && gpu) {
        // Titan GPU path
        GPU_KERNEL_DESCRIPTOR desc{};
        desc.kernelName = reinterpret_cast<uint64_t>("MatMul_Q4_Q8");
        
        // MatMul-specific grid: one block per output tile
        // Assuming M×K @ K×N = M×N
        desc.blockDimX = 16;  // Tile size
        desc.blockDimY = 16;
        desc.blockDimZ = 1;
        
        // Grid dimensions would come from actual matrix sizes
        // Placeholder: calculate from buffer sizes
        desc.gridDimX = 64;   // Would be (N + 15) / 16
        desc.gridDimY = 64;   // Would be (M + 15) / 16
        desc.gridDimZ = 1;
        
        desc.inputBuffer = reinterpret_cast<uint64_t>(weights.data);
        desc.inputSize = weights.sizeBytes;
        desc.outputBuffer = reinterpret_cast<uint64_t>(output.data);
        desc.outputSize = output.sizeBytes;
        
        DispatchResult result{};
        result.pathUsed = DispatchPath::GPU_TITAN;
        
        uint64_t startTime = Titan_GetMicroseconds_Local();
        int status = Titan_ExecuteComputeKernel(&desc, output.data, output.sizeBytes);
        uint64_t endTime = Titan_GetMicroseconds_Local();
        
        result.success = (status == 0);
        result.executionTimeUs = endTime - startTime;
        result.errorCode = status;
        
        return result;
    }
    
    // CPU fallback
    DispatchResult result{};
    result.pathUsed = DispatchPath::CPU_MASM;
    
    // Would call: Cpu_MatMul_Q4_Q8(weights.data, activations.data, output.data, ...)
    // For now, mark as stub
    result.success = false;
    result.errorCode = 2;  // CPU path not yet wired
    
    return result;
}

DispatchResult DispatchFlashAttentionV2(
    const TensorDesc& query,
    const TensorDesc& key,
    const TensorDesc& value,
    TensorDesc& output,
    const TensorDesc* mask,
    float scale,
    const TitanGpuContext* gpu)
{
    DispatchPath path = RecommendDispatchPath(KernelId::FlashAttentionV2,
                                               query.sizeBytes + key.sizeBytes + value.sizeBytes, gpu);
    
    DispatchResult result{};
    result.pathUsed = path;
    
    if (path == DispatchPath::GPU_TITAN && gpu) {
        GPU_KERNEL_DESCRIPTOR desc{};
        desc.kernelName = reinterpret_cast<uint64_t>("FlashAttentionV2");
        
        // FlashAttention uses specific tiling
        desc.blockDimX = 128;  // Br / Bc from FlashAttention paper
        desc.blockDimY = 1;
        desc.blockDimZ = 1;
        
        // Grid: one block per sequence position
        desc.gridDimX = 256;  // Would be seqLen
        desc.gridDimY = 1;
        desc.gridDimZ = 1;
        
        // Input: packed QKV
        desc.inputBuffer = reinterpret_cast<uint64_t>(query.data);
        desc.inputSize = query.sizeBytes + key.sizeBytes + value.sizeBytes;
        desc.outputBuffer = reinterpret_cast<uint64_t>(output.data);
        desc.outputSize = output.sizeBytes;
        
        uint64_t startTime = Titan_GetMicroseconds_Local();
        int status = Titan_ExecuteComputeKernel(&desc, output.data, output.sizeBytes);
        uint64_t endTime = Titan_GetMicroseconds_Local();
        
        result.success = (status == 0);
        result.executionTimeUs = endTime - startTime;
        result.errorCode = status;
    } else {
        // CPU fallback
        result.success = false;
        result.errorCode = 2;  // CPU path not yet wired
    }
    
    return result;
}

DispatchResult DispatchRMSNorm(
    const TensorDesc& input,
    const TensorDesc& weight,
    TensorDesc& output,
    float epsilon,
    const TitanGpuContext* gpu)
{
    DispatchPath path = RecommendDispatchPath(KernelId::RMSNorm, input.sizeBytes, gpu);
    
    DispatchResult result{};
    result.pathUsed = path;
    
    if (path == DispatchPath::GPU_TITAN && gpu) {
        GPU_KERNEL_DESCRIPTOR desc{};
        desc.kernelName = reinterpret_cast<uint64_t>("RMSNorm");
        
        // RMSNorm: one thread per element or per row
        desc.blockDimX = 256;
        desc.blockDimY = 1;
        desc.blockDimZ = 1;
        
        uint32_t numRows = static_cast<uint32_t>(input.sizeBytes / (weight.sizeBytes * sizeof(float)));
        desc.gridDimX = (numRows + 255) / 256;
        desc.gridDimY = 1;
        desc.gridDimZ = 1;
        
        desc.inputBuffer = reinterpret_cast<uint64_t>(input.data);
        desc.inputSize = input.sizeBytes;
        desc.outputBuffer = reinterpret_cast<uint64_t>(output.data);
        desc.outputSize = output.sizeBytes;
        
        uint64_t startTime = Titan_GetMicroseconds_Local();
        int status = Titan_ExecuteComputeKernel(&desc, output.data, output.sizeBytes);
        uint64_t endTime = Titan_GetMicroseconds_Local();
        
        result.success = (status == 0);
        result.executionTimeUs = endTime - startTime;
        result.errorCode = status;
    } else {
        result.success = false;
        result.errorCode = 2;
    }
    
    return result;
}

DispatchResult DispatchRoPE(
    const TensorDesc& input,
    TensorDesc& output,
    const float* cosTable,
    const float* sinTable,
    uint32_t seqLen,
    uint32_t headDim,
    const TitanGpuContext* gpu)
{
    DispatchPath path = RecommendDispatchPath(KernelId::RoPE, input.sizeBytes, gpu);
    
    DispatchResult result{};
    result.pathUsed = path;
    
    if (path == DispatchPath::GPU_TITAN && gpu) {
        GPU_KERNEL_DESCRIPTOR desc{};
        desc.kernelName = reinterpret_cast<uint64_t>("RoPE");
        
        // RoPE: parallel over [batch, heads, seq]
        desc.blockDimX = headDim / 2;  // Process pairs of dimensions
        desc.blockDimY = 1;
        desc.blockDimZ = 1;
        
        desc.gridDimX = seqLen;
        desc.gridDimY = 1;  // Would be batch * heads
        desc.gridDimZ = 1;
        
        desc.inputBuffer = reinterpret_cast<uint64_t>(input.data);
        desc.inputSize = input.sizeBytes;
        desc.outputBuffer = reinterpret_cast<uint64_t>(output.data);
        desc.outputSize = output.sizeBytes;
        
        uint64_t startTime = Titan_GetMicroseconds_Local();
        int status = Titan_ExecuteComputeKernel(&desc, output.data, output.sizeBytes);
        uint64_t endTime = Titan_GetMicroseconds_Local();
        
        result.success = (status == 0);
        result.executionTimeUs = endTime - startTime;
        result.errorCode = status;
    } else {
        result.success = false;
        result.errorCode = 2;
    }
    
    return result;
}

DispatchResult DispatchSiLU(
    const TensorDesc& input,
    TensorDesc& output,
    const TitanGpuContext* gpu)
{
    DispatchPath path = RecommendDispatchPath(KernelId::SiLU, input.sizeBytes, gpu);
    
    DispatchResult result{};
    result.pathUsed = path;
    
    if (path == DispatchPath::GPU_TITAN && gpu) {
        GPU_KERNEL_DESCRIPTOR desc{};
        desc.kernelName = reinterpret_cast<uint64_t>("SiLU");
        
        // Element-wise: many threads
        desc.blockDimX = 256;
        desc.blockDimY = 1;
        desc.blockDimZ = 1;
        
        uint32_t elements = static_cast<uint32_t>(input.sizeBytes / sizeof(float));
        desc.gridDimX = (elements + 255) / 256;
        desc.gridDimY = 1;
        desc.gridDimZ = 1;
        
        desc.inputBuffer = reinterpret_cast<uint64_t>(input.data);
        desc.inputSize = input.sizeBytes;
        desc.outputBuffer = reinterpret_cast<uint64_t>(output.data);
        desc.outputSize = output.sizeBytes;
        
        uint64_t startTime = Titan_GetMicroseconds_Local();
        int status = Titan_ExecuteComputeKernel(&desc, output.data, output.sizeBytes);
        uint64_t endTime = Titan_GetMicroseconds_Local();
        
        result.success = (status == 0);
        result.executionTimeUs = endTime - startTime;
        result.errorCode = status;
    } else {
        result.success = false;
        result.errorCode = 2;
    }
    
    return result;
}

DispatchResult DispatchSoftmax(
    const TensorDesc& input,
    TensorDesc& output,
    int32_t axis,
    const TitanGpuContext* gpu)
{
    DispatchPath path = RecommendDispatchPath(KernelId::Softmax, input.sizeBytes, gpu);
    
    DispatchResult result{};
    result.pathUsed = path;
    
    if (path == DispatchPath::GPU_TITAN && gpu) {
        GPU_KERNEL_DESCRIPTOR desc{};
        desc.kernelName = reinterpret_cast<uint64_t>("Softmax");
        
        // Softmax: one block per row (for row-wise softmax)
        desc.blockDimX = 256;
        desc.blockDimY = 1;
        desc.blockDimZ = 1;
        
        // Grid: number of rows
        desc.gridDimX = 256;  // Would calculate from tensor shape
        desc.gridDimY = 1;
        desc.gridDimZ = 1;
        
        desc.inputBuffer = reinterpret_cast<uint64_t>(input.data);
        desc.inputSize = input.sizeBytes;
        desc.outputBuffer = reinterpret_cast<uint64_t>(output.data);
        desc.outputSize = output.sizeBytes;
        
        uint64_t startTime = Titan_GetMicroseconds_Local();
        int status = Titan_ExecuteComputeKernel(&desc, output.data, output.sizeBytes);
        uint64_t endTime = Titan_GetMicroseconds_Local();
        
        result.success = (status == 0);
        result.executionTimeUs = endTime - startTime;
        result.errorCode = status;
    } else {
        result.success = false;
        result.errorCode = 2;
    }
    
    return result;
}

DispatchResult DispatchCopy(
    const TensorDesc& source,
    TensorDesc& dest,
    size_t sizeBytes,
    const TitanGpuContext* gpu)
{
    DispatchPath path = RecommendDispatchPath(KernelId::CopyAligned, sizeBytes, gpu);
    
    DispatchResult result{};
    result.pathUsed = path;
    
    if (path == DispatchPath::GPU_TITAN && gpu) {
        // Use Titan_PerformCopy for GPU path
        GPU_COPY_OPERATION op{};
        op.operationType = 0;  // Standard copy
        op.sourceBuffer = reinterpret_cast<uint64_t>(source.data);
        op.destBuffer = reinterpret_cast<uint64_t>(dest.data);
        op.transferSize = sizeBytes;
        
        uint64_t startTime = Titan_GetMicroseconds_Local();
        int status = Titan_PerformCopy(&op, 0);  // Synchronous
        uint64_t endTime = Titan_GetMicroseconds_Local();
        
        result.success = (status == 0);
        result.executionTimeUs = endTime - startTime;
        result.errorCode = status;
    } else {
        // CPU fallback: standard memcpy
        std::memcpy(dest.data, source.data, std::min(sizeBytes, dest.sizeBytes));
        result.success = true;
        result.executionTimeUs = 0;  // Would measure
    }
    
    return result;
}

} // namespace sovereign
