//==============================================================================
// MASMBackend.cpp
// Thin adapter for MASM kernel execution
//
// Phase 7C.2 - MASM Backend Integration
// Marshals parameters to exported MASM functions
//==============================================================================

#include "MASMBackend.hpp"
#include <cstdio>
#include <cstring>
#include <chrono>

namespace sovereign {

//==============================================================================
// Timing Helper
//==============================================================================
uint64_t MASMBackend::NowUs() const {
    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::microseconds>(duration).count();
}

//==============================================================================
// Constructor / Destructor
//==============================================================================
MASMBackend::MASMBackend() 
    : initialized_(false) {
    memset(&kernelTable_, 0, sizeof(kernelTable_));
}

MASMBackend::~MASMBackend() {
    Shutdown();
}

//==============================================================================
// Initialization
//==============================================================================
bool MASMBackend::Initialize() {
    if (initialized_) return true;
    
    int result = Sovereign_InitKernelTable(&kernelTable_);
    if (result == 0) {
        initialized_ = true;
        PopulateSupportedKernels();
        return true;
    }
    return false;
}

void MASMBackend::Shutdown() {
    initialized_ = false;
    memset(&kernelTable_, 0, sizeof(kernelTable_));
}

//==============================================================================
// Backend Info
//==============================================================================
BackendInfo MASMBackend::GetInfo() const {
    BackendInfo info{};
    info.name = "MASM";
    info.version = "7C.2";
    info.capabilities = BackendCapability::MASM | BackendCapability::INTRINSICS;
    info.maxThreads = 64;
    info.maxBufferSize = 16ULL * 1024 * 1024 * 1024;  // 16GB
    return info;
}

//==============================================================================
// Capability Reporting
//==============================================================================
void MASMBackend::PopulateSupportedKernels() {
    supportedKernels_.clear();
    
    // Check each kernel and add to supported list if available
    if (kernelTable_.rms_norm_f32) {
        supportedKernels_.push_back(KernelId::RMSNorm);
    }
    if (kernelTable_.layer_norm_f32) {
        supportedKernels_.push_back(KernelId::LayerNorm);
    }
    if (kernelTable_.rope_apply_f32) {
        supportedKernels_.push_back(KernelId::RoPE);
    }
    if (kernelTable_.residual_add_f32) {
        supportedKernels_.push_back(KernelId::ResidualAdd);
    }
    if (kernelTable_.q4k_dequant_tensor) {
        supportedKernels_.push_back(KernelId::Dequantize_Q4);
    }
    if (kernelTable_.q4q8_matmul_intrinsics || kernelTable_.q4_0_q8_0_matmul) {
        supportedKernels_.push_back(KernelId::MatMul_Q4_Q8);
    }
    if (kernelTable_.flash_attention_v2_intrinsics || kernelTable_.flash_attention_v2_f32) {
        supportedKernels_.push_back(KernelId::FlashAttentionV2);
    }
}

bool MASMBackend::SupportsKernel(KernelId id) const {
    for (auto kid : supportedKernels_) {
        if (kid == id) return true;
    }
    return false;
}

bool MASMBackend::SupportsDataType(TensorDesc::DataType dtype) const {
    // MASM supports F32, Q4_0, Q8_0
    switch (dtype) {
        case TensorDesc::DataType::F32:
        case TensorDesc::DataType::Q4_0:
        case TensorDesc::DataType::Q8_0:
            return true;
        default:
            return false;
    }
}

//==============================================================================
// Core Operations
//==============================================================================
bool MASMBackend::MatMul(const TensorDesc& A, const TensorDesc& B, TensorDesc& C,
                          const MatMulParams& params, ExecutionStats* stats) {
    if (!initialized_) return false;
    
    uint64_t startTime = NowUs();
    int result = -1;
    
    // Prefer intrinsics version if available
    if (kernelTable_.q4q8_matmul_intrinsics) {
        result = kernelTable_.q4q8_matmul_intrinsics(
            A.data, B.data, (float*)C.data, params.M, params.N, params.K);
    } else if (kernelTable_.q4_0_q8_0_matmul) {
        result = kernelTable_.q4_0_q8_0_matmul(
            A.data, B.data, (float*)C.data, params.M, params.N, params.K);
    }
    
    if (stats) {
        stats->executionTimeUs = NowUs() - startTime;
        stats->backendId = 0;  // MASM
    }
    
    return result == 0;
}

bool MASMBackend::FlashAttention(const TensorDesc& Q, const TensorDesc& K, const TensorDesc& V,
                                    TensorDesc& output, const AttentionParams& params,
                                    ExecutionStats* stats) {
    if (!initialized_) return false;
    
    uint64_t startTime = NowUs();
    int result = -1;
    
    // Prefer intrinsics version if available
    if (kernelTable_.flash_attention_v2_intrinsics) {
        result = kernelTable_.flash_attention_v2_intrinsics(
            (float*)Q.data, (float*)K.data, (float*)V.data, 
            (float*)output.data, params.seqLen, params.headDim);
    } else if (kernelTable_.flash_attention_v2_f32) {
        result = kernelTable_.flash_attention_v2_f32(
            (float*)Q.data, (float*)K.data, (float*)V.data,
            (float*)output.data, params.seqLen, params.headDim);
    }
    
    if (stats) {
        stats->executionTimeUs = NowUs() - startTime;
        stats->backendId = 0;
    }
    
    return result == 0;
}

bool MASMBackend::RMSNorm(const TensorDesc& input, const TensorDesc& weight, 
                          TensorDesc& output, float epsilon, ExecutionStats* stats) {
    if (!initialized_ || !kernelTable_.rms_norm_f32) return false;
    
    uint64_t startTime = NowUs();
    
    int result = kernelTable_.rms_norm_f32(
        (float*)input.data, (float*)output.data, (float*)weight.data,
        input.dims[0], epsilon);
    
    if (stats) {
        stats->executionTimeUs = NowUs() - startTime;
        stats->backendId = 0;
    }
    
    return result == 0;
}

bool MASMBackend::LayerNorm(const TensorDesc& input, const TensorDesc& weight,
                              const TensorDesc& bias, TensorDesc& output,
                              float epsilon, ExecutionStats* stats) {
    if (!initialized_ || !kernelTable_.layer_norm_f32) return false;
    
    uint64_t startTime = NowUs();
    
    int result = kernelTable_.layer_norm_f32(
        (float*)input.data, (float*)output.data, 
        (float*)weight.data, (float*)bias.data,
        input.dims[0], epsilon);
    
    if (stats) {
        stats->executionTimeUs = NowUs() - startTime;
        stats->backendId = 0;
    }
    
    return result == 0;
}

bool MASMBackend::RoPE(const TensorDesc& input, TensorDesc& output, const float* cosTable,
                        const float* sinTable, uint32_t seqLen, uint32_t headDim,
                        ExecutionStats* stats) {
    if (!initialized_ || !kernelTable_.rope_apply_f32) return false;
    
    uint64_t startTime = NowUs();
    
    // Note: RoPE kernel may need freq_cache parameter
    int result = kernelTable_.rope_apply_f32(
        (float*)input.data, (float*)output.data, seqLen, headDim, 1);
    
    if (stats) {
        stats->executionTimeUs = NowUs() - startTime;
        stats->backendId = 0;
    }
    
    return result == 0;
}

bool MASMBackend::SiLU(const TensorDesc& input, TensorDesc& output, ExecutionStats* stats) {
    // MASM doesn't have dedicated SiLU - would need to implement or fall back
    return false;
}

bool MASMBackend::Softmax(const TensorDesc& input, TensorDesc& output, int32_t axis,
                           ExecutionStats* stats) {
    // MASM doesn't have dedicated Softmax - would need to implement or fall back
    return false;
}

bool MASMBackend::ResidualAdd(const TensorDesc& input, const TensorDesc& residual,
                               TensorDesc& output, ExecutionStats* stats) {
    if (!initialized_ || !kernelTable_.residual_add_f32) return false;
    
    uint64_t startTime = NowUs();
    
    int result = kernelTable_.residual_add_f32(
        (float*)input.data, (float*)residual.data, (float*)output.data,
        input.NumElements());
    
    if (stats) {
        stats->executionTimeUs = NowUs() - startTime;
        stats->backendId = 0;
    }
    
    return result == 0;
}

bool MASMBackend::Quantize(const TensorDesc& input, TensorDesc& output, 
                            const QuantParams& params, ExecutionStats* stats) {
    // MASM quantization not yet implemented
    return false;
}

bool MASMBackend::Dequantize(const TensorDesc& input, TensorDesc& output,
                              const QuantParams& params, ExecutionStats* stats) {
    if (!initialized_ || !kernelTable_.q4k_dequant_tensor) return false;
    
    uint64_t startTime = NowUs();
    
    // Use params.scale as tensor_info placeholder (or nullptr if not needed)
    int result = kernelTable_.q4k_dequant_tensor(
        input.data, (float*)output.data, 
        input.dims[0] * input.dims[1], nullptr);
    
    if (stats) {
        stats->executionTimeUs = NowUs() - startTime;
        stats->backendId = 0;
    }
    
    return result == 0;
}

bool MASMBackend::Copy(const TensorDesc& source, TensorDesc& dest, 
                        size_t sizeBytes, ExecutionStats* stats) {
    // Simple memcpy for now
    uint64_t startTime = NowUs();
    
    memcpy(dest.data, source.data, sizeBytes);
    
    if (stats) {
        stats->executionTimeUs = NowUs() - startTime;
        stats->backendId = 0;
    }
    
    return true;
}

} // namespace sovereign
