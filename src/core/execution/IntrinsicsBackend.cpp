//==============================================================================
// IntrinsicsBackend.cpp
// SIMD Intrinsics Backend - AVX2/AVX-512 Optimized
//
// Wraps the intrinsics kernels from d:\src\asm
// Provides optimized portable implementation
//
// Date: July 10, 2026
// Phase: 7C.1 - Kernel Registry Architecture
//==============================================================================

#include "IKernelBackend.hpp"
#include <cstring>
#include <chrono>

// External declarations from d:\src\asm intrinsics kernels
extern "C" {
    // From Sovereign_Q4Q8_MatMul_Intrinsics.cpp
    int Sovereign_Q4Q8_MatMul_Intrinsics(
        const void* A, const void* B, float* C,
        size_t m, size_t n, size_t k);
    const char* Sovereign_GetQ4Q8Version();
    
    // From Sovereign_FlashAttention_Intrinsics.cpp
    int Sovereign_FlashAttentionV2_Intrinsics(
        float* Q, float* K, float* V, float* output,
        size_t seq_len, size_t head_dim);
    const char* Sovereign_GetFlashAttentionVersion();
}

namespace sovereign {

class IntrinsicsBackend : public IKernelBackend {
public:
    //======================================================================
    // Backend Identification
    //======================================================================
    BackendInfo GetInfo() const override {
        BackendCapability caps = BackendCapability::INTRINSICS 
                               | BackendCapability::REFERENCE;
        
        // Detect AVX-512 at runtime
        if (HasAVX512()) {
            caps = caps | BackendCapability::REFERENCE; // Can use wider vectors
        }
        
        return {
            "Intrinsics",
            Sovereign_GetQ4Q8Version(),
            caps,
            16,  // Up to 16 threads
            SIZE_MAX
        };
    }
    
    //======================================================================
    // Initialization
    //======================================================================
    bool Initialize() override {
        // Check CPU features
        hasAVX2_ = HasAVX2();
        hasAVX512_ = HasAVX512();
        
        if (!hasAVX2_) {
            return false; // AVX2 minimum required
        }
        
        initialized_ = true;
        return true;
    }
    
    void Shutdown() override {
        initialized_ = false;
    }
    
    bool IsInitialized() const override {
        return initialized_;
    }
    
    //======================================================================
    // Capabilities
    //======================================================================
    bool SupportsKernel(KernelId id) const override {
        switch (id) {
            case KernelId::MatMul_Q4_Q8:
            case KernelId::FlashAttentionV2:
                return true;
            default:
                return false;
        }
    }
    
    bool SupportsDataType(TensorDesc::DataType dtype) const override {
        switch (dtype) {
            case TensorDesc::DataType::F32:
            case TensorDesc::DataType::Q4_0:
            case TensorDesc::DataType::Q8_0:
                return true;
            default:
                return false;
        }
    }
    
    //======================================================================
    // Core Operations - Intrinsics Implementations
    //======================================================================
    
    bool MatMul(const TensorDesc& A, const TensorDesc& B, TensorDesc& C,
                const MatMulParams& params, ExecutionStats* stats) override {
        if (!initialized_) return false;
        
        auto start = std::chrono::high_resolution_clock::now();
        
        // Call intrinsics kernel
        int result = Sovereign_Q4Q8_MatMul_Intrinsics(
            A.data, B.data, static_cast<float*>(C.data),
            params.M, params.N, params.K
        );
        
        auto end = std::chrono::high_resolution_clock::now();
        
        if (stats) {
            stats->executionTimeUs = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
            stats->totalTimeUs = stats->executionTimeUs;
            stats->gflops = (2.0 * params.M * params.N * params.K) / (stats->executionTimeUs * 1000.0);
            stats->backendId = 1; // Intrinsics
        }
        
        return result == 0;
    }
    
    bool FlashAttention(const TensorDesc& Q, const TensorDesc& K, const TensorDesc& V,
                       TensorDesc& output, const AttentionParams& params, ExecutionStats* stats) override {
        if (!initialized_) return false;
        
        auto start = std::chrono::high_resolution_clock::now();
        
        // Call intrinsics kernel
        int result = Sovereign_FlashAttentionV2_Intrinsics(
            static_cast<float*>(Q.data),
            static_cast<float*>(K.data),
            static_cast<float*>(V.data),
            static_cast<float*>(output.data),
            params.seqLen,
            params.headDim
        );
        
        auto end = std::chrono::high_resolution_clock::now();
        
        if (stats) {
            stats->executionTimeUs = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
            stats->totalTimeUs = stats->executionTimeUs;
            stats->backendId = 1;
        }
        
        return result == 0;
    }
    
    // Other kernels fall back to reference or return false
    bool RMSNorm(const TensorDesc& input, const TensorDesc& weight, TensorDesc& output,
                float epsilon, ExecutionStats* stats) override {
        // Not yet implemented in intrinsics - would need reference fallback
        return false;
    }
    
    bool LayerNorm(const TensorDesc& input, const TensorDesc& weight, const TensorDesc& bias,
                  TensorDesc& output, float epsilon, ExecutionStats* stats) override {
        return false;
    }
    
    bool RoPE(const TensorDesc& input, TensorDesc& output, const float* cosTable,
             const float* sinTable, uint32_t seqLen, uint32_t headDim,
             ExecutionStats* stats) override {
        return false;
    }
    
    bool SiLU(const TensorDesc& input, TensorDesc& output, ExecutionStats* stats) override {
        return false;
    }
    
    bool Softmax(const TensorDesc& input, TensorDesc& output, int32_t axis,
                ExecutionStats* stats) override {
        return false;
    }
    
    bool ResidualAdd(const TensorDesc& input, const TensorDesc& residual,
                    TensorDesc& output, ExecutionStats* stats) override {
        return false;
    }
    
    bool Quantize(const TensorDesc& input, TensorDesc& output,
                 const QuantParams& params, ExecutionStats* stats) override {
        return false;
    }
    
    bool Dequantize(const TensorDesc& input, TensorDesc& output,
                   const QuantParams& params, ExecutionStats* stats) override {
        return false;
    }
    
    bool Copy(const TensorDesc& source, TensorDesc& dest, size_t sizeBytes,
             ExecutionStats* stats) override {
        auto start = std::chrono::high_resolution_clock::now();
        
        std::memcpy(dest.data, source.data, std::min(sizeBytes, dest.sizeBytes));
        
        auto end = std::chrono::high_resolution_clock::now();
        if (stats) {
            stats->executionTimeUs = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        }
        
        return true;
    }
    
    bool Synchronize() override {
        // Synchronous backend
        return true;
    }

private:
    bool initialized_ = false;
    bool hasAVX2_ = false;
    bool hasAVX512_ = false;
    
    // CPU feature detection
    bool HasAVX2() {
        // Simplified - would use CPUID in production
        #ifdef __AVX2__
        return true;
        #else
        return false;
        #endif
    }
    
    bool HasAVX512() {
        #ifdef __AVX512F__
        return true;
        #else
        return false;
        #endif
    }
};

// Factory function
IKernelBackend* CreateIntrinsicsBackend() {
    return new IntrinsicsBackend();
}

} // namespace sovereign
