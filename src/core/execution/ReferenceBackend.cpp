//==============================================================================
// ReferenceBackend.cpp
// Reference CPU Implementation - Numerical Correctness Oracle
//
// Pure C++ implementation with no optimizations.
// Used for:
// - Validating other backends (Intrinsics, MASM, GPU)
// - Fallback when no optimized backend is available
// - Debugging numerical issues
//
// Date: July 10, 2026
// Phase: 7C.1 - Kernel Registry Architecture
//==============================================================================

#include "IKernelBackend.hpp"
#include <cstring>
#include <cmath>
#include <algorithm>
#include <vector>
#include <chrono>

namespace sovereign {

class ReferenceBackend : public IKernelBackend {
public:
    //======================================================================
    // Backend Identification
    //======================================================================
    BackendInfo GetInfo() const override {
        return {
            "Reference",
            "1.0.0",
            BackendCapability::REFERENCE,
            1,  // Single-threaded reference
            SIZE_MAX
        };
    }
    
    //======================================================================
    // Initialization
    //======================================================================
    bool Initialize() override {
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
        // Reference supports all kernels
        return true;
    }
    
    bool SupportsDataType(TensorDesc::DataType dtype) const override {
        // Reference supports all data types
        return dtype != TensorDesc::DataType::Unknown;
    }
    
    //======================================================================
    // Core Operations - Reference Implementations
    //======================================================================
    
    bool MatMul(const TensorDesc& A, const TensorDesc& B, TensorDesc& C,
                const MatMulParams& params, ExecutionStats* stats) override {
        auto start = std::chrono::high_resolution_clock::now();
        
        // Simple triple-nested loop MatMul
        // C[i,j] = sum_k A[i,k] * B[k,j]
        
        const float* a = static_cast<const float*>(A.data);
        const float* b = static_cast<const float*>(B.data);
        float* c = static_cast<float*>(C.data);
        
        size_t M = params.M ? params.M : A.dims[0];
        size_t K = params.K ? params.K : A.dims[1];
        size_t N = params.N ? params.N : B.dims[1];
        
        // Initialize output
        std::memset(c, 0, M * N * sizeof(float));
        
        // Compute
        for (size_t i = 0; i < M; ++i) {
            for (size_t k = 0; k < K; ++k) {
                float a_ik = a[i * K + k];
                for (size_t j = 0; j < N; ++j) {
                    c[i * N + j] += a_ik * b[k * N + j];
                }
            }
        }
        
        // Apply alpha/beta scaling
        if (params.alpha != 1.0f || params.beta != 0.0f) {
            for (size_t i = 0; i < M * N; ++i) {
                c[i] = params.alpha * c[i] + params.beta * c[i];
            }
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        if (stats) {
            stats->executionTimeUs = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
            stats->totalTimeUs = stats->executionTimeUs;
            stats->gflops = (2.0 * M * N * K) / (stats->executionTimeUs * 1000.0); // GFLOP/s
        }
        
        return true;
    }
    
    bool FlashAttention(const TensorDesc& Q, const TensorDesc& K, const TensorDesc& V,
                       TensorDesc& output, const AttentionParams& params, ExecutionStats* stats) override {
        // Reference: Standard attention (not FlashAttention algorithm)
        // Simpler but O(n^2) memory
        
        auto start = std::chrono::high_resolution_clock::now();
        
        size_t seq_len = params.seqLen;
        size_t head_dim = params.headDim;
        
        const float* q = static_cast<const float*>(Q.data);
        const float* k = static_cast<const float*>(K.data);
        const float* v = static_cast<const float*>(V.data);
        float* out = static_cast<float*>(output.data);
        
        // Allocate temporary buffers
        std::vector<float> scores(seq_len * seq_len);
        std::vector<float> softmax_out(seq_len * seq_len);
        
        // Q × K^T
        for (size_t i = 0; i < seq_len; ++i) {
            for (size_t j = 0; j < seq_len; ++j) {
                float dot = 0.0f;
                for (size_t d = 0; d < head_dim; ++d) {
                    dot += q[i * head_dim + d] * k[j * head_dim + d];
                }
                scores[i * seq_len + j] = dot * params.scale;
            }
        }
        
        // Softmax per row
        for (size_t i = 0; i < seq_len; ++i) {
            float max_val = scores[i * seq_len];
            for (size_t j = 1; j < seq_len; ++j) {
                max_val = std::max(max_val, scores[i * seq_len + j]);
            }
            
            float sum = 0.0f;
            for (size_t j = 0; j < seq_len; ++j) {
                softmax_out[i * seq_len + j] = std::exp(scores[i * seq_len + j] - max_val);
                sum += softmax_out[i * seq_len + j];
            }
            
            for (size_t j = 0; j < seq_len; ++j) {
                softmax_out[i * seq_len + j] /= sum;
            }
        }
        
        // × V
        for (size_t i = 0; i < seq_len; ++i) {
            for (size_t d = 0; d < head_dim; ++d) {
                float sum = 0.0f;
                for (size_t j = 0; j < seq_len; ++j) {
                    sum += softmax_out[i * seq_len + j] * v[j * head_dim + d];
                }
                out[i * head_dim + d] = sum;
            }
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        if (stats) {
            stats->executionTimeUs = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
            stats->totalTimeUs = stats->executionTimeUs;
        }
        
        return true;
    }
    
    bool RMSNorm(const TensorDesc& input, const TensorDesc& weight, TensorDesc& output,
                float epsilon, ExecutionStats* stats) override {
        auto start = std::chrono::high_resolution_clock::now();
        
        const float* in = static_cast<const float*>(input.data);
        const float* w = static_cast<const float*>(weight.data);
        float* out = static_cast<float*>(output.data);
        
        size_t n = input.NumElements();
        
        // Compute RMS
        float sum_sq = 0.0f;
        for (size_t i = 0; i < n; ++i) {
            sum_sq += in[i] * in[i];
        }
        float rms = std::sqrt(sum_sq / n + epsilon);
        
        // Normalize and scale
        for (size_t i = 0; i < n; ++i) {
            out[i] = (in[i] / rms) * w[i % weight.NumElements()];
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        if (stats) {
            stats->executionTimeUs = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        }
        
        return true;
    }
    
    bool LayerNorm(const TensorDesc& input, const TensorDesc& weight, const TensorDesc& bias,
                  TensorDesc& output, float epsilon, ExecutionStats* stats) override {
        auto start = std::chrono::high_resolution_clock::now();
        
        const float* in = static_cast<const float*>(input.data);
        const float* w = static_cast<const float*>(weight.data);
        const float* b = bias.data ? static_cast<const float*>(bias.data) : nullptr;
        float* out = static_cast<float*>(output.data);
        
        size_t n = input.NumElements();
        
        // Compute mean
        float mean = 0.0f;
        for (size_t i = 0; i < n; ++i) {
            mean += in[i];
        }
        mean /= n;
        
        // Compute variance
        float var = 0.0f;
        for (size_t i = 0; i < n; ++i) {
            float diff = in[i] - mean;
            var += diff * diff;
        }
        var /= n;
        
        // Normalize
        float inv_std = 1.0f / std::sqrt(var + epsilon);
        for (size_t i = 0; i < n; ++i) {
            float normalized = (in[i] - mean) * inv_std;
            out[i] = normalized * w[i % weight.NumElements()];
            if (b) {
                out[i] += b[i % bias.NumElements()];
            }
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        if (stats) {
            stats->executionTimeUs = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        }
        
        return true;
    }
    
    bool RoPE(const TensorDesc& input, TensorDesc& output, const float* cosTable,
             const float* sinTable, uint32_t seqLen, uint32_t headDim,
             ExecutionStats* stats) override {
        auto start = std::chrono::high_resolution_clock::now();
        
        const float* in = static_cast<const float*>(input.data);
        float* out = static_cast<float*>(output.data);
        
        // Apply rotary embeddings
        for (uint32_t pos = 0; pos < seqLen; ++pos) {
            for (uint32_t d = 0; d < headDim; d += 2) {
                float x1 = in[pos * headDim + d];
                float x2 = in[pos * headDim + d + 1];
                float cos = cosTable[pos * headDim + d];
                float sin = sinTable[pos * headDim + d];
                
                out[pos * headDim + d] = x1 * cos - x2 * sin;
                out[pos * headDim + d + 1] = x1 * sin + x2 * cos;
            }
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        if (stats) {
            stats->executionTimeUs = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        }
        
        return true;
    }
    
    bool SiLU(const TensorDesc& input, TensorDesc& output, ExecutionStats* stats) override {
        auto start = std::chrono::high_resolution_clock::now();
        
        const float* in = static_cast<const float*>(input.data);
        float* out = static_cast<float*>(output.data);
        
        size_t n = input.NumElements();
        for (size_t i = 0; i < n; ++i) {
            // SiLU(x) = x * sigmoid(x) = x / (1 + exp(-x))
            out[i] = in[i] / (1.0f + std::exp(-in[i]));
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        if (stats) {
            stats->executionTimeUs = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        }
        
        return true;
    }
    
    bool Softmax(const TensorDesc& input, TensorDesc& output, int32_t axis,
                ExecutionStats* stats) override {
        auto start = std::chrono::high_resolution_clock::now();
        
        const float* in = static_cast<const float*>(input.data);
        float* out = static_cast<float*>(output.data);
        
        // Simplified: assume last axis
        size_t batch = input.dims[0];
        size_t features = input.dims[input.numDims - 1];
        
        for (size_t b = 0; b < batch; ++b) {
            // Find max
            float max_val = in[b * features];
            for (size_t i = 1; i < features; ++i) {
                max_val = std::max(max_val, in[b * features + i]);
            }
            
            // Compute exp and sum
            float sum = 0.0f;
            for (size_t i = 0; i < features; ++i) {
                out[b * features + i] = std::exp(in[b * features + i] - max_val);
                sum += out[b * features + i];
            }
            
            // Normalize
            for (size_t i = 0; i < features; ++i) {
                out[b * features + i] /= sum;
            }
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        if (stats) {
            stats->executionTimeUs = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        }
        
        return true;
    }
    
    bool ResidualAdd(const TensorDesc& input, const TensorDesc& residual,
                    TensorDesc& output, ExecutionStats* stats) override {
        auto start = std::chrono::high_resolution_clock::now();
        
        const float* in = static_cast<const float*>(input.data);
        const float* res = static_cast<const float*>(residual.data);
        float* out = static_cast<float*>(output.data);
        
        size_t n = input.NumElements();
        for (size_t i = 0; i < n; ++i) {
            out[i] = in[i] + res[i];
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        if (stats) {
            stats->executionTimeUs = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        }
        
        return true;
    }
    
    bool Quantize(const TensorDesc& input, TensorDesc& output,
                 const QuantParams& params, ExecutionStats* stats) override {
        // Reference: Simple per-block quantization
        // Not fully implemented - would need block-wise processing
        return false;
    }
    
    bool Dequantize(const TensorDesc& input, TensorDesc& output,
                   const QuantParams& params, ExecutionStats* stats) override {
        // Reference: Simple dequantization
        // Not fully implemented
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
        // Synchronous backend - nothing to sync
        return true;
    }

private:
    bool initialized_ = false;
};

// Factory function
IKernelBackend* CreateReferenceBackend() {
    return new ReferenceBackend();
}

} // namespace sovereign
