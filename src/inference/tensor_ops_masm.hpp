// ============================================================================
// RawrXD Tensor Operations MASM Bridge - C++ Interface
// Zero-overhead wrapper for pure x64 MASM tensor kernels
// Replaces GGML dependency with custom assembly
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

// ============================================================================
// C Linkage - MASM exports
// ============================================================================
extern "C" {
    // Arena allocation
    void* ArenaAlloc(size_t size);
    
    // Tensor creation
    void* TensorNew1D(int type, int64_t ne0);
    void* TensorNew2D(int type, int64_t ne0, int64_t ne1);
    
    // Tensor operations
    void MatMulF32(const float* A, const float* B, float* C, 
                   int64_t M, int64_t N, int64_t K);
    void SoftmaxF32(float* x, int64_t n);
    void RMSNormF32(float* x, const float* weight, int64_t n, float eps);
    void SiLUF32(float* x, int64_t n);
    void RoPEF32(float* vec, int64_t head_dim, int pos, float theta_base);
    
    // Data exports
    extern unsigned char g_TensorArena[];
    extern size_t g_TensorArenaUsed;
}

namespace RawrXD {
namespace Inference {
namespace MASM {

// ============================================================================
// Tensor Types
// ============================================================================
enum class TensorType : int {
    F32 = 0,
    F16 = 1
};

// ============================================================================
// Tensor Structure (matches MASM layout)
// ============================================================================
#pragma pack(push, 1)
struct Tensor {
    int32_t type;
    int64_t ne[4];      // dimensions
    void* data;
    
    // Helper methods
    [[nodiscard]] int64_t Ne0() const { return ne[0]; }
    [[nodiscard]] int64_t Ne1() const { return ne[1]; }
    [[nodiscard]] int64_t Ne2() const { return ne[2]; }
    [[nodiscard]] int64_t Ne3() const { return ne[3]; }
    [[nodiscard]] int64_t NumElements() const { return ne[0] * ne[1] * ne[2] * ne[3]; }
    [[nodiscard]] size_t NumBytes() const { return NumElements() * sizeof(float); }
    
    [[nodiscard]] float* DataF32() { return static_cast<float*>(data); }
    [[nodiscard]] const float* DataF32() const { return static_cast<const float*>(data); }
};
#pragma pack(pop)

// ============================================================================
// Tensor Factory
// ============================================================================
class TensorFactory {
public:
    static Tensor* New1D(TensorType type, int64_t ne0) {
        return static_cast<Tensor*>(TensorNew1D(static_cast<int>(type), ne0));
    }
    
    static Tensor* New2D(TensorType type, int64_t ne0, int64_t ne1) {
        return static_cast<Tensor*>(TensorNew2D(static_cast<int>(type), ne0, ne1));
    }
};

// ============================================================================
// Math Operations - Inline wrappers
// ============================================================================
class TensorOps {
public:
    // Matrix multiplication: C = A @ B
    static void MatMul(const Tensor* A, const Tensor* B, Tensor* C) {
        MatMulF32(A->DataF32(), B->DataF32(), C->DataF32(),
                  A->Ne0(), B->Ne1(), A->Ne1());
    }
    
    // Softmax in-place
    static void Softmax(Tensor* x) {
        SoftmaxF32(x->DataF32(), x->Ne0());
    }
    
    // RMSNorm in-place
    static void RMSNorm(Tensor* x, const Tensor* weight, float eps = 1e-6f) {
        RMSNormF32(x->DataF32(), weight ? weight->DataF32() : nullptr, 
                   x->Ne0(), eps);
    }
    
    // SiLU activation in-place
    static void SiLU(Tensor* x) {
        SiLUF32(x->DataF32(), x->Ne0());
    }
    
    // RoPE in-place
    static void RoPE(Tensor* vec, int pos, float theta_base = 10000.0f) {
        RoPEF32(vec->DataF32(), vec->Ne0(), pos, theta_base);
    }
};

// ============================================================================
// Arena Management
// ============================================================================
class TensorArena {
public:
    static void* Allocate(size_t size) {
        return ArenaAlloc(size);
    }
    
    [[nodiscard]] static size_t GetUsed() {
        return g_TensorArenaUsed;
    }
    
    static void Reset() {
        g_TensorArenaUsed = 0;
    }
};

// ============================================================================
// High-level Tensor Operations (GGML-compatible API)
// ============================================================================

// Matrix multiplication with dimensions
inline Tensor* MatMul(Tensor* a, Tensor* b) {
    auto* c = TensorFactory::New2D(TensorType::F32, a->Ne0(), b->Ne1());
    if (c) {
        TensorOps::MatMul(a, b, c);
    }
    return c;
}

// Softmax
inline Tensor* Softmax(Tensor* x) {
    TensorOps::Softmax(x);
    return x;
}

// RMSNorm
inline Tensor* RMSNorm(Tensor* x, Tensor* weight, float eps = 1e-6f) {
    TensorOps::RMSNorm(x, weight, eps);
    return x;
}

// SiLU
inline Tensor* SiLU(Tensor* x) {
    TensorOps::SiLU(x);
    return x;
}

// RoPE
inline Tensor* RoPE(Tensor* x, int pos, float theta_base = 10000.0f) {
    TensorOps::RoPE(x, pos, theta_base);
    return x;
}

// ============================================================================
// Attention Computation (high-level)
// ============================================================================
class AttentionOps {
public:
    // Compute attention scores: Q @ K^T / sqrt(head_dim)
    static void ComputeScores(const float* Q, const float* K, float* scores,
                               int n_head, int head_dim, int seq_len);
    
    // Apply attention to values: softmax(scores) @ V
    static void ApplyAttention(const float* scores, const float* V, float* output,
                                int n_head, int head_dim, int seq_len);
    
    // Full attention forward pass
    static void Forward(Tensor* Q, Tensor* K, Tensor* V, Tensor* output,
                       int n_head, int head_dim, int seq_len);
};

// ============================================================================
// Transformer Layer (high-level)
// ============================================================================
class TransformerLayerMASM {
public:
    struct Weights {
        Tensor* attn_norm;
        Tensor* attn_q;
        Tensor* attn_k;
        Tensor* attn_v;
        Tensor* attn_o;
        Tensor* ffn_norm;
        Tensor* ffn_gate;
        Tensor* ffn_up;
        Tensor* ffn_down;
    };
    
    void Forward(Tensor* hidden_states, int seq_len, int pos,
                 const Weights& weights, int n_head, int n_kv_head);
};

} // namespace MASM
} // namespace Inference
} // namespace RawrXD

// ============================================================================
// GGML Compatibility Layer
// ============================================================================
// These allow gradual migration from GGML to MASM

// Type aliases for GGML compatibility
using ggml_context = void;
using ggml_tensor = RawrXD::Inference::MASM::Tensor;
using ggml_type = RawrXD::Inference::MASM::TensorType;

#define GGML_TYPE_F32 static_cast<int>(RawrXD::Inference::MASM::TensorType::F32)
#define GGML_TYPE_F16 static_cast<int>(RawrXD::Inference::MASM::TensorType::F16)

// Inline compatibility functions
inline ggml_tensor* ggml_new_tensor_1d(ggml_context* ctx, ggml_type type, int64_t ne0) {
    (void)ctx;
    return RawrXD::Inference::MASM::TensorFactory::New1D(type, ne0);
}

inline ggml_tensor* ggml_new_tensor_2d(ggml_context* ctx, ggml_type type, int64_t ne0, int64_t ne1) {
    (void)ctx;
    return RawrXD::Inference::MASM::TensorFactory::New2D(type, ne0, ne1);
}

inline size_t ggml_nbytes(const ggml_tensor* tensor) {
    return tensor ? tensor->NumBytes() : 0;
}

inline float* ggml_get_data_f32(ggml_tensor* tensor) {
    return tensor ? tensor->DataF32() : nullptr;
}

inline void ggml_set_f32(ggml_tensor* tensor, float value) {
    if (!tensor || !tensor->data) return;
    float* data = tensor->DataF32();
    for (int64_t i = 0; i < tensor->NumElements(); i++) {
        data[i] = value;
    }
}

// Minimal context (no-op for MASM version)
struct ggml_init_params {
    size_t mem_size;
    void* mem_buffer;
    bool no_alloc;
};

inline ggml_context* ggml_init(ggml_init_params params) {
    (void)params;
    return reinterpret_cast<ggml_context*>(1);  // Dummy non-null pointer
}

inline void ggml_free(ggml_context* ctx) {
    (void)ctx;
}
