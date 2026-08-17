//===============================================================================
// GGML Pure MASM Header - Dependency-Free GGML Operations
// C interface to pure x64 assembly implementations
//===============================================================================

#ifndef GGML_MASM_PURE_H
#define GGML_MASM_PURE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

//===============================================================================
// Core Operations - Implemented in Assembly
//===============================================================================

// Element-wise addition: dst[i] = src0[i] + src1[i]
void ggml_masm_add_f32(float* dst, const float* src0, const float* src1, size_t count);

// Element-wise multiplication: dst[i] = src0[i] * src1[i]
void ggml_masm_mul_f32(float* dst, const float* src0, const float* src1, size_t count);

// Scale: dst[i] = src[i] * scale
void ggml_masm_scale_f32(float* dst, const float* src, size_t count, float scale);

// SiLU activation: dst[i] = src[i] * sigmoid(src[i])
void ggml_masm_silu_f32(float* dst, const float* src, size_t count);

// Softmax: dst[i] = exp(src[i]) / sum(exp(src[j]))
void ggml_masm_softmax_f32(float* dst, const float* src, size_t count);

// Rotary Position Embedding
void ggml_masm_rope_f32(float* dst, const float* src, size_t head_dim, int position);

// Matrix multiplication: C[M,N] = A[M,K] * B[K,N]
void ggml_masm_matmul_f32(float* C, const float* A, const float* B, 
                          size_t M, size_t N, size_t K);

// RMS Normalization
void ggml_masm_rms_norm_f32(float* dst, const float* src, size_t count);

// Matrix transpose
void ggml_masm_transpose_f32(float* dst, const float* src, size_t rows, size_t cols);

// Copy
void ggml_masm_copy_f32(float* dst, const float* src, size_t count);

//===============================================================================
// Tensor Structure (Minimal)
//===============================================================================

typedef enum {
    GGML_MASM_TYPE_F32 = 0,
    GGML_MASM_TYPE_F16 = 1,
    GGML_MASM_TYPE_Q4_0 = 2,
    GGML_MASM_TYPE_Q8_0 = 3,
} ggml_masm_type;

typedef struct {
    ggml_masm_type type;
    int n_dims;
    int64_t ne[4];  // Number of elements per dimension
    int64_t nb[4];  // Stride in bytes per dimension
    void* data;
    char name[64];
} ggml_masm_tensor;

//===============================================================================
// Context Structure
//===============================================================================

typedef struct ggml_masm_context ggml_masm_context;

typedef struct {
    size_t mem_size;
    void* mem_buffer;
    bool no_alloc;
} ggml_masm_init_params;

// Context management
ggml_masm_context* ggml_masm_init(const ggml_masm_init_params* params);
void ggml_masm_free(ggml_masm_context* ctx);
void* ggml_masm_get_mem_buffer(ggml_masm_context* ctx);
size_t ggml_masm_get_mem_size(ggml_masm_context* ctx);

//===============================================================================
// Tensor Operations
//===============================================================================

// Tensor creation
ggml_masm_tensor* ggml_masm_new_tensor_1d(ggml_masm_context* ctx, ggml_masm_type type, int64_t ne0);
ggml_masm_tensor* ggml_masm_new_tensor_2d(ggml_masm_context* ctx, ggml_masm_type type, 
                                           int64_t ne0, int64_t ne1);
ggml_masm_tensor* ggml_masm_new_tensor_3d(ggml_masm_context* ctx, ggml_masm_type type,
                                           int64_t ne0, int64_t ne1, int64_t ne2);
ggml_masm_tensor* ggml_masm_new_tensor_4d(ggml_masm_context* ctx, ggml_masm_type type,
                                           int64_t ne0, int64_t ne1, int64_t ne2, int64_t ne3);

// Tensor operations
ggml_masm_tensor* ggml_masm_add(ggml_masm_context* ctx, ggml_masm_tensor* a, ggml_masm_tensor* b);
ggml_masm_tensor* ggml_masm_mul(ggml_masm_context* ctx, ggml_masm_tensor* a, ggml_masm_tensor* b);
ggml_masm_tensor* ggml_masm_scale(ggml_masm_context* ctx, ggml_masm_tensor* a, float s);
ggml_masm_tensor* ggml_masm_silu(ggml_masm_context* ctx, ggml_masm_tensor* a);
ggml_masm_tensor* ggml_masm_softmax(ggml_masm_context* ctx, ggml_masm_tensor* a);
ggml_masm_tensor* ggml_masm_rms_norm(ggml_masm_context* ctx, ggml_masm_tensor* a, float eps);
ggml_masm_tensor* ggml_masm_matmul(ggml_masm_context* ctx, ggml_masm_tensor* a, ggml_masm_tensor* b);
ggml_masm_tensor* ggml_masm_rope(ggml_masm_context* ctx, ggml_masm_tensor* a, int pos);

// Graph computation
typedef struct ggml_masm_cgraph ggml_masm_cgraph;

ggml_masm_cgraph* ggml_masm_new_graph(ggml_masm_context* ctx);
void ggml_masm_build_forward_expand(ggml_masm_cgraph* cgraph, ggml_masm_tensor* tensor);
void ggml_masm_graph_compute(ggml_masm_context* ctx, ggml_masm_cgraph* cgraph);

// Tensor data access
void* ggml_masm_get_data(ggml_masm_tensor* tensor);
size_t ggml_masm_nbytes(const ggml_masm_tensor* tensor);
float* ggml_masm_get_f32_1d(const ggml_masm_tensor* tensor, int i);
void ggml_masm_set_f32_1d(ggml_masm_tensor* tensor, int i, float value);

// Utility
int64_t ggml_masm_nelements(const ggml_masm_tensor* tensor);
int64_t ggml_masm_nrows(const ggml_masm_tensor* tensor);

//===============================================================================
// KV Cache
//===============================================================================

typedef struct {
    ggml_masm_tensor* k;
    ggml_masm_tensor* v;
    int n_ctx;
    int n_used;
    ggml_masm_context* ctx;
} ggml_masm_kv_cache;

bool ggml_masm_kv_cache_init(ggml_masm_kv_cache* cache, ggml_masm_context* ctx,
                              int n_ctx, int n_embd, int n_head);
void ggml_masm_kv_cache_free(ggml_masm_kv_cache* cache);
void ggml_masm_kv_cache_clear(ggml_masm_kv_cache* cache);

//===============================================================================
// Transformer Operations
//===============================================================================

// Attention: Q @ K^T / sqrt(head_dim) @ V
ggml_masm_tensor* ggml_masm_attention(ggml_masm_context* ctx,
                                       ggml_masm_tensor* q,
                                       ggml_masm_tensor* k,
                                       ggml_masm_tensor* v,
                                       int n_head);

// Feed-forward network: silu(x @ W1) * (x @ W3) @ W2
ggml_masm_tensor* ggml_masm_ffn(ggml_masm_context* ctx,
                                 ggml_masm_tensor* x,
                                 ggml_masm_tensor* w1,
                                 ggml_masm_tensor* w2,
                                 ggml_masm_tensor* w3);

// Transformer layer: norm -> attention -> residual -> norm -> ffn -> residual
ggml_masm_tensor* ggml_masm_transformer_layer(ggml_masm_context* ctx,
                                                 ggml_masm_tensor* x,
                                                 ggml_masm_kv_cache* kv_cache,
                                                 int layer_idx,
                                                 int pos);

//===============================================================================
// Sampling
//===============================================================================

// Top-k sampling
int ggml_masm_sample_top_k(const float* logits, int n_vocab, int k);

// Top-p (nucleus) sampling
int ggml_masm_sample_top_p(const float* logits, int n_vocab, float p);

// Temperature scaling
void ggml_masm_apply_temperature(float* logits, int n_vocab, float temp);

// Greedy sampling (argmax)
int ggml_masm_sample_greedy(const float* logits, int n_vocab);

//===============================================================================
// Initialization
//===============================================================================

bool ggml_masm_init_library(void);
void ggml_masm_deinit_library(void);

#ifdef __cplusplus
}
#endif

#endif // GGML_MASM_PURE_H
