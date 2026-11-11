// ============================================================================
// rawrxd_masm_bridge.h
// C++ declarations for pure x64 MASM tensor kernels
// Zero dependencies — no GGML, no CRT math required
// ============================================================================
#pragma once
#include <cstddef>
#include <cstdint>

// ============================================================================
// Inference Context (matches MASM layout)
// Layout must match the MASM struct exactly
// ============================================================================
struct RawrXDInferenceCtx {
    // KV cache (offsets 0, 8, 16)
    float* kv_cache_k = nullptr;
    float* kv_cache_v = nullptr;
    size_t kv_cache_size = 0;
    
    // Padding to align next fields
    size_t _pad1[3] = {};
    
    // Model weights (offset 24)
    float* tok_embeddings = nullptr;
    float* output_weights = nullptr;
    float* norm_weights = nullptr;
    
    // Padding
    size_t _pad2[3] = {};
    
    // Per-layer weights (32 layers max) - offset 48
    float* layer_norm_1[32] = {};
    float* layer_norm_2[32] = {};
    float* wq[32] = {};
    float* wk[32] = {};
    float* wv[32] = {};
    float* wo[32] = {};
    float* w1[32] = {};
    float* w2[32] = {};
    float* w3[32] = {};
    
    // Hyperparameters - offset 64
    int n_vocab = 32000;
    int n_embd = 4096;
    int n_head = 32;
    int n_layer = 32;
    int n_ff = 11008;
    int n_rot = 128;
    int head_dim = 128;
    int n_ctx = 4096;
    
    // State
    int n_past = 0;
    int initialized = 0;
    
    // Scratch buffer
    float* scratch = nullptr;
    size_t scratch_size = 0;
};

// ============================================================================
// MASM Kernel Declarations (extern "C" — Microsoft x64 calling convention)
// ============================================================================
extern "C" {

// --- Math Kernels (from rawrxd_math_masm.asm) ---
float rawrxd_dot_f32(const float* a, const float* b, size_t n);
void rawrxd_matvec_f32(const float* mat, const float* vec, float* out,
                       size_t rows, size_t cols);
void rawrxd_matmul_f32(const float* A, const float* B, float* C,
                        size_t M, size_t N, size_t K);
void rawrxd_rms_norm_f32(float* out, const float* x, const float* weight,
                         size_t n, float eps);
void rawrxd_softmax_f32(float* x, size_t n);
void rawrxd_silu_f32(float* out, const float* x, size_t n);
void rawrxd_rope_f32(float* data, int n_past, int n_dims, int n_rot,
                     int n_tokens, float theta_base);
void rawrxd_add_f32(float* c, const float* a, const float* b, size_t n);
void rawrxd_scale_f32(float* y, const float* x, float scale, size_t n);
void rawrxd_copy_f32(float* dst, const float* src, size_t n);
void rawrxd_set_zero_f32(float* data, size_t n);

// --- Transformer Kernels (from rawrxd_transformer_masm_fixed.asm) ---
void rawrxd_transformer_layer(
    float* hidden,
    const float* wq, const float* wk, const float* wv, const float* wo,
    const float* w1, const float* w2, const float* w3,
    const float* norm1, const float* norm2,
    float* kv_cache_k, float* kv_cache_v,
    int n_embd, int n_head, int n_ff, int n_rot, int n_past,
    float* scratch);

void rawrxd_forward_token(float* logits, int token_id, RawrXDInferenceCtx* ctx);

// --- KV Cache (from rawrxd_transformer_masm_fixed.asm) ---
int rawrxd_kv_cache_alloc(RawrXDInferenceCtx* ctx, int n_layer, int n_ctx, int n_embd);
void rawrxd_kv_cache_free(RawrXDInferenceCtx* ctx);
void rawrxd_kv_cache_reset(RawrXDInferenceCtx* ctx);

// --- Sampling (from rawrxd_transformer_masm_fixed.asm) ---
int rawrxd_sample_top_k(const float* logits, int n_vocab, int k, float temp);

} // extern "C"
