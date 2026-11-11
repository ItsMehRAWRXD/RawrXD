//============================================================================
// nevm_kernels.hpp
// RawrXD N-EVM Transformer Kernel Suite
// Complete primitive coverage for transformer execution
//============================================================================

#pragma once

#include "nevm_core.hpp"
#include "nevm_isa.hpp"
#include <cmath>

namespace RawrXD {
namespace NEVM {
namespace Kernels {

//============================================================================
// Kernel Dispatch Interface
// All kernels use virtual tensor addresses
//============================================================================

using ISA::VirtualTensorAddress;
using ISA::PrecisionMode;

//============================================================================
// 1. Embedding
//============================================================================

// Token embedding lookup
// input: token_ids [batch, seq_len]
// weight: embedding_matrix [vocab_size, hidden_dim]
// output: embeddings [batch, seq_len, hidden_dim]
bool Embedding_Lookup(const int32_t* token_ids,
                       uint32_t batch_size,
                       uint32_t seq_len,
                       VirtualTensorAddress weight_vta,
                       float* output,
                       uint32_t vocab_size,
                       uint32_t hidden_dim);

// Position encoding (RoPE pre-computed)
bool PositionEncoding_RoPE(float* q, float* k,
                            uint32_t seq_len,
                            uint32_t head_dim,
                            uint32_t num_heads,
                            uint32_t max_seq_len);

//============================================================================
// 2. RMSNorm
//============================================================================

// Root Mean Square Layer Normalization
// x' = x / sqrt(mean(x^2) + epsilon) * weight
bool RMSNorm_Forward(const float* input,
                      float* output,
                      VirtualTensorAddress weight_vta,
                      uint32_t batch_size,
                      uint32_t hidden_dim,
                      float epsilon = 1e-6f);

// In-place variant
bool RMSNorm_InPlace(float* data,
                      VirtualTensorAddress weight_vta,
                      uint32_t batch_size,
                      uint32_t hidden_dim,
                      float epsilon = 1e-6f);

//============================================================================
// 3. RoPE (Rotary Position Embedding)
//============================================================================

// Apply rotary embeddings to Q and K
// Uses pre-computed sin/cos tables
bool RoPE_Apply(float* q, float* k,
                 const float* sin_table,
                 const float* cos_table,
                 uint32_t seq_len,
                 uint32_t num_heads,
                 uint32_t head_dim);

// Pre-compute sin/cos tables
bool RoPE_Precompute(float* sin_table,
                      float* cos_table,
                      uint32_t max_seq_len,
                      uint32_t head_dim,
                      float base = 10000.0f);

//============================================================================
// 4. QKV Projection
//============================================================================

// Combined QKV projection
// input: [batch, seq_len, hidden_dim]
// weight_q/k/v: [hidden_dim, hidden_dim]
// output_q/k/v: [batch, seq_len, hidden_dim]
bool QKV_Projection(const float* input,
                     float* output_q,
                     float* output_k,
                     float* output_v,
                     VirtualTensorAddress weight_q_vta,
                     VirtualTensorAddress weight_k_vta,
                     VirtualTensorAddress weight_v_vta,
                     uint32_t batch_size,
                     uint32_t seq_len,
                     uint32_t hidden_dim);

// Fused QKV with precision selection
bool QKV_Projection_Fused(const float* input,
                            float* output_q,
                            float* output_k,
                            float* output_v,
                            VirtualTensorAddress weight_vta,  // Combined weight
                            uint32_t batch_size,
                            uint32_t seq_len,
                            uint32_t hidden_dim,
                            PrecisionMode precision);

//============================================================================
// 5. Attention
//============================================================================

// Scaled dot-product attention
// Q: [batch, num_heads, seq_len, head_dim]
// K: [batch, num_heads, seq_len, head_dim]
// V: [batch, num_heads, seq_len, head_dim]
// output: [batch, num_heads, seq_len, head_dim]
bool Attention_Forward(const float* q,
                        const float* k,
                        const float* v,
                        float* output,
                        float* softmax_buffer,
                        uint32_t batch_size,
                        uint32_t num_heads,
                        uint32_t seq_len,
                        uint32_t head_dim,
                        float scale = 0.0f);  // 0 = auto-compute

// Flash Attention variant (memory-efficient)
bool Attention_Flash(const float* q,
                       const float* k,
                       const float* v,
                       float* output,
                       uint32_t batch_size,
                       uint32_t num_heads,
                       uint32_t seq_len,
                       uint32_t head_dim,
                       uint32_t block_size = 128);

// KV-cache aware attention (for generation)
bool Attention_WithKVCache(const float* q,
                              const float* k_cache,
                              const float* v_cache,
                              float* output,
                              uint32_t batch_size,
                              uint32_t num_heads,
                              uint32_t seq_len,
                              uint32_t cache_len,
                              uint32_t head_dim);

//============================================================================
// 6. Softmax
//============================================================================

// Numerically stable softmax
// input/output: [batch, heads, seq_len, seq_len]
bool Softmax_Forward(const float* input,
                      float* output,
                      uint32_t batch_size,
                      uint32_t num_heads,
                      uint32_t seq_len);

// Softmax with temperature scaling
bool Softmax_Temperature(const float* input,
                            float* output,
                            uint32_t batch_size,
                            uint32_t num_heads,
                            uint32_t seq_len,
                            float temperature);

//============================================================================
// 7. FFN / SwiGLU
//============================================================================

// SwiGLU activation: Swish(xW + b) * (xV + c)
bool SwiGLU_Forward(const float* input,
                     float* output,
                     VirtualTensorAddress gate_weight_vta,
                     VirtualTensorAddress up_weight_vta,
                     VirtualTensorAddress down_weight_vta,
                     uint32_t batch_size,
                     uint32_t seq_len,
                     uint32_t hidden_dim,
                     uint32_t ffn_dim);

// FFN with GELU (alternative)
bool FFN_GELU(const float* input,
               float* output,
               VirtualTensorAddress w1_vta,
               VirtualTensorAddress w2_vta,
               uint32_t batch_size,
               uint32_t seq_len,
               uint32_t hidden_dim,
               uint32_t ffn_dim);

//============================================================================
// 8. Output Projection
//============================================================================

// Final LM head projection
// hidden: [batch, seq_len, hidden_dim]
// weight: [vocab_size, hidden_dim]
// logits: [batch, seq_len, vocab_size]
bool OutputProjection(const float* hidden,
                       float* logits,
                       VirtualTensorAddress weight_vta,
                       uint32_t batch_size,
                       uint32_t seq_len,
                       uint32_t hidden_dim,
                       uint32_t vocab_size);

// Top-k sampling preparation
bool Logits_TopK(const float* logits,
                  float* topk_values,
                  int32_t* topk_indices,
                  uint32_t batch_size,
                  uint32_t vocab_size,
                  uint32_t k);

//============================================================================
// 9. Sampling
//============================================================================

// Greedy sampling (argmax)
bool Sample_Greedy(const float* logits,
                    int32_t* output_tokens,
                    uint32_t batch_size,
                    uint32_t vocab_size);

// Temperature sampling
bool Sample_Temperature(const float* logits,
                          int32_t* output_tokens,
                          uint32_t batch_size,
                          uint32_t vocab_size,
                          float temperature,
                          uint64_t random_seed);

// Top-p (nucleus) sampling
bool Sample_TopP(const float* logits,
                   int32_t* output_tokens,
                   uint32_t batch_size,
                   uint32_t vocab_size,
                   float top_p,
                   float temperature,
                   uint64_t random_seed);

// Top-k + Top-p combined
bool Sample_TopK_TopP(const float* logits,
                        int32_t* output_tokens,
                        uint32_t batch_size,
                        uint32_t vocab_size,
                        uint32_t top_k,
                        float top_p,
                        float temperature,
                        uint64_t random_seed);

//============================================================================
// 10. KV Cache Management
//============================================================================

// Append new K,V to cache
bool KVCache_Append(float* k_cache,
                     float* v_cache,
                     const float* new_k,
                     const float* new_v,
                     uint32_t cache_pos,
                     uint32_t batch_size,
                     uint32_t num_heads,
                     uint32_t head_dim);

// Trim cache to max length (sliding window)
bool KVCache_Slide(float* k_cache,
                    float* v_cache,
                    uint32_t* cache_len,
                    uint32_t max_len,
                    uint32_t batch_size,
                    uint32_t num_heads,
                    uint32_t head_dim);

//============================================================================
// 11. Complete Transformer Layer
//============================================================================

// Full transformer layer execution
// Pre-norm architecture:
//   x = x + Attention(RMSNorm(x))
//   x = x + FFN(RMSNorm(x))
bool TransformerLayer_Forward(const float* input,
                                 float* output,
                                 float* residual_buffer,
                                 float* norm_buffer,
                                 float* qkv_buffer,
                                 float* attn_buffer,
                                 float* ffn_buffer,
                                 VirtualTensorAddress layer_weights,  // All weights for layer
                                 uint32_t batch_size,
                                 uint32_t seq_len,
                                 uint32_t hidden_dim,
                                 uint32_t num_heads,
                                 uint32_t ffn_dim,
                                 PrecisionMode precision);

//============================================================================
// 12. Quantization Error Tracking
//============================================================================

// Track per-block quantization error
struct QuantizationError {
    float max_error;
    float mean_error;
    float std_error;
    uint32_t samples;
};

bool TrackQuantizationError(const float* fp32_output,
                             const float* quantized_output,
                             uint32_t count,
                             QuantizationError* out_error);

// Update precision controller with error feedback
bool UpdatePrecisionFromError(VirtualTensorAddress vta,
                               const QuantizationError& error,
                               float threshold);

//============================================================================
// Kernel Statistics
//============================================================================

struct KernelStats {
    uint64_t calls;
    uint64_t total_cycles;
    uint64_t bytes_read;
    uint64_t bytes_written;
    float avg_latency_ms;
    float min_latency_ms;
    float max_latency_ms;
};

void ResetKernelStats();
KernelStats GetKernelStats(const char* kernel_name);

} // namespace Kernels
} // namespace NEVM
} // namespace RawrXD
