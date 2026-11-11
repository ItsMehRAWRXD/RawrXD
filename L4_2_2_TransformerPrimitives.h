// L4_2_2_TransformerPrimitives.h
// L4.2.2 Transformer Block Primitives
// Reference implementations for RMSNorm, RoPE, Attention, FFN

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <cmath>

namespace RawrXD {
namespace L4 {

// ============================================================================
// RMS Normalization
// ============================================================================
// Root Mean Square Layer Normalization
// Used in Llama/Mistral architectures
//
// Formula: rms_norm(x) = x / sqrt(mean(x^2) + epsilon) * weight

struct RMSNormConfig {
    float epsilon = 1e-6f;
    size_t hidden_size = 4096;
};

// Reference RMSNorm implementation
// x: input vector (hidden_size elements)
// weight: learned scale parameters (hidden_size elements)
// output: normalized output (hidden_size elements)
void RMSNorm_Reference(
    const float* x,
    const float* weight,
    float* output,
    const RMSNormConfig& config
);

// ============================================================================
// RoPE (Rotary Positional Embedding)
// ============================================================================
// Applies rotary positional embeddings to query and key vectors
// Used in Llama/Mistral for better long-context modeling
//
// Formula (simplified):
//   [x0, x1] * [cos(m*theta), -sin(m*theta)]
//   [x2, x3]   [sin(m*theta),  cos(m*theta)]
// where m = position, theta = base^(2i/d)

struct RoPEConfig {
    size_t head_dim = 128;      // Dimension per attention head
    size_t num_heads = 32;      // Number of attention heads
    float theta_base = 10000.0f; // Base for frequency computation
    size_t max_position = 8192; // Maximum sequence length
};

// Precompute RoPE frequency tables
// Returns cos and sin tables for all positions and dimensions
struct RoPETables {
    std::vector<float> cos_table;  // [max_position * head_dim]
    std::vector<float> sin_table;  // [max_position * head_dim]
};

RoPETables PrecomputeRoPE(const RoPEConfig& config);

// Apply RoPE to query and key tensors
// q: query tensor [num_heads, head_dim] - modified in place
// k: key tensor [num_heads, head_dim] - modified in place
// position: current token position in sequence
void ApplyRoPE_Reference(
    float* q,
    float* k,
    size_t position,
    const RoPEConfig& config,
    const RoPETables& tables
);

// ============================================================================
// Attention
// ============================================================================
// Multi-head self-attention
// Q, K, V are already projected and have RoPE applied

struct AttentionConfig {
    size_t num_heads = 32;
    size_t head_dim = 128;
    size_t num_kv_heads = 8;  // For GQA (Grouped Query Attention)
    float scale = 0.0f;       // 1/sqrt(head_dim), computed if 0
};

// Compute attention scores and output
// q: [num_heads, head_dim] - query (with RoPE)
// k_cache: [num_kv_heads, seq_len, head_dim] - cached keys
// v_cache: [num_kv_heads, seq_len, head_dim] - cached values
// seq_len: current sequence length (including current token)
// output: [num_heads, head_dim] - attention output
void Attention_Reference(
    const float* q,
    const float* k_cache,
    const float* v_cache,
    float* output,
    size_t seq_len,
    const AttentionConfig& config
);

// Softmax function (used in attention)
// input/output: [num_heads, seq_len] - attention scores
void Softmax_Reference(
    float* data,
    size_t num_heads,
    size_t seq_len
);

// ============================================================================
// FFN (Feed-Forward Network)
// ============================================================================
// Llama/Mistral-style SwiGLU FFN
//
// Formula:
//   gate = W_gate * x
//   up = W_up * x
//   hidden = SiLU(gate) * up
//   output = W_down * hidden

struct FFNConfig {
    size_t hidden_size = 4096;
    size_t intermediate_size = 14336; // 3.5x hidden_size for Llama-3
};

// SiLU activation (Sigmoid Linear Unit)
// SiLU(x) = x * sigmoid(x)
float SiLU(float x);

// Reference FFN implementation
// x: input [hidden_size]
// w_gate: [intermediate_size, hidden_size]
// w_up: [intermediate_size, hidden_size]
// w_down: [hidden_size, intermediate_size]
// output: [hidden_size]
void FFN_Reference(
    const float* x,
    const float* w_gate,
    const float* w_up,
    const float* w_down,
    float* output,
    const FFNConfig& config
);

// ============================================================================
// Complete Transformer Layer
// ============================================================================
// NOTE: TransformerLayerConfig is defined in L4_2_2_5_TransformerLayer.h
// to avoid circular dependencies and ensure single source of truth.

// Forward declaration
struct TransformerLayerConfig;

// ============================================================================
// Validation Helpers
// ============================================================================

// Compare two tensors with tolerance
struct TensorComparisonResult {
    bool passed;
    float max_error;
    float mean_error;
    float rmse;
    size_t first_mismatch_idx;
};

TensorComparisonResult CompareTensors(
    const float* reference,
    const float* actual,
    size_t count,
    float tolerance = 1e-4f
);

} // namespace L4
} // namespace RawrXD
