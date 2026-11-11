/**
 * @file ffn_contracts.h
 * @brief RawrXD L4.4 FFN Contracts
 *
 * Feed-Forward Network contracts and reference implementation.
 * Completes the transformer block primitive set.
 *
 * @copyright RawrXD 2026
 */

#pragma once

#include "attention_contracts.h"

namespace rawrxd {
namespace ffn {

// ============================================================================
// FFN Configuration
// ============================================================================

/**
 * @brief Feed-Forward Network configuration
 *
 * Standard transformer FFN: Linear -> Activation -> Linear
 * With optional gating (SwiGLU, GeGLU, etc.)
 */
struct FFNConfig {
    uint32_t hidden_dim;            // Input/output dimension (model dim)
    uint32_t ffn_dim;             // Intermediate dimension (typically 4x hidden)
    
    // Activation function
    enum class Activation {
        RELU,
        GELU,
        SILU,                     // Swish
        SWIGLU,                   // Gated: Swish + GLU
        GEGLU                     // Gated: GELU + GLU
    };
    Activation activation = Activation::SWIGLU;
    
    // Gated FFN (SwiGLU/GeGLU) uses 3 matrices instead of 2
    bool is_gated() const {
        return activation == Activation::SWIGLU || 
               activation == Activation::GEGLU;
    }
    
    // Validation
    bool IsValid() const {
        return hidden_dim > 0 && ffn_dim > 0;
    }
    
    // Get activation name
    const char* ActivationName() const;
};

// ============================================================================
// FFN Weights
// ============================================================================

/**
 * @brief FFN weight tensors
 *
 * Layout:
 *   Standard:  up_proj [hidden_dim, ffn_dim], down_proj [ffn_dim, hidden_dim]
 *   Gated:     gate_proj [hidden_dim, ffn_dim], up_proj [hidden_dim, ffn_dim], down_proj [ffn_dim, hidden_dim]
 */
struct FFNWeights {
    // For standard FFN
    TensorView up_proj;           // [hidden_dim, ffn_dim] or [ffn_dim, hidden_dim] depending on layout
    TensorView down_proj;         // [ffn_dim, hidden_dim] or [hidden_dim, ffn_dim]
    
    // For gated FFN (SwiGLU, GeGLU)
    TensorView gate_proj;         // [hidden_dim, ffn_dim] - gating weights
    
    // Compression type for quantized weights
    compression::CompressionType codec = compression::CompressionType::FP32;
    
    // Validation
    bool IsValid(const FFNConfig& config) const;
};

// ============================================================================
// FFN Inputs/Outputs
// ============================================================================

/**
 * @brief FFN operation inputs
 */
struct FFNInputs {
    TensorView hidden_state;      // [batch, hidden_dim] - input from attention or previous layer
    uint32_t batch_size = 1;
};

/**
 * @brief FFN operation outputs
 */
struct FFNOutputs {
    TensorView output;            // [batch, hidden_dim] - FFN output
    
    // Optional intermediate activations for analysis
    TensorView intermediate;      // [batch, ffn_dim] - post-activation (optional)
};

// ============================================================================
// FFN Interface
// ============================================================================

/**
 * @brief Execute FFN
 *
 * Standard:  output = down_proj(activation(up_proj(input)))
 * Gated:     output = down_proj(activation(gate_proj(input)) * up_proj(input))
 */
bool ExecuteFFN(
    const FFNConfig& config,
    const FFNInputs& inputs,
    const FFNWeights& weights,
    FFNOutputs& outputs
);

/**
 * @brief Reference FFN implementation
 *
 * Portable, correct, unoptimized.
 */
bool ExecuteFFNReference(
    const FFNConfig& config,
    const FFNInputs& inputs,
    const FFNWeights& weights,
    FFNOutputs& outputs
);

// ============================================================================
// Activation Functions
// ============================================================================

// ReLU: max(0, x)
void ReLU(float* data, uint32_t count);

// GELU: x * Φ(x) where Φ is CDF of standard normal
void GELU(float* data, uint32_t count);

// SiLU (Swish): x * sigmoid(x)
void SiLU(float* data, uint32_t count);

// Sigmoid: 1 / (1 + exp(-x))
void Sigmoid(float* data, uint32_t count);

// ============================================================================
// Validation
// ============================================================================

/**
 * @brief Validate FFN configuration and inputs
 */
bool ValidateFFN(
    const FFNConfig& config,
    const FFNInputs& inputs,
    const FFNWeights& weights,
    const FFNOutputs& outputs,
    std::vector<std::string>* out_errors = nullptr
);

/**
 * @brief Compare FFN outputs
 */
ValidationResult ValidateFFNOutputs(
    const FFNOutputs& test,
    const FFNOutputs& reference
);

// ============================================================================
// Utilities
// ============================================================================

// Print FFN config
void PrintFFNConfig(const FFNConfig& config);

// Calculate FFN FLOPs
uint64_t CalculateFFNFLOPs(const FFNConfig& config, uint32_t batch_size);

// Calculate FFN memory usage
uint64_t CalculateFFNMemory(const FFNConfig& config);

} // namespace ffn
} // namespace rawrxd
