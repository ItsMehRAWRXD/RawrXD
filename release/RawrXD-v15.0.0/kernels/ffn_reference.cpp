/**
 * @file ffn_reference.cpp
 * @brief RawrXD L4.4 FFN Reference Implementation
 *
 * Portable, correct feed-forward network implementation.
 * Used for validation of optimized kernels.
 *
 * @copyright RawrXD 2026
 */

#include "ffn_contracts.h"
#include <cmath>
#include <cstring>

namespace rawrxd {
namespace ffn {

// ============================================================================
// Activation Functions
// ============================================================================

void ReLU(float* data, uint32_t count) {
    for (uint32_t i = 0; i < count; ++i) {
        data[i] = std::max(0.0f, data[i]);
    }
}

void GELU(float* data, uint32_t count) {
    // GELU(x) = x * Φ(x) where Φ is CDF of standard normal
    // Approximation: 0.5 * x * (1 + tanh(√(2/π) * (x + 0.044715 * x³)))
    const float sqrt_2_over_pi = 0.7978845608f;
    const float coeff = 0.044715f;
    
    for (uint32_t i = 0; i < count; ++i) {
        float x = data[i];
        float x3 = x * x * x;
        float inner = sqrt_2_over_pi * (x + coeff * x3);
        data[i] = 0.5f * x * (1.0f + std::tanh(inner));
    }
}

void SiLU(float* data, uint32_t count) {
    // SiLU(x) = x * sigmoid(x)
    for (uint32_t i = 0; i < count; ++i) {
        float x = data[i];
        data[i] = x / (1.0f + std::exp(-x));
    }
}

void Sigmoid(float* data, uint32_t count) {
    for (uint32_t i = 0; i < count; ++i) {
        float x = data[i];
        data[i] = 1.0f / (1.0f + std::exp(-x));
    }
}

// ============================================================================
// Matrix Operations
// ============================================================================

static void MatrixVectorMultiply(
    const float* matrix,
    const float* vector,
    float* output,
    uint32_t rows,
    uint32_t cols
) {
    // output[rows] = matrix[rows, cols] @ vector[cols]
    for (uint32_t r = 0; r < rows; ++r) {
        double sum = 0.0;
        for (uint32_t c = 0; c < cols; ++c) {
            sum += static_cast<double>(matrix[r * cols + c]) * 
                   static_cast<double>(vector[c]);
        }
        output[r] = static_cast<float>(sum);
    }
}

static void MatrixVectorMultiplyTransposed(
    const float* matrix,
    const float* vector,
    float* output,
    uint32_t rows,
    uint32_t cols
) {
    // output[cols] = matrix[rows, cols].T @ vector[rows]
    for (uint32_t c = 0; c < cols; ++c) {
        double sum = 0.0;
        for (uint32_t r = 0; r < rows; ++r) {
            sum += static_cast<double>(matrix[r * cols + c]) * 
                   static_cast<double>(vector[r]);
        }
        output[c] = static_cast<float>(sum);
    }
}

// ============================================================================
// FFN Implementation
// ============================================================================

bool ExecuteFFNReference(
    const FFNConfig& config,
    const FFNInputs& inputs,
    const FFNWeights& weights,
    FFNOutputs& outputs
) {
    if (!config.IsValid()) return false;
    if (!inputs.hidden_state.IsValid()) return false;
    if (!outputs.output.IsValid()) return false;
    
    const uint32_t batch_size = inputs.batch_size;
    const uint32_t hidden_dim = config.hidden_dim;
    const uint32_t ffn_dim = config.ffn_dim;
    
    // Allocate intermediate buffer
    std::vector<float> intermediate(ffn_dim);
    std::vector<float> gate_values(config.is_gated() ? ffn_dim : 0);
    
    for (uint32_t b = 0; b < batch_size; ++b) {
        const float* input_row = inputs.hidden_state.data + b * hidden_dim;
        float* output_row = outputs.output.data + b * hidden_dim;
        
        if (config.is_gated()) {
            // Gated FFN: SwiGLU or GeGLU
            // Step 1: Compute gate projection
            MatrixVectorMultiply(
                weights.gate_proj.data,
                input_row,
                gate_values.data(),
                ffn_dim,
                hidden_dim
            );
            
            // Step 2: Apply activation to gate
            switch (config.activation) {
                case FFNConfig::Activation::SWIGLU:
                    SiLU(gate_values.data(), ffn_dim);
                    break;
                case FFNConfig::Activation::GEGLU:
                    GELU(gate_values.data(), ffn_dim);
                    break;
                default:
                    break;
            }
            
            // Step 3: Compute up projection
            MatrixVectorMultiply(
                weights.up_proj.data,
                input_row,
                intermediate.data(),
                ffn_dim,
                hidden_dim
            );
            
            // Step 4: Element-wise multiply gate * up
            for (uint32_t i = 0; i < ffn_dim; ++i) {
                intermediate[i] *= gate_values[i];
            }
            
        } else {
            // Standard FFN
            // Step 1: up_proj: [hidden_dim] -> [ffn_dim]
            MatrixVectorMultiply(
                weights.up_proj.data,
                input_row,
                intermediate.data(),
                ffn_dim,
                hidden_dim
            );
            
            // Step 2: Apply activation
            switch (config.activation) {
                case FFNConfig::Activation::RELU:
                    ReLU(intermediate.data(), ffn_dim);
                    break;
                case FFNConfig::Activation::GELU:
                    GELU(intermediate.data(), ffn_dim);
                    break;
                case FFNConfig::Activation::SILU:
                    SiLU(intermediate.data(), ffn_dim);
                    break;
                default:
                    break;
            }
        }
        
        // Step 3: down_proj: [ffn_dim] -> [hidden_dim]
        MatrixVectorMultiplyTransposed(
            weights.down_proj.data,
            intermediate.data(),
            output_row,
            ffn_dim,
            hidden_dim
        );
    }
    
    return true;
}

// ============================================================================
// Validation
// ============================================================================

bool ValidateFFN(
    const FFNConfig& config,
    const FFNInputs& inputs,
    const FFNWeights& weights,
    const FFNOutputs& outputs,
    std::vector<std::string>* out_errors
) {
    bool valid = true;
    
    if (!config.IsValid()) {
        if (out_errors) out_errors->push_back("Invalid FFN config");
        valid = false;
    }
    
    if (!inputs.hidden_state.IsValid()) {
        if (out_errors) out_errors->push_back("Invalid input hidden_state");
        valid = false;
    }
    
    if (!outputs.output.IsValid()) {
        if (out_errors) out_errors->push_back("Invalid output");
        valid = false;
    }
    
    if (!weights.IsValid(config)) {
        if (out_errors) out_errors->push_back("Invalid weights");
        valid = false;
    }
    
    return valid;
}

ValidationResult ValidateFFNOutputs(
    const FFNOutputs& test,
    const FFNOutputs& reference
) {
    ValidationResult result;
    
    if (!test.output.IsValid() || !reference.output.IsValid()) {
        result.AddError("Invalid output tensors");
        return result;
    }
    
    // Compute cosine similarity
    double dot = 0.0;
    double norm_test = 0.0;
    double norm_ref = 0.0;
    double max_error = 0.0;
    double sum_sq_error = 0.0;
    
    for (uint32_t i = 0; i < test.output.total_elements; ++i) {
        float t = test.output.data[i];
        float r = reference.output.data[i];
        
        dot += t * r;
        norm_test += t * t;
        norm_ref += r * r;
        
        float err = std::abs(t - r);
        max_error = std::max(max_error, static_cast<double>(err));
        sum_sq_error += err * err;
    }
    
    result.cosine_similarity = (norm_test > 0 && norm_ref > 0) ?
        static_cast<float>(dot / std::sqrt(norm_test * norm_ref)) : 0.0f;
    result.max_absolute_error = static_cast<float>(max_error);
    result.rmse = static_cast<float>(std::sqrt(sum_sq_error / test.output.total_elements));
    result.passed = result.IsPassing();
    
    return result;
}

// ============================================================================
// Utilities
// ============================================================================

const char* FFNConfig::ActivationName() const {
    switch (activation) {
        case Activation::RELU: return "ReLU";
        case Activation::GELU: return "GELU";
        case Activation::SILU: return "SiLU";
        case Activation::SWIGLU: return "SwiGLU";
        case Activation::GEGLU: return "GeGLU";
        default: return "Unknown";
    }
}

bool FFNWeights::IsValid(const FFNConfig& config) const {
    if (!up_proj.IsValid() || !down_proj.IsValid()) return false;
    
    if (config.is_gated()) {
        if (!gate_proj.IsValid()) return false;
    }
    
    return true;
}

void PrintFFNConfig(const FFNConfig& config) {
    std::cout << "FFNConfig:\n";
    std::cout << "  Hidden dim: " << config.hidden_dim << "\n";
    std::cout << "  FFN dim: " << config.ffn_dim << "\n";
    std::cout << "  Activation: " << config.ActivationName() << "\n";
    std::cout << "  Gated: " << (config.is_gated() ? "yes" : "no") << "\n";
}

uint64_t CalculateFFNFLOPs(const FFNConfig& config, uint32_t batch_size) {
    // FFN FLOPs: 2 * hidden_dim * ffn_dim per token (for standard)
    // Gated: 3 * hidden_dim * ffn_dim per token
    uint64_t mults = config.is_gated() ? 3 : 2;
    return mults * batch_size * config.hidden_dim * config.ffn_dim;
}

uint64_t CalculateFFNMemory(const FFNConfig& config) {
    // Weight memory: (2 or 3) * hidden_dim * ffn_dim * sizeof(float)
    uint64_t matrices = config.is_gated() ? 3 : 2;
    return matrices * config.hidden_dim * config.ffn_dim * sizeof(float);
}

} // namespace ffn
} // namespace rawrxd
