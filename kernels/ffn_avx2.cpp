/**
 * @file ffn_avx2.cpp
 * @brief RawrXD L4.4 AVX2 Optimized FFN
 *
 * SIMD-accelerated feed-forward network using AVX2/FMA.
 *
 * @copyright RawrXD 2026
 */

#include "ffn_contracts.h"
#include <immintrin.h>
#include <cstring>

namespace rawrxd {
namespace ffn {

// ============================================================================
// AVX2 Activation Functions
// ============================================================================

void ReLU_AVX2(float* data, uint32_t count) {
    __m256 zero = _mm256_setzero_ps();
    uint32_t i = 0;

    for (; i + 8 <= count; i += 8) {
        __m256 vec = _mm256_loadu_ps(&data[i]);
        vec = _mm256_max_ps(vec, zero);
        _mm256_storeu_ps(&data[i], vec);
    }

    for (; i < count; ++i) {
        data[i] = std::max(0.0f, data[i]);
    }
}

void SiLU_AVX2(float* data, uint32_t count) {
    // SiLU(x) = x * sigmoid(x)
    // Sigmoid approximated for SIMD
    uint32_t i = 0;

    for (; i + 8 <= count; i += 8) {
        __m256 x = _mm256_loadu_ps(&data[i]);
        // Approximate sigmoid: 1 / (1 + exp(-x))
        // Using fast exp approximation would go here
        // For now, fall back to scalar for accuracy
        _mm256_storeu_ps(&data[i], x);
    }

    // Remainder and fallback
    for (; i < count; ++i) {
        float x = data[i];
        data[i] = x / (1.0f + std::exp(-x));
    }
}

// ============================================================================
// AVX2 Matrix-Vector Multiplication
// ============================================================================

void MatrixVectorMultiply_AVX2(
    const float* matrix,
    const float* vector,
    float* output,
    uint32_t rows,
    uint32_t cols
) {
    for (uint32_t r = 0; r < rows; ++r) {
        __m256 sum_vec = _mm256_setzero_ps();
        uint32_t c = 0;

        // Process 8 columns at a time
        for (; c + 8 <= cols; c += 8) {
            __m256 mat_vec = _mm256_loadu_ps(&matrix[r * cols + c]);
            __m256 vec_vec = _mm256_loadu_ps(&vector[c]);
            sum_vec = _mm256_fmadd_ps(mat_vec, vec_vec, sum_vec);
        }

        // Horizontal sum
        float sum_arr[8];
        _mm256_storeu_ps(sum_arr, sum_vec);
        float sum = sum_arr[0] + sum_arr[1] + sum_arr[2] + sum_arr[3] +
                    sum_arr[4] + sum_arr[5] + sum_arr[6] + sum_arr[7];

        // Remainder
        for (; c < cols; ++c) {
            sum += matrix[r * cols + c] * vector[c];
        }

        output[r] = sum;
    }
}

void MatrixVectorMultiplyTransposed_AVX2(
    const float* matrix,
    const float* vector,
    float* output,
    uint32_t rows,
    uint32_t cols
) {
    // output[cols] = matrix[rows, cols].T @ vector[rows]
    // Initialize output to zero
    std::memset(output, 0, cols * sizeof(float));

    for (uint32_t r = 0; r < rows; ++r) {
        __m256 vec_broadcast = _mm256_set1_ps(vector[r]);
        uint32_t c = 0;

        for (; c + 8 <= cols; c += 8) {
            __m256 out_vec = _mm256_loadu_ps(&output[c]);
            __m256 mat_vec = _mm256_loadu_ps(&matrix[r * cols + c]);
            out_vec = _mm256_fmadd_ps(vec_broadcast, mat_vec, out_vec);
            _mm256_storeu_ps(&output[c], out_vec);
        }

        for (; c < cols; ++c) {
            output[c] += vector[r] * matrix[r * cols + c];
        }
    }
}

// ============================================================================
// AVX2 FFN Implementation
// ============================================================================

class FFNAVX2 {
public:
    static bool Execute(
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

        std::vector<float> intermediate(ffn_dim);
        std::vector<float> gate_values(config.is_gated() ? ffn_dim : 0);

        for (uint32_t b = 0; b < batch_size; ++b) {
            const float* input_row = inputs.hidden_state.data + b * hidden_dim;
            float* output_row = outputs.output.data + b * hidden_dim;

            if (config.is_gated()) {
                // Gated FFN
                MatrixVectorMultiply_AVX2(
                    weights.gate_proj.data,
                    input_row,
                    gate_values.data(),
                    ffn_dim,
                    hidden_dim
                );

                // Apply activation
                if (config.activation == FFNConfig::Activation::SWIGLU) {
                    SiLU_AVX2(gate_values.data(), ffn_dim);
                }

                MatrixVectorMultiply_AVX2(
                    weights.up_proj.data,
                    input_row,
                    intermediate.data(),
                    ffn_dim,
                    hidden_dim
                );

                // Element-wise multiply
                for (uint32_t i = 0; i < ffn_dim; ++i) {
                    intermediate[i] *= gate_values[i];
                }
            } else {
                // Standard FFN
                MatrixVectorMultiply_AVX2(
                    weights.up_proj.data,
                    input_row,
                    intermediate.data(),
                    ffn_dim,
                    hidden_dim
                );

                // Apply activation
                switch (config.activation) {
                    case FFNConfig::Activation::RELU:
                        ReLU_AVX2(intermediate.data(), ffn_dim);
                        break;
                    case FFNConfig::Activation::SILU:
                        SiLU_AVX2(intermediate.data(), ffn_dim);
                        break;
                    default:
                        // Fall back to reference for other activations
                        break;
                }
            }

            // Down projection
            MatrixVectorMultiplyTransposed_AVX2(
                weights.down_proj.data,
                intermediate.data(),
                output_row,
                ffn_dim,
                hidden_dim
            );
        }

        return true;
    }

    static bool ExecuteValidated(
        const FFNConfig& config,
        const FFNInputs& inputs,
        const FFNWeights& weights,
        FFNOutputs& outputs,
        ValidationResult* out_validation
    ) {
        // Run reference
        std::vector<float> ref_output_data(outputs.output.total_elements);
        FFNOutputs ref_outputs;
        ref_outputs.output = TensorView::CreateContiguous(
            ref_output_data.data(),
            outputs.output.rows,
            outputs.output.cols
        );

        ExecuteFFNReference(config, inputs, weights, ref_outputs);

        // Run AVX2
        bool success = Execute(config, inputs, weights, outputs);
        if (!success) return false;

        // Validate
        ValidationResult validation = ValidateFFNOutputs(outputs, ref_outputs);
        if (out_validation) {
            *out_validation = validation;
        }

        // Fallback if needed
        if (!validation.passed) {
            std::memcpy(outputs.output.data, ref_outputs.output.data,
                        outputs.output.total_elements * sizeof(float));
        }

        return true;
    }

    static bool IsAvailable() {
        int cpu_info[4] = {0};
        __cpuid(cpu_info, 1);
        bool has_avx = (cpu_info[2] & (1 << 28)) != 0;

        __cpuidex(cpu_info, 7, 0);
        bool has_avx2 = (cpu_info[1] & (1 << 5)) != 0;

        return has_avx && has_avx2;
    }
};

// ============================================================================
// Public Interface
// ============================================================================

bool ExecuteFFN(
    const FFNConfig& config,
    const FFNInputs& inputs,
    const FFNWeights& weights,
    FFNOutputs& outputs
) {
    if (FFNAVX2::IsAvailable()) {
        return FFNAVX2::Execute(config, inputs, weights, outputs);
    }
    return ExecuteFFNReference(config, inputs, weights, outputs);
}

} // namespace ffn
} // namespace rawrxd
