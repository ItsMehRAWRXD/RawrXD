#pragma once

#include "TensorView.hpp"

#include <cstdint>
#include <vector>

namespace deep2 {

// Dequantize a raw TensorView into contiguous f32 memory.
// Logical shape = reverse of GGUF on-disk dim order.
// Returns false for unsupported types.
bool dequantizeTensor(const TensorView& src, DequantizedTensor& dst);

// Row-major GEMV: y[rows] = W[rows][cols] * x[cols].
bool gemvFloat(const float* W, const float* x, float* y,
               std::uint64_t rows, std::uint64_t cols);

// NOTE: Q2_K/Q3_K_S/Q4_K/Q6_K block layouts below are the ggml K-quant block
// formats (qs + per-group scales + fp16 super-scale d). The exact per-group
// scale normalization and zero point for the minor K-types cannot be derived
// from the file itself; they are empirical hypotheses (H1) validated by running
// Phi-3 end-to-end. Wrong parameters produce immediate garbage output, which
// makes them fast to detect and correct.
struct QuantLayoutH1 {
    // Q4_K_S: per-group scale = d * scales[g] / 32.0f, value = (nibble - 8) * scale
    static constexpr float Q4K_SCALE_DIV = 32.0f;
    static constexpr float Q4K_ZERO_POINT = 8.0f;
    // Q2_K: per-group scale = d * scales[g] / 64.0f, value = (q - 1.5) * scale
    static constexpr float Q2K_SCALE_DIV = 64.0f;
    static constexpr float Q2K_ZERO_POINT = 1.5f;
    // Q3_K_S: per-group scale = d * scales[g] / 32.0f, value = (q - 4) * scale
    static constexpr float Q3K_SCALE_DIV = 32.0f;
    static constexpr float Q3K_ZERO_POINT = 4.0f;
    // Q6_K: per-group scale = d * scales[g] / 32.0f, value = (q - 32) * scale
    static constexpr float Q6K_SCALE_DIV = 32.0f;
    static constexpr float Q6K_ZERO_POINT = 32.0f;
};

} // namespace deep2
