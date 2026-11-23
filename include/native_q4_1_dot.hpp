#pragma once
// GGML Q4_1: 32 values per 20-byte block (FP16 d, FP16 m, 16 packed bytes).
#include "native_q4_0_dot.hpp"
#include <cstddef>
#include <cstdint>
#include <stdexcept>
namespace RawrXD::Compression {
inline float q4_1_dot(const PackedTensorView& weights, const float* x, size_t x_count) {
    if (!x || weights.elements != x_count ||
        weights.elements_per_block != 32 || weights.bytes_per_block != 20)
        throw std::invalid_argument("Q4_1 shape or format mismatch");
    const auto blocks = weights.block_count();
    float sum = 0.0f;
    for (uint64_t b = 0; b < blocks; ++b) {
        const uint8_t* p = weights.block(b);
        const float d = ggml_half_to_float(uint16_t(p[0]) | (uint16_t(p[1]) << 8));
        const float m = ggml_half_to_float(uint16_t(p[2]) | (uint16_t(p[3]) << 8));
        const float* v = x + static_cast<size_t>(b) * 32;
        for (size_t j = 0; j < 16; ++j) {
            const uint8_t q = p[4 + j];
            sum += (d * float(q & 15u) + m) * v[j];
            sum += (d * float(q >> 4) + m) * v[j + 16];
        }
    }
    return sum;
}
} // namespace RawrXD::Compression
