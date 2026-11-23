#pragma once
// GGML Q8_0 packed dot product. Keeps the weight tensor in 34-byte blocks.
// Layout: IEEE binary16 scale followed by 32 signed 8-bit quantized weights.
#include "native_q4_0_dot.hpp"
#include <cstddef>
#include <cstdint>
#include <stdexcept>
namespace RawrXD::Compression {
inline float q8_0_dot(const PackedTensorView& weights, const float* x, size_t x_count) {
    if (!x || weights.elements != x_count ||
        weights.elements_per_block != 32 || weights.bytes_per_block != 34)
        throw std::invalid_argument("Q8_0 shape or format mismatch");
    const auto blocks = weights.block_count();
    float sum = 0.0f;
    for (uint64_t b = 0; b < blocks; ++b) {
        const uint8_t* p = weights.block(b);
        const uint16_t half = uint16_t(p[0]) | (uint16_t(p[1]) << 8);
        const float scale = ggml_half_to_float(half);
        const float* v = x + static_cast<size_t>(b) * 32;
        for (size_t j = 0; j < 32; ++j) {
            const int q = p[2 + j] < 128 ? int(p[2 + j]) : int(p[2 + j]) - 256;
            sum += scale * float(q) * v[j];
        }
    }
    return sum;
}
} // namespace RawrXD::Compression
