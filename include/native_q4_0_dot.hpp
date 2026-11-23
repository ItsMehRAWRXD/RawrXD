#pragma once
// GGML Q4_0 packed block dot product, without allocating an F32 weight tensor.
// Block layout: little-endian IEEE binary16 scale + 16 packed bytes for 32 weights.
// Low nibbles encode weights 0..15, high nibbles encode weights 16..31.
#include "native_packed_tensor_view.hpp"
#include <cmath>
#include <cstring>
#include <stdexcept>
namespace RawrXD::Compression {
inline float ggml_half_to_float(uint16_t h) noexcept {
    const uint32_t sign = (uint32_t(h & 0x8000u) << 16);
    const uint32_t exp = (h >> 10) & 31u;
    const uint32_t mant = h & 1023u;
    uint32_t bits = sign;
    if (exp == 31) bits |= 0x7f800000u | (mant << 13);
    else if (exp != 0) bits |= ((exp + 112u) << 23) | (mant << 13);
    else if (mant) {
        uint32_t m = mant, e = 113u;
        while ((m & 1024u) == 0) { m <<= 1; --e; }
        bits |= (e << 23) | ((m & 1023u) << 13);
    }
    float f;
    std::memcpy(&f, &bits, sizeof(f));
    return f;
}
inline float q4_0_dot(const PackedTensorView& weights, const float* x, size_t x_count) {
    if (!x || weights.elements != x_count ||
        weights.elements_per_block != 32 || weights.bytes_per_block != 18)
        throw std::invalid_argument("Q4_0 shape or format mismatch");
    const auto blocks = weights.block_count();
    float sum = 0.0f;
    for (uint64_t b = 0; b < blocks; ++b) {
        const uint8_t* p = weights.block(b);
        const uint16_t h = uint16_t(p[0]) | (uint16_t(p[1]) << 8);
        const float d = ggml_half_to_float(h);
        const float* v = x + static_cast<size_t>(b) * 32;
        for (size_t j = 0; j < 16; ++j) {
            const uint8_t q = p[2 + j];
            sum += (static_cast<int>(q & 15u) - 8) * d * v[j];
            sum += (static_cast<int>(q >> 4) - 8) * d * v[j + 16];
        }
    }
    return sum;
}
} // namespace RawrXD::Compression
