#pragma once
// GGML Q8_0 block arithmetic. Does not allocate a dequantized matrix.
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
namespace rawrxd::compression {
inline float q8_0_half_to_float(std::uint16_t h) noexcept {
    const std::uint32_t sign = std::uint32_t(h & 0x8000u) << 16;
    const std::uint32_t exponent = (h >> 10) & 31u, fraction = h & 1023u;
    std::uint32_t bits = sign;
    if (exponent == 31) bits |= 0x7f800000u | (fraction << 13);
    else if (exponent) bits |= ((exponent + 112u) << 23) | (fraction << 13);
    else if (fraction) {
        std::uint32_t mantissa = fraction, shift = 0;
        while (!(mantissa & 1024u)) { mantissa <<= 1; ++shift; }
        bits |= ((113u - shift) << 23) | ((mantissa & 1023u) << 13);
    }
    float result;
    std::memcpy(&result, &bits, sizeof(result));
    return result;
}
inline float q8_0_scale(const std::uint8_t* block) {
    if (!block) throw std::invalid_argument("null Q8_0 block");
    const auto h = std::uint16_t(block[0]) | (std::uint16_t(block[1]) << 8);
    const float scale = q8_0_half_to_float(h);
    if (!std::isfinite(scale)) throw std::domain_error("nonfinite Q8_0 scale");
    return scale;
}
inline double q8_0_dot_block(const std::uint8_t* block, const float* input) {
    if (!input) throw std::invalid_argument("null Q8_0 input");
    const float scale = q8_0_scale(block);
    double sum = 0.0;
    for (std::size_t i = 0; i < 32; ++i) {
        const std::int8_t q = static_cast<std::int8_t>(block[2 + i]);
        sum += static_cast<double>(scale) * q * input[i];
    }
    return sum;
}
inline void q8_0_decode_block(const std::uint8_t* block, float* output) {
    if (!output) throw std::invalid_argument("null Q8_0 output");
    const float scale = q8_0_scale(block);
    for (std::size_t i = 0; i < 32; ++i)
        output[i] = scale * static_cast<std::int8_t>(block[2 + i]);
}
} // namespace rawrxd::compression
