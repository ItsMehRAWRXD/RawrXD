#include "../../src/quant_kernels.hpp"
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

// CPU mirror of gemv_packed16.comp's byte-addressed Q8_0 decoder.
// This validates GGUF block stride, signed-byte conversion, F16 scale decode,
// and the transition between adjacent 34-byte blocks.
static uint32_t loadWordLE(const std::vector<uint8_t>& bytes, size_t offset) {
    assert(offset + 4 <= bytes.size());
    return uint32_t(bytes[offset]) |
           (uint32_t(bytes[offset + 1]) << 8) |
           (uint32_t(bytes[offset + 2]) << 16) |
           (uint32_t(bytes[offset + 3]) << 24);
}

static uint32_t loadByteShaderModel(const std::vector<uint8_t>& bytes, uint32_t offset) {
    const uint32_t word = loadWordLE(bytes, static_cast<size_t>(offset >> 2u) * 4u);
    return (word >> ((offset & 3u) * 8u)) & 0xffu;
}

static float loadQ8_0ShaderModel(const std::vector<uint8_t>& bytes, uint32_t index) {
    const uint32_t blockOffset = (index >> 5u) * 34u;
    const uint32_t scaleBits = loadByteShaderModel(bytes, blockOffset) |
        (loadByteShaderModel(bytes, blockOffset + 1u) << 8u);
    uint32_t scaleWord = scaleBits;
    float scale = 0.0f;
    std::memcpy(&scale, &scaleWord, sizeof(scale));
    // unpackHalf2x16 semantics for the low 16-bit lane.
    const uint32_t sign = (scaleBits & 0x8000u) << 16u;
    const uint32_t exponent = (scaleBits >> 10u) & 0x1fu;
    const uint32_t fraction = scaleBits & 0x3ffu;
    uint32_t f32 = 0;
    if (exponent == 0) {
        if (fraction == 0) f32 = sign;
        else {
            uint32_t mantissa = fraction;
            int32_t e = -14;
            while ((mantissa & 0x400u) == 0) { mantissa <<= 1; --e; }
            mantissa &= 0x3ffu;
            f32 = sign | (uint32_t(e + 127) << 23u) | (mantissa << 13u);
        }
    } else if (exponent == 31) {
        f32 = sign | 0x7f800000u | (fraction << 13u);
    } else {
        f32 = sign | ((exponent + 112u) << 23u) | (fraction << 13u);
    }
    std::memcpy(&scale, &f32, sizeof(scale));
    const uint32_t qByte = loadByteShaderModel(bytes, blockOffset + 2u + (index & 31u));
    const int q = qByte >= 128u ? int(qByte) - 256 : int(qByte);
    return scale * float(q);
}

int main() {
    std::vector<uint8_t> encoded(2u * 34u, 0);
    for (size_t block = 0; block < 2; ++block) {
        const size_t base = block * 34u;
        encoded[base] = 0x00; // F16 scale = 1.0
        encoded[base + 1] = 0x3c;
        for (size_t lane = 0; lane < 32; ++lane)
            encoded[base + 2 + lane] = static_cast<uint8_t>(static_cast<int8_t>(int(lane) - 16));
    }

    float canonical[64]{};
    assert(deep2::dequantizeTensorRange(deep2::TensorType::Q8_0, 64, 0, 64,
                                        encoded.data(), encoded.size(), canonical));
    for (uint32_t i = 0; i < 64; ++i) {
        const float shaderValue = loadQ8_0ShaderModel(encoded, i);
        assert(std::isfinite(shaderValue));
        assert(shaderValue == canonical[i]);
    }
    // Explicitly exercise the unaligned 34-byte block boundary and last byte.
    assert(loadQ8_0ShaderModel(encoded, 31) == canonical[31]);
    assert(loadQ8_0ShaderModel(encoded, 32) == canonical[32]);
    assert(loadQ8_0ShaderModel(encoded, 63) == canonical[63]);
    std::cout << "packed Q8_0 shader decoder parity PASS\n";
}
