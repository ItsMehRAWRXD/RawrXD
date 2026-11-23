#include "../../src/quant_kernels.hpp"
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

static uint32_t loadWordLE(const std::vector<uint8_t>& bytes, size_t offset) {
    assert(offset + 4 <= bytes.size());
    return uint32_t(bytes[offset]) |
           (uint32_t(bytes[offset + 1]) << 8) |
           (uint32_t(bytes[offset + 2]) << 16) |
           (uint32_t(bytes[offset + 3]) << 24);
}

static uint32_t loadByte(const std::vector<uint8_t>& bytes, uint32_t offset) {
    const uint32_t word = loadWordLE(bytes, static_cast<size_t>(offset >> 2u) * 4u);
    return (word >> ((offset & 3u) * 8u)) & 0xffu;
}

static float halfToFloat(uint16_t h) {
    const uint32_t sign = (uint32_t(h & 0x8000u)) << 16u;
    const uint32_t exponent = (h >> 10u) & 0x1fu;
    const uint32_t fraction = h & 0x3ffu;
    uint32_t bits = 0;
    if (exponent == 0u) {
        if (!fraction) bits = sign;
        else {
            uint32_t mantissa = fraction;
            int32_t e = -14;
            while ((mantissa & 0x400u) == 0u) { mantissa <<= 1u; --e; }
            mantissa &= 0x3ffu;
            bits = sign | (uint32_t(e + 127) << 23u) | (mantissa << 13u);
        }
    } else if (exponent == 31u) {
        bits = sign | 0x7f800000u | (fraction << 13u);
    } else {
        bits = sign | ((exponent + 112u) << 23u) | (fraction << 13u);
    }
    float value = 0.0f;
    std::memcpy(&value, &bits, sizeof(value));
    return value;
}

static uint16_t loadHalf(const std::vector<uint8_t>& bytes, uint32_t offset) {
    return static_cast<uint16_t>(loadByte(bytes, offset) |
                                 (loadByte(bytes, offset + 1u) << 8u));
}

// CPU mirror of gemv_packed16.comp's byte-addressed fixed-block decoder.
// GGML type IDs: Q4_0=2, Q4_1=3, Q5_0=6, Q5_1=7, Q8_0=8, Q8_1=9.
static float loadPackedShaderModel(const std::vector<uint8_t>& bytes,
                                   uint32_t type, uint32_t index) {
    const uint32_t blockBytes = type == 2u ? 18u : type == 3u ? 20u :
        type == 6u ? 22u : type == 7u ? 24u : type == 8u ? 34u : 36u;
    const uint32_t lane = index & 31u;
    const uint32_t block = (index >> 5u) * blockBytes;
    const float d = halfToFloat(loadHalf(bytes, block));
    if (type == 8u || type == 9u) {
        const uint32_t qOffset = block + (type == 8u ? 2u : 4u);
        const uint32_t qb = loadByte(bytes, qOffset + lane);
        const int q = qb >= 128u ? int(qb) - 256 : int(qb);
        return d * float(q);
    }
    if (type == 2u || type == 3u) {
        const float m = type == 3u ? halfToFloat(loadHalf(bytes, block + 2u)) : 0.0f;
        const uint32_t qOffset = block + (type == 2u ? 2u : 4u);
        const uint32_t packed = loadByte(bytes, qOffset + (lane & 15u));
        const int q = lane < 16u ? int(packed & 0x0fu) : int(packed >> 4u);
        return type == 2u ? d * float(q - 8) : d * float(q) + m;
    }
    const float m = type == 7u ? halfToFloat(loadHalf(bytes, block + 2u)) : 0.0f;
    const uint32_t qhOffset = block + (type == 6u ? 2u : 4u);
    const uint32_t qsOffset = qhOffset + 4u;
    const uint32_t packed = loadByte(bytes, qsOffset + (lane & 15u));
    const int low = lane < 16u ? int(packed & 0x0fu) : int(packed >> 4u);
    const uint32_t highBit = lane < 16u ? lane : lane - 4u;
    const uint32_t high = (loadByte(bytes, qhOffset + (highBit >> 3u)) >>
                           (highBit & 7u)) & 1u;
    const int q = low | (int(high) << 4);
    return type == 6u ? d * float(q - 16) : d * float(q) + m;
}

static void put16(uint8_t* p, uint16_t value) {
    p[0] = static_cast<uint8_t>(value);
    p[1] = static_cast<uint8_t>(value >> 8u);
}

static void testFixedBlock(uint32_t type) {
    const size_t blockBytes = type == 2u ? 18u : type == 3u ? 20u :
        type == 6u ? 22u : type == 7u ? 24u : type == 8u ? 34u : 36u;
    std::vector<uint8_t> encoded(blockBytes * 2u, 0);
    for (size_t b = 0; b < 2; ++b) {
        uint8_t* p = encoded.data() + b * blockBytes;
        put16(p, 0x3c00u); // d = 1.0
        if (type == 3u || type == 7u) put16(p + 2, 0x3800u); // m = 0.5
        if (type == 2u) {
            for (int i = 0; i < 16; ++i) p[2 + i] = 0x98;
        } else if (type == 3u) {
            for (int i = 0; i < 16; ++i) p[4 + i] = 0x98;
        } else if (type == 6u || type == 7u) {
            const size_t qh = type == 6u ? 2u : 4u;
            const uint8_t high[4] = {0xA5, 0x3C, 0xF0, 0x0F};
            for (int i = 0; i < 4; ++i) p[qh + i] = high[i];
            for (int i = 0; i < 16; ++i) p[qh + 4 + i] = 0x98;
        } else {
            const size_t q = type == 8u ? 2u : 4u;
            for (int i = 0; i < 32; ++i) p[q + i] = static_cast<uint8_t>(static_cast<int8_t>(i - 16));
        }
    }

    const auto tensorType = static_cast<deep2::TensorType>(type);
    float canonical[64]{};
    assert(deep2::dequantizeTensorRange(tensorType, 64, 0, 64,
                                        encoded.data(), encoded.size(), canonical));
    for (uint32_t i = 0; i < 64; ++i) {
        const float packed = loadPackedShaderModel(encoded, type, i);
        assert(std::isfinite(packed));
        assert(packed == canonical[i]);
    }
}

int main() {
    for (uint32_t type : {2u, 3u, 6u, 7u, 8u, 9u}) testFixedBlock(type);
    std::cout << "packed Q4/Q5/Q8 Vulkan shader decoder parity PASS\n";
}
