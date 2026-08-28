#pragma once

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace rawrxd::deep2 {

struct Q4_0_Block {
    uint16_t d;
    uint8_t  qs[16];
};

static_assert(sizeof(Q4_0_Block) == 18, "Q4_0 block must be 18 bytes");

inline float fp16_to_float_q40(uint16_t h) noexcept
{
    const uint32_t sign = (static_cast<uint32_t>(h & 0x8000u)) << 16;
    const uint32_t exp  = (h >> 10) & 0x1Fu;
    const uint32_t mant = h & 0x03FFu;

    uint32_t bits = 0;

    if (exp == 0) {
        if (mant == 0) {
            bits = sign;
        } else {
            uint32_t m = mant;
            int e = -1;
            while ((m & 0x0400u) == 0) {
                m <<= 1;
                --e;
            }
            m &= 0x03FFu;
            const uint32_t fexp = static_cast<uint32_t>(e + 127);
            bits = sign | (fexp << 23) | (m << 13);
        }
    } else if (exp == 31) {
        bits = sign | 0x7F800000u | (mant << 13);
    } else {
        bits = sign |
               ((exp + (127 - 15)) << 23) |
               (mant << 13);
    }

    float out;
    std::memcpy(&out, &bits, sizeof(out));
    return out;
}

inline bool Q4_0_GEMV_Reference(
    const void* weightData,
    std::size_t rows,
    std::size_t cols,
    const float* x,
    float* y) noexcept
{
    if (!weightData || !x || !y)
        return false;

    constexpr std::size_t kBlockSize = 32;
    constexpr std::size_t kBlockBytes = 18;

    if ((cols == 0) || (rows == 0) || (cols % kBlockSize) != 0)
        return false;

    const std::size_t blocksPerRow = cols / kBlockSize;
    const std::size_t rowBytes     = blocksPerRow * kBlockBytes;

    std::fill(y, y + rows, 0.0f);

    const auto* base =
        static_cast<const uint8_t*>(weightData);

    for (std::size_t r = 0; r < rows; ++r) {
        const uint8_t* row = base + r * rowBytes;
        float sum = 0.0f;

        for (std::size_t b = 0; b < blocksPerRow; ++b) {
            const uint8_t* block = row + b * kBlockBytes;

            const uint16_t dBits =
                static_cast<uint16_t>(block[0]) |
                (static_cast<uint16_t>(block[1]) << 8);

            const float d = fp16_to_float_q40(dBits);
            const uint8_t* qs = block + 2;
            const float* xv = x + b * kBlockSize;

            for (std::size_t j = 0; j < 16; ++j) {
                const uint8_t q = qs[j];

                const int q0 = static_cast<int>(q & 0x0Fu) - 8;
                const int q1 = static_cast<int>(q >> 4)   - 8;

                sum += (d * static_cast<float>(q0)) * xv[j];
                sum += (d * static_cast<float>(q1)) * xv[j + 16];
            }
        }

        y[r] = std::isfinite(sum) ? sum : 0.0f;
    }

    return true;
}

} // namespace rawrxd::deep2
